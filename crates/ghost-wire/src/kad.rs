use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

pub const ID_LEN: usize = 32;
pub const K: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; ID_LEN]);

impl NodeId {
	pub fn distance(&self, other: &NodeId) -> [u8; ID_LEN] {
		let mut out = [0u8; ID_LEN];
		for i in 0..ID_LEN {
			out[i] = self.0[i] ^ other.0[i];
		}
		out
	}

	pub fn bucket_index(&self, other: &NodeId) -> usize {
		let d = self.distance(other);
		leading_zeros(&d)
	}
}

fn leading_zeros(bytes: &[u8; ID_LEN]) -> usize {
	for (i, b) in bytes.iter().enumerate() {
		if *b != 0 {
			return i * 8 + b.leading_zeros() as usize;
		}
	}
	ID_LEN * 8
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
	pub id: NodeId,
	pub endpoint: String,
	pub last_seen: SystemTime,
	pub score: PeerScore,
}

#[derive(Clone, Debug)]
pub struct PeerScore {
	pub successes: u64,
	pub failures: u64,
	pub latency_ms_ema: f64, // exponential moving average
}

impl PeerScore {
	pub fn new() -> Self {
		Self { successes: 0, failures: 0, latency_ms_ema: 0.0 }
	}
	pub fn on_success(&mut self, latency_ms: f64) {
		self.successes += 1;
		let alpha = 0.2;
		self.latency_ms_ema = if self.latency_ms_ema == 0.0 {
			latency_ms
		} else {
			alpha * latency_ms + (1.0 - alpha) * self.latency_ms_ema
		};
	}
	pub fn on_failure(&mut self) {
		self.failures += 1;
	}
	/// Exponential decay toward baseline; call periodically with elapsed seconds.
	pub fn decay(&mut self, elapsed_secs: f64) {
		let beta = (elapsed_secs / 60.0).min(1.0); // decay over ~1min
		self.latency_ms_ema = (1.0 - beta) * self.latency_ms_ema;
		if self.failures > 0 {
			let dec = (self.failures as f64) * (1.0 - beta);
			self.failures = dec as u64;
		}
	}
	/// Heuristic: blacklist if failures exceed threshold or EMA too high.
	pub fn is_bad(&self) -> bool {
		self.failures >= 5 || self.latency_ms_ema > 5000.0
	}
	pub fn cmp_quality(&self, other: &PeerScore) -> Ordering {
		// lower EMA latency and fewer failures preferred
		self.failures.cmp(&other.failures).then_with(|| {
			self.latency_ms_ema
				.partial_cmp(&other.latency_ms_ema)
				.unwrap_or(Ordering::Equal)
		}).reverse()
	}
}

#[derive(Clone, Debug)]
pub struct KBucket {
	pub entries: VecDeque<PeerInfo>, // MRU at back
	pub k: usize,
}

impl KBucket {
	pub fn new(k: usize) -> Self {
		Self { entries: VecDeque::new(), k }
	}
	pub fn upsert(&mut self, info: PeerInfo) {
		if let Some(pos) = self.entries.iter().position(|p| p.id == info.id) {
			self.entries.remove(pos);
			self.entries.push_back(info);
		} else {
			if self.entries.len() >= self.k {
				// Evict the peer with worst score; fallback to LRU (front)
				let mut worst_idx = 0usize;
				let mut worst_score = None;
				for (i, p) in self.entries.iter().enumerate() {
					if let Some(ws) = &worst_score {
						if p.score.cmp_quality(ws) == std::cmp::Ordering::Less {
							worst_idx = i;
							worst_score = Some(p.score.clone());
						}
					} else {
						worst_idx = i;
						worst_score = Some(p.score.clone());
					}
				}
				if self.entries.len() > 0 {
					let _ = self.entries.remove(worst_idx);
				}
			}
			self.entries.push_back(info);
		}
	}
	pub fn iter(&self) -> impl Iterator<Item = &PeerInfo> {
		self.entries.iter()
	}
}

pub struct RoutingTable {
	pub local_id: NodeId,
	pub buckets: Vec<KBucket>, // 0..=256
	pub blacklist: Blacklist,
}

impl RoutingTable {
	pub fn new(local_id: NodeId) -> Self {
		let mut buckets = Vec::with_capacity(ID_LEN * 8 + 1);
		for _ in 0..=ID_LEN * 8 {
			buckets.push(KBucket::new(K));
		}
		Self { local_id, buckets, blacklist: Blacklist::new() }
	}

	pub fn insert_or_update(&mut self, info: PeerInfo) {
		if self.blacklist.contains(&info.id) {
			return;
		}
		let idx = self.local_id.bucket_index(&info.id);
		self.buckets[idx].upsert(info);
	}

	/// Update peer score and reflect blacklist automatically if needed.
	pub fn record_result(&mut self, peer_id: &NodeId, success: bool, latency_ms: Option<f64>) {
		// Find and update in-place
		for b in &mut self.buckets {
			if let Some(pos) = b.entries.iter().position(|p| &p.id == peer_id) {
				let mut p = b.entries.remove(pos).unwrap();
				if success {
					p.score.on_success(latency_ms.unwrap_or(0.0));
				} else {
					p.score.on_failure();
				}
				if p.score.is_bad() {
					self.blacklist.add(&p.id);
					// do not reinsert
				} else {
					b.entries.push_back(p);
				}
				break;
			}
		}
	}

	/// Reindex all bucket entries for a new local_id (e.g., identity rotation).
	pub fn reindex_for_local_id(&mut self, new_local_id: NodeId) {
		let mut all = Vec::new();
		for b in &mut self.buckets {
			for p in b.entries.drain(..) {
				all.push(p);
			}
		}
		self.local_id = new_local_id;
		for p in all {
			self.insert_or_update(p);
		}
	}

	pub fn find_closest(&self, target: &NodeId, n: usize) -> Vec<PeerInfo> {
		let mut all = Vec::new();
		for b in &self.buckets {
			for p in b.iter() {
				all.push(p.clone());
			}
		}
		all.sort_by(|a, b| {
			let da = a.id.distance(target);
			let db = b.id.distance(target);
			da.cmp(&db)
		});
		all.truncate(n);
		all
	}
}

use std::collections::HashSet;
use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct BlacklistEntry {
	pub id: NodeId,
	pub expiry: SystemTime,
}

#[derive(Default)]
pub struct Blacklist {
	set: HashSet<[u8;32]>,
}

impl Blacklist {
	pub fn new() -> Self { Self { set: HashSet::new() } }
	pub fn add(&mut self, id: &NodeId) { self.set.insert(id.0); }
	pub fn contains(&self, id: &NodeId) -> bool { self.set.contains(&id.0) }
	pub fn remove(&mut self, id: &NodeId) { self.set.remove(&id.0); }
}


