use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Advert {
	#[serde(with = "serde_bytes")]
	pub addr: Vec<u8>, // ghost address bytes
	pub epoch: u64,
	pub ttl_secs: u64,
	pub endpoint: String, // e.g., "quic://host:port" or "udp://ip:port"
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lookup {
	#[serde(with = "serde_bytes")]
	pub addr: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LookupResp {
	#[serde(with = "serde_bytes")]
	pub addr: Vec<u8>,
	pub records: Vec<Advert>,
}

#[derive(Clone, Debug)]
struct Entry {
	advert: Advert,
	expiry: SystemTime,
}

#[derive(Default)]
pub struct DhtStore {
	map: HashMap<Vec<u8>, Vec<Entry>>,
}

impl DhtStore {
	pub fn new() -> Self { Self { map: HashMap::new() } }

	pub fn gc(&mut self) {
		let now = SystemTime::now();
		self.map.retain(|_, v| {
			v.retain(|e| e.expiry > now);
			!v.is_empty()
		});
	}

	pub fn advertise(&mut self, adv: Advert) {
		let expiry = SystemTime::now() + Duration::from_secs(adv.ttl_secs);
		let entry = Entry { advert: adv.clone(), expiry };
		self.map.entry(adv.addr.clone()).or_default().push(entry);
	}

	pub fn lookup(&mut self, addr: &[u8]) -> Vec<Advert> {
		self.gc();
		self.map.get(addr).map(|v| v.iter().map(|e| e.advert.clone()).collect()).unwrap_or_default()
	}
}


