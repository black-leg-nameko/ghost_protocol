use crate::quic::quic_echo_client;
use crate::kad::{RoutingTable, NodeId, PeerInfo, PeerScore};
use crate::dht::{DhtStore, Advert, Lookup, LookupResp};
use crate::kad_rpc::{T_FIND_NODE, T_FIND_NODE_RESP, T_STORE_ADV, T_GET_ADV, T_GET_ADV_RESP, T_REGISTER, T_LIST_PEERS, T_LIST_PEERS_RESP, FindNodeReq, PeerEntry, RegisterPeer, ListPeersResp};
use crate::envelope::Envelope;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tokio::io;
use serde_cbor;
use serde::de::DeserializeOwned;

#[derive(Debug, Error)]
pub enum NetError {
	#[error("quic: {0}")]
	Quic(#[from] crate::quic::QuicError),
	#[error("io: {0}")]
	Io(#[from] io::Error),
	#[error("timeout")]
	Timeout,
	#[error("cbor: {0}")]
	Cbor(#[from] serde_cbor::Error),
}

/// Measure RTT by sending a payload over QUIC echo and waiting for response.
pub async fn quic_ping(addr: SocketAddr, server_cert_der: &[u8], payload: &[u8]) -> Result<Duration, NetError> {
	let t0 = Instant::now();
	let echoed = quic_echo_client(addr, server_cert_der, payload).await?;
	let dt = t0.elapsed();
	if echoed == payload {
		Ok(dt)
	} else {
		Ok(dt) // still return dt; payload mismatch not fatal for measurement
	}
}

/// Start a UDP DHT server handling Envelope(CBOR) for basic Kademlia/DHT ops.
pub async fn start_udp_kad_server(bind: SocketAddr, rt: RoutingTable) -> io::Result<(UdpSocket, tokio::task::JoinHandle<()>)> {
	let sock = UdpSocket::bind(bind).await?;
	let local = sock.local_addr()?;
	let state_rt = std::sync::Arc::new(tokio::sync::Mutex::new(rt));
	let state_dht = std::sync::Arc::new(tokio::sync::Mutex::new(DhtStore::new()));
	let s = sock.try_clone().expect("clone udp");
	let task = tokio::spawn(async move {
		let mut buf = vec![0u8; 2048];
		loop {
			match s.recv_from(&mut buf).await {
				Ok((n, from)) => {
					let data = &buf[..n];
					if let Ok(env) = serde_cbor::from_slice::<Envelope>(data) {
						let mut resp_opt = None;
						match env.type_id {
							T_STORE_ADV => {
								if let Ok(adv) = serde_cbor::value::from_value::<Advert>(env.body.clone()) {
									let mut d = state_dht.lock().await;
									d.advertise(adv);
									resp_opt = Some(Envelope::new(T_GET_ADV_RESP, 1, serde_cbor::to_value(()).unwrap()));
								}
							}
							T_GET_ADV => {
								if let Ok(req) = serde_cbor::value::from_value::<Lookup>(env.body.clone()) {
									let mut d = state_dht.lock().await;
									let recs = d.lookup(&req.addr);
									let body = serde_cbor::to_value(LookupResp { addr: req.addr, records: recs }).unwrap();
									resp_opt = Some(Envelope::new(T_GET_ADV_RESP, 1, body));
								}
							}
							T_FIND_NODE => {
								if let Ok(req) = serde_cbor::value::from_value::<FindNodeReq>(env.body.clone()) {
									let mut target = [0u8;32];
									if req.target.len()==32 { target.copy_from_slice(&req.target); }
									let rt = state_rt.lock().await;
									let peers = rt.find_closest(&NodeId(target), req.count as usize);
									let list: Vec<PeerEntry> = peers.into_iter().map(|p| PeerEntry {
										id: p.id.0.to_vec(),
										endpoint: p.endpoint,
										rtt_ms: p.score.latency_ms_ema as u32,
									}).collect();
									let body = serde_cbor::to_value(crate::kad_rpc::FindNodeResp { peers: list }).unwrap();
									resp_opt = Some(Envelope::new(T_FIND_NODE_RESP, 1, body));
								}
							}
							_ => {}
						}
						if let Some(resp) = resp_opt {
							let out = serde_cbor::to_vec(&resp).unwrap();
							let _ = s.send_to(&out, from).await;
						}
					}
				}
				Err(_) => break,
			}
		}
	});
	Ok((sock, task))
}

pub async fn udp_kad_request<A: Into<SocketAddr>>(target: A, env: &Envelope, timeout_ms: u64) -> Result<Envelope, NetError> {
	let target = target.into();
	let sock = UdpSocket::bind(if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
	let bytes = serde_cbor::to_vec(env)?;
	sock.send_to(&bytes, target).await?;
	let mut buf = vec![0u8; 2048];
	let (n, _from) = timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf)).await.map_err(|_| NetError::Timeout)??;
	let resp: Envelope = serde_cbor::from_slice(&buf[..n])?;
	Ok(resp)
}

/// Iterative FIND_NODE over UDP: query alpha closest peers until convergence or round limit.
pub async fn iterative_find_node_udp(rt: &RoutingTable, seeds: Vec<SocketAddr>, target: NodeId, alpha: usize, k: usize, max_rounds: usize) -> Result<Vec<PeerEntry>, NetError> {
	use std::collections::{HashSet, BinaryHeap};
	use std::cmp::Ordering;
	#[derive(Eq)]
	struct Entry { dist: [u8;32], addr: SocketAddr }
	impl Ord for Entry {
		fn cmp(&self, other: &Self) -> Ordering { other.dist.cmp(&self.dist) }
	}
	impl PartialOrd for Entry { fn partial_cmp(&self, o:&Self)->Option<Ordering>{Some(self.cmp(o))} }
	impl PartialEq for Entry { fn eq(&self, o:&Self)->bool{ self.dist==o.dist && self.addr==o.addr } }
	let mut shortlist = BinaryHeap::new();
	for s in seeds {
		shortlist.push(Entry { dist: target.0, addr: s });
	}
	let mut seen = HashSet::new();
	let mut best_peers: Vec<PeerEntry> = Vec::new();
	for _round in 0..max_rounds {
		let mut batch = Vec::new();
		while batch.len() < alpha {
			if let Some(e) = shortlist.pop() {
				if seen.insert(e.addr) {
					batch.push(e.addr);
				}
			} else { break; }
		}
		if batch.is_empty() { break; }
		let mut tasks = Vec::new();
		for addr in batch {
			let req = Envelope::new(T_FIND_NODE, 1, serde_cbor::to_value(FindNodeReq { target: target.0.to_vec(), count: k as u16 }).unwrap());
			tasks.push(tokio::spawn(async move {
				(addr, udp_kad_request(addr, &req, 800).await)
			}));
		}
		let mut improved = false;
		for t in tasks {
			if let Ok((addr, Ok(resp))) = t.await {
				if resp.type_id == T_FIND_NODE_RESP {
					if let Ok(r) = serde_cbor::value::from_value::<crate::kad_rpc::FindNodeResp>(resp.body) {
						for p in r.peers {
							// endpoints expected like "quic://ip:port" or "udp://ip:port"
							if let Some(rest) = p.endpoint.strip_prefix("udp://") {
								if let Ok(sa) = rest.parse::<SocketAddr>() {
									let mut dist = [0u8;32];
									let mut pid = [0u8;32];
									if p.id.len()==32 { pid.copy_from_slice(&p.id); }
									let peer_id = NodeId(pid);
									dist = target.distance(&peer_id);
									shortlist.push(Entry { dist, addr: sa });
									improved = true;
								}
							}
						}
						best_peers = r.peers;
					}
				}
			}
		}
		if !improved { break; }
	}
	Ok(best_peers)
}


