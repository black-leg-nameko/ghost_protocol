use crate::dht::{Advert, DhtStore, Lookup, LookupResp};
use crate::envelope::Envelope;
use crate::kad::{RoutingTable, NodeId, PeerInfo, PeerScore};
use crate::quic::{make_client_config, make_server_config};
use quinn::{Endpoint, Connection};
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};

#[derive(Debug, Error)]
pub enum KadError {
	#[error("io: {0}")]
	Io(#[from] std::io::Error),
	#[error("quic: {0}")]
	Quic(#[from] quinn::ConnectionError),
	#[error("write: {0}")]
	Write(#[from] quinn::WriteError),
	#[error("read")]
	Read,
	#[error("config: {0}")]
	Config(String),
	#[error("cbor: {0}")]
	Cbor(#[from] serde_cbor::Error),
}

// Type IDs for envelopes
pub const T_PING: u64 = 300;
pub const T_PONG: u64 = 301;
pub const T_FIND_NODE: u64 = 302;
pub const T_FIND_NODE_RESP: u64 = 303;
pub const T_STORE_ADV: u64 = 304;
pub const T_GET_ADV: u64 = 305;
pub const T_GET_ADV_RESP: u64 = 306;
pub const T_REGISTER: u64 = 307;
pub const T_LIST_PEERS: u64 = 308;
pub const T_LIST_PEERS_RESP: u64 = 309;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindNodeReq {
	#[serde(with = "serde_bytes")]
	pub target: Vec<u8>, // 32 bytes
	pub count: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerEntry {
	#[serde(with = "serde_bytes")]
	pub id: Vec<u8>,
	pub endpoint: String,
	pub rtt_ms: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindNodeResp {
	pub peers: Vec<PeerEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterPeer {
	#[serde(with = "serde_bytes")]
	pub id: Vec<u8>,
	pub endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListPeersResp {
	pub peers: Vec<PeerEntry>,
}

struct KadState {
	rt: RoutingTable,
	dht: DhtStore,
	peers: HashMap<[u8;32], PeerInfo>, // rendezvous registry
}

impl KadState {
	fn new(rt: RoutingTable) -> Self {
		Self { rt, dht: DhtStore::new(), peers: HashMap::new() }
	}
}

async fn handle_stream(mut conn: Connection, state: Arc<Mutex<KadState>>) {
	loop {
		let Ok((mut send, mut recv)) = conn.accept_bi().await else { break; };
		tokio::spawn({
			let state = state.clone();
			async move {
				let mut len_buf = [0u8; 4];
				if recv.read_exact(&mut len_buf).await.is_err() { let _=send.finish().await; return; }
				let len = u32::from_be_bytes(len_buf) as usize;
				let mut buf = vec![0u8; len];
				if recv.read_exact(&mut buf).await.is_err() { let _=send.finish().await; return; }
				let env: Envelope = serde_cbor::from_slice(&buf).unwrap_or_else(|_| Envelope::new(0, 0, Value::Null));
				let mut resp_opt: Option<Envelope> = None;
				{
					let mut st = state.lock().unwrap();
					match env.type_id {
						T_PING => {
							resp_opt = Some(Envelope::new(T_PONG, 1, Value::Text("pong".into())));
						}
						T_FIND_NODE => {
							if let Ok(req) = serde_cbor::value::from_value::<FindNodeReq>(env.body.clone()) {
								let mut target = [0u8;32];
                                if req.target.len()==32 { target.copy_from_slice(&req.target); }
								let peers = st.rt.find_closest(&crate::kad::NodeId(target), req.count as usize);
								let list = peers.into_iter().map(|p| {
									PeerEntry {
										id: p.id.0.to_vec(),
										endpoint: p.endpoint,
										rtt_ms: p.score.latency_ms_ema as u32,
									}
								}).collect();
								let body = serde_cbor::to_value(FindNodeResp { peers: list }).unwrap();
								resp_opt = Some(Envelope::new(T_FIND_NODE_RESP, 1, body));
							}
						}
						T_STORE_ADV => {
							if let Ok(adv) = serde_cbor::value::from_value::<Advert>(env.body.clone()) {
								st.dht.advertise(adv);
								resp_opt = Some(Envelope::new(T_PONG, 1, Value::Null));
							}
						}
						T_GET_ADV => {
							if let Ok(req) = serde_cbor::value::from_value::<Lookup>(env.body.clone()) {
								let recs = st.dht.lookup(&req.addr);
								let body = serde_cbor::to_value(LookupResp { addr: req.addr, records: recs }).unwrap();
								resp_opt = Some(Envelope::new(T_GET_ADV_RESP, 1, body));
							}
						}
						T_REGISTER => {
							if let Ok(reg) = serde_cbor::value::from_value::<RegisterPeer>(env.body.clone()) {
								let mut id = [0u8;32];
								if reg.id.len()==32 { id.copy_from_slice(&reg.id); }
								let info = PeerInfo {
									id: NodeId(id),
									endpoint: reg.endpoint,
									last_seen: std::time::SystemTime::now(),
									score: PeerScore::new(),
								};
								st.peers.insert(id, info);
								resp_opt = Some(Envelope::new(T_PONG, 1, Value::Null));
							}
						}
						T_LIST_PEERS => {
							let peers: Vec<PeerEntry> = st.peers.values().cloned().map(|p| PeerEntry {
								id: p.id.0.to_vec(),
								endpoint: p.endpoint,
								rtt_ms: p.score.latency_ms_ema as u32,
							}).collect();
							let body = serde_cbor::to_value(ListPeersResp { peers }).unwrap();
							resp_opt = Some(Envelope::new(T_LIST_PEERS_RESP, 1, body));
						}
						_ => {}
					}
				}
				if let Some(resp) = resp_opt {
					let out = serde_cbor::to_vec(&resp).unwrap();
					let len = (out.len() as u32).to_be_bytes();
					let _ = send.write_all(&len).await;
					let _ = send.write_all(&out).await;
					let _ = send.finish().await;
				} else {
					let _ = send.finish().await;
				}
			}
		});
	}
}

pub async fn start_kad_quic_server<A: ToSocketAddrs>(bind: A, rt: RoutingTable) -> Result<(Endpoint, SocketAddr, Vec<u8>, JoinHandle<()>), KadError> {
	let (server_cfg, cert_der) = make_server_config().map_err(|e| KadError::Config(format!("{e}")))?;
	let bind_addr = bind.to_socket_addrs()?.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no addr"))?;
	let endpoint = Endpoint::server(server_cfg, bind_addr)?;
	let state = Arc::new(Mutex::new(KadState::new(rt)));
	let mut incoming = endpoint.incoming();
	let st2 = state.clone();
	let task = tokio::spawn(async move {
		while let Some(connecting) = incoming.next().await {
			match connecting.await {
				Ok(conn) => {
					let st = st2.clone();
					tokio::spawn(async move { handle_stream(conn, st).await; });
				}
				Err(_) => break,
			}
		}
	});
	Ok((endpoint, endpoint.local_addr()?, cert_der, task))
}

pub async fn kad_quic_request(addr: SocketAddr, cert_der: &[u8], env: &Envelope) -> Result<Envelope, KadError> {
	let client_cfg = make_client_config(cert_der).map_err(|e| KadError::Config(format!("{e}")))?;
	let mut endpoint = Endpoint::client("[::]:0".parse().unwrap())?;
	endpoint.set_default_client_config(client_cfg);
	let conn = endpoint.connect(addr, "localhost")?.await?;
	let (mut send, mut recv) = conn.open_bi().await?;
	let bytes = serde_cbor::to_vec(env)?;
	let len = (bytes.len() as u32).to_be_bytes();
	send.write_all(&len).await?;
	send.write_all(&bytes).await?;
	send.finish().await?;
	let mut len_buf = [0u8; 4];
	recv.read_exact(&mut len_buf).await.map_err(|_| KadError::Read)?;
	let resp_len = u32::from_be_bytes(len_buf) as usize;
	let mut buf = vec![0u8; resp_len];
	recv.read_exact(&mut buf).await.map_err(|_| KadError::Read)?;
	let resp: Envelope = serde_cbor::from_slice(&buf)?;
	Ok(resp)
}


