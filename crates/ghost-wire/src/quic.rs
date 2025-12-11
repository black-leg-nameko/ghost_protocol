use rcgen::generate_simple_self_signed;
use rustls::{Certificate, PrivateKey, ServerConfig as RustlsServerConfig, ClientConfig as RustlsClientConfig, RootCertStore};
use quinn::{Endpoint, Incoming, ServerConfig, ClientConfig, TransportConfig, Connection, RecvStream, SendStream};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use std::net::{SocketAddr, ToSocketAddrs};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use futures_util::StreamExt;
use futures_util::future::join_all;

#[derive(Debug, Error)]
pub enum QuicError {
	#[error("config error: {0}")]
	Config(String),
	#[error("io error: {0}")]
	Io(#[from] std::io::Error),
	#[error("quic error: {0}")]
	Quinn(#[from] quinn::ConnectionError),
	#[error("write error: {0}")]
	Write(#[from] quinn::WriteError),
	#[error("read error")]
	Read,
}

fn make_server_config() -> Result<(ServerConfig, Vec<u8>), QuicError> {
	let cert = generate_simple_self_signed(vec!["localhost".into()]).map_err(|e| QuicError::Config(format!("rcgen: {e}")))?;
	let cert_der = cert.serialize_der().map_err(|e| QuicError::Config(format!("cert der: {e}")))?;
	let key_der = cert.serialize_private_key_der();
	let rustls_cert = Certificate(cert_der.clone());
	let rustls_key = PrivateKey(key_der);
	let mut tls = RustlsServerConfig::builder().with_no_client_auth().with_single_cert(vec![rustls_cert], rustls_key)
		.map_err(|e| QuicError::Config(format!("rustls server: {e}")))?;
	tls.alpn_protocols = vec![b"ghost/1".to_vec()];
	let crypto = QuicServerConfig::try_from(tls).map_err(|e| QuicError::Config(format!("quic server cfg: {e}")))?;
	let mut transport = TransportConfig::default();
	transport.max_concurrent_bidi_streams(16u32.into());
	let mut server_cfg = ServerConfig::with_crypto(crypto);
	server_cfg.transport = std::sync::Arc::new(transport);
	Ok((server_cfg, cert_der))
}

fn make_client_config(server_cert_der: &[u8]) -> Result<ClientConfig, QuicError> {
	let mut roots = RootCertStore::empty();
	roots.add(&Certificate(server_cert_der.to_vec())).map_err(|e| QuicError::Config(format!("add root: {e}")))?;
	let mut tls = RustlsClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
	tls.alpn_protocols = vec![b"ghost/1".to_vec()];
	let crypto = QuicClientConfig::try_from(tls).map_err(|e| QuicError::Config(format!("quic client cfg: {e}")))?;
	let mut cfg = ClientConfig::new(std::sync::Arc::new(crypto));
	let mut transport = TransportConfig::default();
	transport.max_concurrent_bidi_streams(16u32.into());
	cfg.transport = std::sync::Arc::new(transport);
	Ok(cfg)
}

pub async fn quic_echo_oneshot_server<A: ToSocketAddrs>(bind: A) -> Result<(SocketAddr, Vec<u8>, tokio::task::JoinHandle<()>), QuicError> {
	let (server_cfg, cert_der) = make_server_config()?;
	let bind_addr = bind.to_socket_addrs()?.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no addr"))?;
	let endpoint = Endpoint::server(server_cfg, bind_addr)?;
	let incoming = endpoint.incoming();
	let task = tokio::spawn(async move {
		if let Some(connecting) = incoming.into_future().await.0 {
			if let Ok(conn) = connecting.await {
				let _ = handle_connection(conn).await;
			}
		}
		// drop endpoint to shutdown
	});
	Ok((endpoint.local_addr()?, cert_der, task))
}

pub async fn quic_echo_client(server_addr: SocketAddr, server_cert_der: &[u8], payload: &[u8]) -> Result<Vec<u8>, QuicError> {
	let client_cfg = make_client_config(server_cert_der)?;
	// use ephemeral UDP bind
	let mut endpoint = Endpoint::client("[::]:0".parse().unwrap())?;
	endpoint.set_default_client_config(client_cfg);
	let conn = endpoint.connect(server_addr, "localhost")?.await?;
	let (mut send, mut recv) = conn.open_bi().await?;
	let len = (payload.len() as u32).to_be_bytes();
	send.write_all(&len).await?;
	send.write_all(payload).await?;
	send.finish().await?;
	let mut len_buf = [0u8; 4];
	recv.read_exact(&mut len_buf).await.map_err(|_| QuicError::Read)?;
	let resp_len = u32::from_be_bytes(len_buf) as usize;
	let mut resp = vec![0u8; resp_len];
	recv.read_exact(&mut resp).await.map_err(|_| QuicError::Read)?;
	Ok(resp)
}

async fn handle_bidi(mut send: SendStream, mut recv: RecvStream) {
	let mut len_buf = [0u8; 4];
	if recv.read_exact(&mut len_buf).await.is_ok() {
		let len = u32::from_be_bytes(len_buf) as usize;
		let mut buf = vec![0u8; len];
		if recv.read_exact(&mut buf).await.is_ok() {
			let _ = send.write_all(&len_buf).await;
			let _ = send.write_all(&buf).await;
			let _ = send.finish().await;
		}
	}
}

async fn handle_connection(conn: Connection) -> Result<(), QuicError> {
	loop {
		match conn.accept_bi().await {
			Ok((send, recv)) => {
				tokio::spawn(handle_bidi(send, recv));
			}
			Err(_e) => {
				break;
			}
		}
	}
	Ok(())
}

/// Persistent multi-connection server: accepts connections and streams until the endpoint is dropped.
pub async fn quic_start_server<A: ToSocketAddrs>(bind: A) -> Result<(Endpoint, SocketAddr, Vec<u8>, tokio::task::JoinHandle<()>), QuicError> {
	let (server_cfg, cert_der) = make_server_config()?;
	let bind_addr = bind.to_socket_addrs()?.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no addr"))?;
	let endpoint = Endpoint::server(server_cfg, bind_addr)?;
	let mut incoming = endpoint.incoming();
	let task = tokio::spawn(async move {
		while let Some(connecting) = incoming.next().await {
			match connecting.await {
				Ok(conn) => {
					tokio::spawn(async move {
						let _ = handle_connection(conn).await;
					});
				}
				Err(_e) => break,
			}
		}
	});
	Ok((endpoint, endpoint.local_addr()?, cert_der, task))
}

/// Single connection, multiple concurrent bidi streams to the server. Returns echoed payloads in order.
pub async fn quic_client_send_many(server_addr: SocketAddr, server_cert_der: &[u8], payloads: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, QuicError> {
	let client_cfg = make_client_config(server_cert_der)?;
	let mut endpoint = Endpoint::client("[::]:0".parse().unwrap())?;
	endpoint.set_default_client_config(client_cfg);
	let conn = endpoint.connect(server_addr, "localhost")?.await?;
	let mut tasks = Vec::new();
	for p in payloads {
		let c = conn.clone();
		tasks.push(tokio::spawn(async move {
			let (mut send, mut recv) = c.open_bi().await.map_err(|e| QuicError::Quinn(e))?;
			let len = (p.len() as u32).to_be_bytes();
			send.write_all(&len).await.map_err(|e| QuicError::Write(e))?;
			send.write_all(&p).await.map_err(|e| QuicError::Write(e))?;
			send.finish().await.map_err(|e| QuicError::Write(e))?;
			let mut len_buf = [0u8; 4];
			recv.read_exact(&mut len_buf).await.map_err(|_| QuicError::Read)?;
			let resp_len = u32::from_be_bytes(len_buf) as usize;
			let mut resp = vec![0u8; resp_len];
			recv.read_exact(&mut resp).await.map_err(|_| QuicError::Read)?;
			Ok::<Vec<u8>, QuicError>(resp)
		}));
	}
	let results = join_all(tasks).await;
	let mut out = Vec::new();
	for r in results {
		out.push(r.expect("task join")?);
	}
	Ok(out)
}


