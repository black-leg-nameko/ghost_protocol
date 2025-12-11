use crate::quic::quic_echo_client;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetError {
	#[error("quic: {0}")]
	Quic(#[from] crate::quic::QuicError),
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


