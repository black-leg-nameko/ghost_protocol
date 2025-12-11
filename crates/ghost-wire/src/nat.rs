use rand::RngCore;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

#[derive(Debug, Error)]
pub enum NatError {
	#[error("io: {0}")]
	Io(#[from] std::io::Error),
	#[error("timeout")]
	Timeout,
	#[error("stun malformed")]
	Malformed,
	#[error("stun unsupported family")]
	Unsupported,
}

/// Perform a STUN Binding Request (RFC5389 minimal) and return the mapped public address.
/// Supports XOR-MAPPED-ADDRESS for IPv4/IPv6.
pub async fn stun_binding_request(stun_addr: SocketAddr) -> Result<SocketAddr, NatError> {
	let sock = UdpSocket::bind(match stun_addr.is_ipv4() {
		true => "0.0.0.0:0",
		false => "[::]:0",
	}).await?;
	// Build STUN binding request
	let mut txid = [0u8; 12];
	rand::thread_rng().fill_bytes(&mut txid);
	let mut req = [0u8; 20];
	// Type: 0x0001
	req[0] = 0x00; req[1] = 0x01;
	// Length: 0
	req[2] = 0x00; req[3] = 0x00;
	// Magic cookie: 0x2112A442
	req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42;
	// Transaction ID
	req[8..20].copy_from_slice(&txid);
	sock.send_to(&req, stun_addr).await?;
	let mut buf = [0u8; 1024];
	let (n, _from) = timeout(Duration::from_millis(1200), sock.recv_from(&mut buf)).await.map_err(|_| NatError::Timeout)??;
	if n < 20 { return Err(NatError::Malformed); }
	// Verify magic and transaction id
	if buf[4] != 0x21 || buf[5] != 0x12 || buf[6] != 0xA4 || buf[7] != 0x42 {
		return Err(NatError::Malformed);
	}
	if &buf[8..20] != &txid {
		return Err(NatError::Malformed);
	}
	// Parse attributes
	let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
	let mut idx = 20usize;
	let end = 20 + msg_len;
	while idx + 4 <= n && idx + 4 <= end {
		let atype = u16::from_be_bytes([buf[idx], buf[idx+1]]);
		let alen = u16::from_be_bytes([buf[idx+2], buf[idx+3]]) as usize;
		idx += 4;
		if idx + alen > n { break; }
		// 32-bit padding
		let padded = (alen + 3) & !3;
		if atype == 0x0020 /* XOR-MAPPED-ADDRESS */ {
			if alen < 4 { return Err(NatError::Malformed); }
			let family = buf[idx+1];
			let xport = u16::from_be_bytes([buf[idx+2], buf[idx+3]]);
			let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
			let port = xport ^ ((cookie >> 16) as u16);
			if family == 0x01 {
				// IPv4
				if alen < 8 { return Err(NatError::Malformed); }
				let mut xaddr = [0u8; 4];
				xaddr.copy_from_slice(&buf[idx+4..idx+8]);
				let mc = cookie.to_be_bytes();
				let addr = Ipv4Addr::new(
					xaddr[0] ^ mc[0],
					xaddr[1] ^ mc[1],
					xaddr[2] ^ mc[2],
					xaddr[3] ^ mc[3],
				);
				return Ok(SocketAddr::new(std::net::IpAddr::V4(addr), port));
			} else if family == 0x02 {
				// IPv6
				if alen < 20 { return Err(NatError::Malformed); }
				let mut xaddr = [0u8; 16];
				xaddr.copy_from_slice(&buf[idx+4..idx+20]);
				let mut mc_xor = [0u8; 16];
				// cookie (4) + txid (12)
				mc_xor[0..4].copy_from_slice(&buf[4..8]);
				mc_xor[4..16].copy_from_slice(&buf[8..20]);
				for i in 0..16 {
					xaddr[i] ^= mc_xor[i];
				}
				let addr = Ipv6Addr::from(xaddr);
				return Ok(SocketAddr::new(std::net::IpAddr::V6(addr), port));
			} else {
				return Err(NatError::Unsupported);
			}
		}
		idx += padded;
	}
	Err(NatError::Malformed)
}


