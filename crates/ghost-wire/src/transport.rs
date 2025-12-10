use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

pub struct UdpTransport {
	socket: UdpSocket,
}

impl UdpTransport {
	pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
		let socket = UdpSocket::bind(addr)?;
		socket.set_nonblocking(false)?;
		socket.set_read_timeout(Some(Duration::from_millis(250)))?;
		Ok(Self { socket })
	}

	pub fn local_addr(&self) -> io::Result<SocketAddr> {
		self.socket.local_addr()
	}

	pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
		self.socket.send_to(data, addr)
	}

	pub fn recv(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
		let mut buf = vec![0u8; 2048];
		match self.socket.recv_from(&mut buf) {
			Ok((n, from)) => {
				buf.truncate(n);
				Ok((buf, from))
			}
			Err(e) => Err(e),
		}
	}
}


