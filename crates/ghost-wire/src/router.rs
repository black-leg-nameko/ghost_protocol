use crate::{from_cbor_bytes, to_cbor_bytes, GACK, GHLO, RACK, ROTATE};
use serde::Serialize;
use thiserror::Error;
use std::collections::{HashSet, VecDeque};

#[derive(Debug, Error)]
pub enum RouteError {
	#[error("no handler registered for message")]
	NoHandler,
	#[error("decode error")]
	Decode(#[from] serde_cbor::Error),
	#[error("handler error: {0}")]
	Handler(String),
	#[error("replayed nonce")]
	Replay,
	#[error("rotate verification failed")]
	RotateVerify,
	#[error("rotate verifier not set")]
	NoRotateVerifier,
}

type GhloHandler = Box<dyn Fn(&GHLO) -> Result<Option<Vec<u8>>, RouteError> + Send + Sync>;
type GackHandler = Box<dyn Fn(&GACK) -> Result<Option<Vec<u8>>, RouteError> + Send + Sync>;
type RotateHandler = Box<dyn Fn(&ROTATE) -> Result<Option<Vec<u8>>, RouteError> + Send + Sync>;
type RackHandler = Box<dyn Fn(&RACK) -> Result<Option<Vec<u8>>, RouteError> + Send + Sync>;
type RotateVerifier = Box<dyn Fn(&ROTATE) -> bool + Send + Sync>;

pub struct Router {
	on_ghlo: Option<GhloHandler>,
	on_gack: Option<GackHandler>,
	on_rotate: Option<RotateHandler>,
	on_rack: Option<RackHandler>,
	// Simple replay window for GHLO nonces (size-bounded LRU set)
	nonce_cap: usize,
	seen_nonce_set: HashSet<Vec<u8>>,
	seen_nonce_order: VecDeque<Vec<u8>>,
	// Mandatory rotate proof verification
	rotate_verifier: Option<RotateVerifier>,
}

impl Router {
	pub fn new() -> Self {
		Self {
			on_ghlo: None,
			on_gack: None,
			on_rotate: None,
			on_rack: None,
			nonce_cap: 1024,
			seen_nonce_set: HashSet::new(),
			seen_nonce_order: VecDeque::new(),
			rotate_verifier: None,
		}
	}

	pub fn on_ghlo<F>(&mut self, f: F)
	where
		F: Fn(&GHLO) -> Result<Option<Vec<u8>>, RouteError> + Send + Sync + 'static,
	{
		self.on_ghlo = Some(Box::new(f));
	}

	pub fn on_gack<F>(&mut self, f: F)
	where
		F: Fn(&GACK) -> Result<Option<Vec<u8>>, RouteError> + Send + Sync + 'static,
	{
		self.on_gack = Some(Box::new(f));
	}

	pub fn on_rotate<F>(&mut self, f: F)
	where
		F: Fn(&ROTATE) -> Result<Option<Vec<u8>>, RouteError> + Send + Sync + 'static,
	{
		self.on_rotate = Some(Box::new(f));
	}

	pub fn on_rack<F>(&mut self, f: F)
	where
		F: Fn(&RACK) -> Result<Option<Vec<u8>>, RouteError> + Send + Sync + 'static,
	{
		self.on_rack = Some(Box::new(f));
	}

	/// Set maximum number of GHLO nonces remembered for replay protection (default 1024).
	pub fn set_nonce_capacity(&mut self, cap: usize) {
		self.nonce_cap = cap.max(1);
		// Shrink if needed
		while self.seen_nonce_order.len() > self.nonce_cap {
			if let Some(old) = self.seen_nonce_order.pop_front() {
				self.seen_nonce_set.remove(&old);
			}
		}
	}

	/// Provide a mandatory rotate proof verifier. If not set, ROTATE messages are rejected.
	pub fn set_rotate_verifier<F>(&mut self, f: F)
	where
		F: Fn(&ROTATE) -> bool + Send + Sync + 'static,
	{
		self.rotate_verifier = Some(Box::new(f));
	}

	/// Try to decode `bytes` as one of the known message types and invoke the registered handler.
	/// This is a pragmatic demux for the current scaffold where messages are encoded without an envelope.
	pub fn route(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, RouteError> {
		// Try GHLO
		if let Ok(msg) = from_cbor_bytes::<GHLO>(bytes) {
			// Replay protection: drop duplicates of GHLO.nonce
			if self.seen_nonce_set.contains(&msg.nonce) {
				return Err(RouteError::Replay);
			}
			self.seen_nonce_set.insert(msg.nonce.clone());
			self.seen_nonce_order.push_back(msg.nonce.clone());
			if self.seen_nonce_order.len() > self.nonce_cap {
				if let Some(old) = self.seen_nonce_order.pop_front() {
					self.seen_nonce_set.remove(&old);
				}
			}
			if let Some(h) = &self.on_ghlo {
				return h(&msg);
			} else {
				return Err(RouteError::NoHandler);
			}
		}
		// Try GACK
		if let Ok(msg) = from_cbor_bytes::<GACK>(bytes) {
			if let Some(h) = &self.on_gack {
				return h(&msg);
			} else {
				return Err(RouteError::NoHandler);
			}
		}
		// Try ROTATE
		if let Ok(msg) = from_cbor_bytes::<ROTATE>(bytes) {
			// Enforce rotate verification
			match &self.rotate_verifier {
				None => return Err(RouteError::NoRotateVerifier),
				Some(v) => {
					if !(v)(&msg) {
						return Err(RouteError::RotateVerify);
					}
				}
			}
			if let Some(h) = &self.on_rotate {
				return h(&msg);
			} else {
				return Err(RouteError::NoHandler);
			}
		}
		// Try RACK
		if let Ok(msg) = from_cbor_bytes::<RACK>(bytes) {
			if let Some(h) = &self.on_rack {
				return h(&msg);
			} else {
				return Err(RouteError::NoHandler);
			}
		}
		Err(RouteError::Handler("unknown message shape".to_string()))
	}
}

pub fn encode_response<T: Serialize>(msg: &T) -> Result<Vec<u8>, RouteError> {
	to_cbor_bytes(msg).map_err(RouteError::Decode)
}


