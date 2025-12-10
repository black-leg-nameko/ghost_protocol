use crate::{from_cbor_bytes, to_cbor_bytes, GACK, GHLO, RACK, ROTATE};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RouteError {
	#[error("no handler registered for message")]
	NoHandler,
	#[error("decode error")]
	Decode(#[from] serde_cbor::Error),
	#[error("handler error: {0}")]
	Handler(String),
}

type GhloHandler = Box<dyn Fn(&GHLO) -> Result<Option<Vec<u8>>, RouteError> + Send + Sync>;
type GackHandler = Box<dyn Fn(&GACK) -> Result<Option<Vec<u8>>, RouteError> + Send + Sync>;
type RotateHandler = Box<dyn Fn(&ROTATE) -> Result<Option<Vec<u8>>, RouteError> + Send + Sync>;
type RackHandler = Box<dyn Fn(&RACK) -> Result<Option<Vec<u8>>, RouteError> + Send + Sync>;

pub struct Router {
	on_ghlo: Option<GhloHandler>,
	on_gack: Option<GackHandler>,
	on_rotate: Option<RotateHandler>,
	on_rack: Option<RackHandler>,
}

impl Router {
	pub fn new() -> Self {
		Self {
			on_ghlo: None,
			on_gack: None,
			on_rotate: None,
			on_rack: None,
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

	/// Try to decode `bytes` as one of the known message types and invoke the registered handler.
	/// This is a pragmatic demux for the current scaffold where messages are encoded without an envelope.
	pub fn route(&self, bytes: &[u8]) -> Result<Option<Vec<u8>>, RouteError> {
		// Try GHLO
		if let Ok(msg) = from_cbor_bytes::<GHLO>(bytes) {
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


