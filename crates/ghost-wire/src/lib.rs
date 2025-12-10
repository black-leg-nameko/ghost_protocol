use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod framing;
pub mod router;
pub mod transport;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GHLO {
	pub ver: u64,
	pub e: u64,
	#[serde(with = "serde_bytes")]
	pub pk: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub nonce: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub kex: Vec<u8>,
	pub suite: u64,
	pub opts: BTreeMap<String, serde_cbor::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GACK {
	pub e: u64,
	#[serde(with = "serde_bytes")]
	pub pk: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub nonce: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub kex: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub mac: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ROTATE {
	pub e_old: u64,
	pub e_new: u64,
	#[serde(with = "serde_bytes")]
	pub pk_old: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub pk_new: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub t1: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub t2: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub c: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub s1: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub s2: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub null: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RACK {
	pub e_new: u64,
	pub ack: bool,
	pub note: Option<String>,
}

pub fn to_cbor_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_cbor::Error> {
	serde_cbor::to_vec(value)
}

pub fn from_cbor_bytes<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, serde_cbor::Error> {
	serde_cbor::from_slice(bytes)
}


