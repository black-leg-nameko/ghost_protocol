use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::collections::BTreeMap;
use rand::RngCore;
use time::OffsetDateTime;

pub const ENV_VER: u64 = 1;
pub const EXT_CORR_ID: u64 = 100;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
	pub env_ver: u64,
	pub type_id: u64,
	pub msg_ver: u64,
	#[serde(with = "serde_bytes")]
	pub msg_id: Vec<u8>, // 16 bytes
	pub flags: u64,
	pub ts: u64,
	pub body: Value,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub ext: Option<BTreeMap<u64, Value>>,
}

impl Envelope {
	pub fn new(type_id: u64, msg_ver: u64, body: Value) -> Self {
		let mut msg_id = vec![0u8; 16];
		rand::thread_rng().fill_bytes(&mut msg_id);
		Self {
			env_ver: ENV_VER,
			type_id,
			msg_ver,
			msg_id,
			flags: 0,
			ts: OffsetDateTime::now_utc().unix_timestamp() as u64,
			body,
			ext: None,
		}
	}

	pub fn with_corr(mut self, corr: [u8;16]) -> Self {
		let mut map = self.ext.take().unwrap_or_default();
		map.insert(EXT_CORR_ID, Value::Bytes(corr.to_vec()));
		self.ext = Some(map);
		self
	}

	pub fn corr_id(&self) -> Option<[u8;16]> {
		self.ext.as_ref().and_then(|m| {
			m.get(&EXT_CORR_ID).and_then(|v| match v {
				Value::Bytes(b) if b.len() == 16 => {
					let mut arr = [0u8;16];
					arr.copy_from_slice(b);
					Some(arr)
				}
				_ => None
			})
		})
	}
}


