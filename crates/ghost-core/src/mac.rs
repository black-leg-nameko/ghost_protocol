use hmac::{Hmac, Mac};
use sha2::Sha512_256;

type HmacSha512_256 = Hmac<Sha512_256>;

/// Compute HMAC-SHA-512/256 over `data` with `key`.
pub fn hmac_sha512_256(key: &[u8], data: &[u8]) -> [u8; 32] {
	let mut mac = HmacSha512_256::new_from_slice(key).expect("HMAC key");
	mac.update(data);
	let out = mac.finalize().into_bytes();
	let mut arr = [0u8; 32];
	arr.copy_from_slice(&out);
	arr
}


