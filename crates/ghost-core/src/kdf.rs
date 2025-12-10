use hkdf::Hkdf;
use sha2::{Digest, Sha512, Sha512_256};

pub fn hkdf_sha512(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
	let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
	let mut okm = vec![0u8; out_len];
	hk.expand(info, &mut okm).expect("HKDF expand");
	okm
}

pub fn sha512_256(data: &[u8]) -> [u8; 32] {
	let mut hasher = Sha512_256::new();
	hasher.update(data);
	let out = hasher.finalize();
	let mut arr = [0u8; 32];
	arr.copy_from_slice(&out);
	arr
}


