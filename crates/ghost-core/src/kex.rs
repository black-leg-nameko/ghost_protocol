use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use crate::kdf::hkdf_sha512;

pub struct X25519Keypair {
	pub secret: EphemeralSecret,
	pub public: PublicKey,
}

impl X25519Keypair {
	pub fn generate() -> Self {
		let secret = EphemeralSecret::random_from_rng(OsRng);
		let public = PublicKey::from(&secret);
		Self { secret, public }
	}
}

pub fn dh_shared(secret: EphemeralSecret, peer_public: &PublicKey) -> SharedSecret {
	secret.diffie_hellman(peer_public)
}

/// Derive a 32-byte session key bound to the transcript hash using HKDF-SHA-512.
pub fn derive_session_key(shared: &SharedSecret, transcript_hash: &[u8]) -> [u8; 32] {
	let okm = hkdf_sha512(shared.as_bytes(), b"sess", transcript_hash, 32);
	let mut out = [0u8; 32];
	out.copy_from_slice(&okm);
	out
}


