use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

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


