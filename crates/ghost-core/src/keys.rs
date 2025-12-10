use crate::types::{Epoch, GhostKeypair, random_scalar};
use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::Digest;
use sha2::Sha512_256;

pub struct Ghost {
	pub epoch: Epoch,
	pub keypair: GhostKeypair,
}

impl Ghost {
	pub fn generate(epoch: Epoch) -> Self {
		let sk = random_scalar();
		let kp = GhostKeypair::new(sk);
		Self { epoch, keypair: kp }
	}
}

pub fn address_for(pk: &RistrettoPoint, epoch: Epoch) -> [u8; 32] {
	let mut hasher = Sha512_256::new();
	hasher.update(pk.compress().as_bytes());
	hasher.update(epoch.to_be_bytes());
	let mut out = [0u8; 32];
	out.copy_from_slice(&hasher.finalize());
	out
}


