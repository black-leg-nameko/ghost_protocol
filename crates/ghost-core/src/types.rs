use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use serde::{Deserialize, Serialize};
use rand::rngs::OsRng;
use rand::RngCore;

pub type Epoch = u64;

#[derive(Clone, Debug)]
pub struct GhostKeypair {
	pub secret: Scalar,
	pub public: RistrettoPoint,
}

impl GhostKeypair {
	pub fn new(secret: Scalar) -> Self {
		let public = &secret * RISTRETTO_BASEPOINT_POINT;
		Self { secret, public }
	}
}

pub fn ristretto_generator() -> RistrettoPoint {
	RISTRETTO_BASEPOINT_POINT
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedPoint(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl From<RistrettoPoint> for EncodedPoint {
	fn from(p: RistrettoPoint) -> Self {
		EncodedPoint(p.compress().to_bytes().to_vec())
	}
}

impl TryFrom<EncodedPoint> for RistrettoPoint {
	type Error = &'static str;
	fn try_from(v: EncodedPoint) -> Result<Self, Self::Error> {
		let mut arr = [0u8; 32];
		if v.0.len() != 32 {
			return Err("invalid length");
		}
		arr.copy_from_slice(&v.0);
		CompressedRistretto(arr)
			.decompress()
			.ok_or("invalid point encoding")
	}
}

pub fn random_scalar() -> Scalar {
	let mut wide = [0u8; 64];
	OsRng.fill_bytes(&mut wide);
	Scalar::from_bytes_mod_order_wide(&wide)
}


