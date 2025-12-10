use crate::kdf::sha512_256;
use crate::types::{ristretto_generator, random_scalar};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotateProof {
	#[serde(with = "serde_bytes")]
	pub pk_old: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub pk_new: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub t1: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub t2: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub c: Vec<u8>, // scalar bytes
	#[serde(with = "serde_bytes")]
	pub s1: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub s2: Vec<u8>,
	#[serde(with = "serde_bytes")]
	pub null: Vec<u8>,
	pub e_old: u64,
	pub e_new: u64,
}

fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
	s.to_bytes()
}

fn scalar_from_bytes(b: &[u8]) -> Option<Scalar> {
	if b.len() != 32 { return None; }
	let mut arr = [0u8; 32];
	arr.copy_from_slice(b);
	Some(Scalar::from_bytes_mod_order(arr))
}

fn point_to_bytes(p: &RistrettoPoint) -> [u8; 32] {
	p.compress().to_bytes()
}

fn point_from_bytes(b: &[u8]) -> Option<RistrettoPoint> {
	if b.len() != 32 { return None; }
	let mut arr = [0u8; 32];
	arr.copy_from_slice(b);
	CompressedRistretto(arr).decompress()
}

fn hash_challenge(dvk: &[u8], e_new: u64, pk_old: &RistrettoPoint, pk_new: &RistrettoPoint, t1: &RistrettoPoint, t2: &RistrettoPoint) -> Scalar {
	let mut data = Vec::new();
	data.extend_from_slice(dvk);
	data.extend_from_slice(b"GHOST-ROTATE");
	data.extend_from_slice(&e_new.to_be_bytes());
	data.extend_from_slice(&point_to_bytes(pk_old));
	data.extend_from_slice(&point_to_bytes(pk_new));
	data.extend_from_slice(&point_to_bytes(t1));
	data.extend_from_slice(&point_to_bytes(t2));
	let h = sha512_256(&data);
	Scalar::from_bytes_mod_order(h)
}

fn compute_null(dvk: &[u8], e_new: u64) -> [u8; 32] {
	let mut data = Vec::new();
	data.extend_from_slice(dvk);
	data.extend_from_slice(b"NULL");
	data.extend_from_slice(&e_new.to_be_bytes());
	sha512_256(&data)
}

pub fn prove_rotate(dvk: &[u8], e_old: u64, e_new: u64, sk_old: &Scalar, sk_new: &Scalar) -> RotateProof {
	let g = ristretto_generator();
	let pk_old = sk_old * g;
	let pk_new = sk_new * g;

	let r1 = random_scalar();
	let r2 = random_scalar();
	let t1 = r1 * g;
	let t2 = r2 * g;
	let c = hash_challenge(dvk, e_new, &pk_old, &pk_new, &t1, &t2);
	let s1 = r1 + c * sk_old;
	let s2 = r2 + c * sk_new;
	let null = compute_null(dvk, e_new).to_vec();

	RotateProof {
		pk_old: point_to_bytes(&pk_old).to_vec(),
		pk_new: point_to_bytes(&pk_new).to_vec(),
		t1: point_to_bytes(&t1).to_vec(),
		t2: point_to_bytes(&t2).to_vec(),
		c: scalar_to_bytes(&c).to_vec(),
		s1: scalar_to_bytes(&s1).to_vec(),
		s2: scalar_to_bytes(&s2).to_vec(),
		null,
		e_old,
		e_new,
	}
}

pub fn verify_rotate(dvk: &[u8], proof: &RotateProof) -> bool {
	let pk_old = match point_from_bytes(&proof.pk_old) { Some(p) => p, None => return false };
	let pk_new = match point_from_bytes(&proof.pk_new) { Some(p) => p, None => return false };
	let t1 = match point_from_bytes(&proof.t1) { Some(p) => p, None => return false };
	let t2 = match point_from_bytes(&proof.t2) { Some(p) => p, None => return false };
	let c = match scalar_from_bytes(&proof.c) { Some(s) => s, None => return false };
	let s1 = match scalar_from_bytes(&proof.s1) { Some(s) => s, None => return false };
	let s2 = match scalar_from_bytes(&proof.s2) { Some(s) => s, None => return false };

	let g = ristretto_generator();
	let c_prime = hash_challenge(dvk, proof.e_new, &pk_old, &pk_new, &t1, &t2);
	if c != c_prime {
		return false;
	}
	let lhs1 = s1 * g;
	let rhs1 = t1 + c * pk_old;
	let lhs2 = s2 * g;
	let rhs2 = t2 + c * pk_new;
	(lhs1 == rhs1) && (lhs2 == rhs2)
}


