use rand::RngCore;
use sha2::{Digest, Sha512_256};

#[derive(Clone, Copy, Debug)]
pub enum PowAlgo {
	Sha512_256,
}

#[derive(Clone, Copy, Debug)]
pub struct PowStamp {
	pub algo: PowAlgo,
	pub difficulty_bits: u8,
	pub nonce: u64,
}

fn leading_zero_bits(bytes: &[u8]) -> u8 {
	let mut count: u8 = 0;
	for b in bytes {
		if *b == 0 {
			count = count.saturating_add(8);
			continue;
		}
		// Count leading zeros in the first non-zero byte
		let mut v = *b;
		let mut c = 0u8;
		while (v & 0x80) == 0 {
			c += 1;
			v <<= 1;
		}
		count = count.saturating_add(c);
		break;
	}
	count
}

fn hash_payload(algo: PowAlgo, payload: &[u8], salt: &[u8], nonce: u64) -> [u8; 32] {
	match algo {
		PowAlgo::Sha512_256 => {
			let mut h = Sha512_256::new();
			h.update(b"ghost/pow/v1");
			h.update(payload);
			h.update(salt);
			h.update(&nonce.to_be_bytes());
			let out = h.finalize();
			let mut arr = [0u8; 32];
			arr.copy_from_slice(&out);
			arr
		}
	}
}

pub fn verify_pow(stamp: &PowStamp, payload: &[u8], salt: &[u8]) -> bool {
	let digest = hash_payload(stamp.algo, payload, salt, stamp.nonce);
	let lz = leading_zero_bits(&digest);
	lz >= stamp.difficulty_bits
}

/// Solve PoW by finding a nonce such that hash(payload||salt||nonce) has at least `difficulty_bits` leading zero bits.
/// This is a simple Hashcash-like puzzle intended as an anti-spam throttle.
pub fn solve_pow(algo: PowAlgo, difficulty_bits: u8, payload: &[u8], salt: &[u8]) -> PowStamp {
	// Start from a random seed to avoid deterministic collisions while testing
	let mut rng = rand::thread_rng();
	let mut nonce = rng.next_u64();
	loop {
		let digest = hash_payload(algo, payload, salt, nonce);
		if leading_zero_bits(&digest) >= difficulty_bits {
			return PowStamp {
				algo,
				difficulty_bits,
				nonce,
			};
		}
		nonce = nonce.wrapping_add(1);
	}
}


