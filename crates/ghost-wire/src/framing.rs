use ghost_core::aead::{decrypt, encrypt, AeadKey};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16; // ChaCha20Poly1305 tag size
pub const HEADER_LEN: usize = 4 + NONCE_LEN; // 4-byte ciphertext length + 12-byte nonce
const AAD_PREFIX: &[u8] = b"ghost/aead/v1";

#[derive(Debug, Error)]
pub enum FramingError {
	#[error("need more data")]
	Incomplete,
	#[error("malformed header")]
	MalformedHeader,
	#[error("decryption failed")]
	Crypto,
}

#[derive(Clone, Debug)]
pub enum NonceMode {
	Random,
	/// Use a fixed base and XOR with an increasing counter encoded in little-endian in the last 8 bytes.
	Counter { base: [u8; NONCE_LEN], counter: u64 },
}

pub struct AeadFramer {
	key: AeadKey,
	nonce_mode: NonceMode,
}

impl AeadFramer {
	pub fn new(key: AeadKey, nonce_mode: NonceMode) -> Self {
		Self { key, nonce_mode }
	}

	fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
		match &mut self.nonce_mode {
			NonceMode::Random => {
				let mut n = [0u8; NONCE_LEN];
				OsRng.fill_bytes(&mut n);
				n
			}
			NonceMode::Counter { base, counter } => {
				let mut n = *base;
				let ctr = counter.to_le_bytes();
				for i in 0..8 {
					n[NONCE_LEN - 8 + i] ^= ctr[i];
				}
				*counter = counter.wrapping_add(1);
				n
			}
		}
	}

	/// Produce a single AEAD frame: [4-byte ct_len][12-byte nonce][ciphertext]
	/// AAD = "ghost/aead/v1" || 4-byte ct_len
	pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
		let nonce = self.next_nonce();
		let ct_len = plaintext
			.len()
			.checked_add(TAG_LEN)
			.expect("frame too large");
		let ct_len_u32: u32 = ct_len
			.try_into()
			.expect("ciphertext length exceeds u32::MAX");
		let mut header = [0u8; 4];
		header.copy_from_slice(&ct_len_u32.to_be_bytes());
		let mut aad = Vec::with_capacity(AAD_PREFIX.len() + header.len());
		aad.extend_from_slice(AAD_PREFIX);
		aad.extend_from_slice(&header);
		let ct = encrypt(&self.key, &nonce, &aad, plaintext);

		let mut frame = Vec::with_capacity(HEADER_LEN + ct.len());
		frame.extend_from_slice(&header);
		frame.extend_from_slice(&nonce);
		frame.extend_from_slice(&ct);
		frame
	}

	/// Attempt to open a single frame from `bytes`. Returns the plaintext if successful.
	/// Expects: [4-byte ct_len][12-byte nonce][ciphertext(ct_len)]
	/// AAD = "ghost/aead/v1" || 4-byte ct_len
	pub fn open(&self, bytes: &[u8]) -> Result<Vec<u8>, FramingError> {
		if bytes.len() < HEADER_LEN {
			return Err(FramingError::Incomplete);
		}
		let mut len_bytes = [0u8; 4];
		len_bytes.copy_from_slice(&bytes[0..4]);
		let ct_len = u32::from_be_bytes(len_bytes) as usize;
		if ct_len < TAG_LEN {
			return Err(FramingError::MalformedHeader);
		}
		let total_needed = HEADER_LEN
			.checked_add(ct_len)
			.ok_or(FramingError::MalformedHeader)?;
		if bytes.len() < total_needed {
			return Err(FramingError::Incomplete);
		}
		let mut nonce = [0u8; NONCE_LEN];
		nonce.copy_from_slice(&bytes[4..4 + NONCE_LEN]);
		let ct = &bytes[HEADER_LEN..HEADER_LEN + ct_len];

		let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 4);
		aad.extend_from_slice(AAD_PREFIX);
		aad.extend_from_slice(&len_bytes);
		let pt = decrypt(&self.key, &nonce, &aad, ct).map_err(|_| FramingError::Crypto)?;
		Ok(pt)
	}
}


