use ghost_core::aead::{decrypt, encrypt, AeadKey};
use ghost_core::kdf::hkdf_sha512;
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16; // ChaCha20Poly1305 tag size
// v2 header: [4-byte ct_len][12-byte nonce][4-byte stream_id][8-byte seq][1-byte flags][4-byte gen]
pub const HEADER_LEN: usize = 4 + NONCE_LEN + 4 + 8 + 1 + 4;
const AAD_PREFIX: &[u8] = b"ghost/aead/v2";
// Frame flags
pub const FLAG_START: u8 = 0x01;
pub const FLAG_END: u8 = 0x02;
pub const FLAG_REKEY: u8 = 0x04;

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

#[derive(Clone, Debug)]
pub struct FrameMeta {
	pub stream_id: u32,
	pub seq: u64,
	pub flags: u8,
	pub generation: u32,
}

pub struct AeadFramer {
	key: AeadKey,
	nonce_mode: NonceMode,
	seq: u64,
	generation: u32,
	base_key: [u8; 32],
}

impl AeadFramer {
	pub fn new(key: AeadKey, nonce_mode: NonceMode) -> Self {
		Self {
			key,
			nonce_mode,
			seq: 0,
			generation: 0,
			base_key: [0u8; 32],
		}
	}

	/// Optionally provide the base key bytes enabling HKDF-based rekeying.
	pub fn set_base_key(&mut self, base_key32: [u8; 32]) {
		self.base_key = base_key32;
	}

	/// Manually set the AEAD key and increase generation.
	pub fn rekey_with(&mut self, new_key: AeadKey) {
		self.key = new_key;
		self.generation = self.generation.wrapping_add(1);
	}

	/// Derive next key using HKDF-SHA-512: okm = HKDF(base_key, "aead-gen" || gen_be, out=32).
	pub fn rekey_hkdf_next(&mut self) {
		let mut info = b"aead-gen".to_vec();
		let next_gen = self.generation.wrapping_add(1);
		info.extend_from_slice(&next_gen.to_be_bytes());
		let okm = hkdf_sha512(&self.base_key, b"", &info, 32);
		let key = AeadKey::from_bytes(&okm);
		self.rekey_with(key);
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
				let ctr_val = if self.seq > *counter { self.seq } else { *counter };
				let ctr = ctr_val.to_le_bytes();
				for i in 0..8 {
					n[NONCE_LEN - 8 + i] ^= ctr[i];
				}
				*counter = ctr_val.wrapping_add(1);
				n
			}
		}
	}

	/// Produce a single AEAD frame on stream 0 with START|END set.
	pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
		self.seal_on_stream(0, plaintext)
	}

	/// Produce a single AEAD frame for a given `stream_id` with START|END set.
	pub fn seal_on_stream(&mut self, stream_id: u32, plaintext: &[u8]) -> Vec<u8> {
		let flags = FLAG_START | FLAG_END;
		self.seal_inner(stream_id, plaintext, flags)
	}

	fn seal_inner(&mut self, stream_id: u32, plaintext: &[u8], flags: u8) -> Vec<u8> {
		let nonce = self.next_nonce();
		let ct_len = plaintext.len().checked_add(TAG_LEN).expect("frame too large");
		let ct_len_u32: u32 = ct_len.try_into().expect("ciphertext length exceeds u32::MAX");
		let mut len_bytes = [0u8; 4];
		len_bytes.copy_from_slice(&ct_len_u32.to_be_bytes());
		let stream_bytes = stream_id.to_be_bytes();
		let seq_now = self.seq;
		let seq_bytes = seq_now.to_be_bytes();
		let gen_bytes = self.generation.to_be_bytes();
		let flags_bytes = [flags];
		let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 4 + 4 + 8 + 1 + 4);
		aad.extend_from_slice(AAD_PREFIX);
		aad.extend_from_slice(&len_bytes);
		aad.extend_from_slice(&stream_bytes);
		aad.extend_from_slice(&seq_bytes);
		aad.extend_from_slice(&flags_bytes);
		aad.extend_from_slice(&gen_bytes);
		let ct = encrypt(&self.key, &nonce, &aad, plaintext);

		let mut frame = Vec::with_capacity(HEADER_LEN + ct.len());
		frame.extend_from_slice(&len_bytes);
		frame.extend_from_slice(&nonce);
		frame.extend_from_slice(&stream_bytes);
		frame.extend_from_slice(&seq_bytes);
		frame.extend_from_slice(&flags_bytes);
		frame.extend_from_slice(&gen_bytes);
		frame.extend_from_slice(&ct);
		self.seq = self.seq.wrapping_add(1);
		frame
	}

	/// Fragment `payload` into multiple frames for `stream_id`, each up to `max_payload` bytes of plaintext.
	pub fn seal_fragmented(&mut self, stream_id: u32, payload: &[u8], max_payload: usize) -> Vec<Vec<u8>> {
		assert!(max_payload > 0, "max_payload must be > 0");
		let mut out = Vec::new();
		let mut offset = 0usize;
		let total = payload.len();
		while offset < total {
			let remaining = total - offset;
			let take = remaining.min(max_payload);
			let chunk = &payload[offset..offset + take];
			let is_first = offset == 0;
			let is_last = offset + take == total;
			let mut flags = 0u8;
			if is_first { flags |= FLAG_START; }
			if is_last { flags |= FLAG_END; }
			let frame = self.seal_inner(stream_id, chunk, flags);
			out.push(frame);
			offset += take;
		}
		out
	}

	/// Parse and open a single frame; returns metadata and plaintext.
	pub fn open_frame(&self, bytes: &[u8]) -> Result<(FrameMeta, Vec<u8>), FramingError> {
		if bytes.len() < HEADER_LEN {
			return Err(FramingError::Incomplete);
		}
		let mut len_bytes = [0u8; 4];
		len_bytes.copy_from_slice(&bytes[0..4]);
		let ct_len = u32::from_be_bytes(len_bytes) as usize;
		if ct_len < TAG_LEN {
			return Err(FramingError::MalformedHeader);
		}
		let mut nonce = [0u8; NONCE_LEN];
		nonce.copy_from_slice(&bytes[4..4 + NONCE_LEN]);
		let mut idx = 4 + NONCE_LEN;
		let mut sid_bytes = [0u8; 4];
		sid_bytes.copy_from_slice(&bytes[idx..idx + 4]);
		let stream_id = u32::from_be_bytes(sid_bytes);
		idx += 4;
		let mut seq_bytes = [0u8; 8];
		seq_bytes.copy_from_slice(&bytes[idx..idx + 8]);
		let seq = u64::from_be_bytes(seq_bytes);
		idx += 8;
		let flags = bytes[idx];
		idx += 1;
		let mut gen_bytes = [0u8; 4];
		gen_bytes.copy_from_slice(&bytes[idx..idx + 4]);
		let generation = u32::from_be_bytes(gen_bytes);
		idx += 4;

		let total_needed = idx.checked_add(ct_len).ok_or(FramingError::MalformedHeader)?;
		if bytes.len() < total_needed {
			return Err(FramingError::Incomplete);
		}
		let ct = &bytes[idx..idx + ct_len];

		let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 4 + 4 + 8 + 1 + 4);
		aad.extend_from_slice(AAD_PREFIX);
		aad.extend_from_slice(&len_bytes);
		aad.extend_from_slice(&sid_bytes);
		aad.extend_from_slice(&seq_bytes);
		aad.extend_from_slice(&[flags]);
		aad.extend_from_slice(&gen_bytes);
		let pt = decrypt(&self.key, &nonce, &aad, ct).map_err(|_| FramingError::Crypto)?;
		let meta = FrameMeta { stream_id, seq, flags, generation };
		Ok((meta, pt))
	}

	/// Backward-compatible helper that discards metadata and returns plaintext only.
	pub fn open(&self, bytes: &[u8]) -> Result<Vec<u8>, FramingError> {
		let (_meta, pt) = self.open_frame(bytes)?;
		Ok(pt)
	}
}


