use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

pub struct AeadKey(pub Key);

impl AeadKey {
	pub fn from_bytes(k: &[u8]) -> Self {
		let mut key = [0u8; 32];
		key.copy_from_slice(&k[..32]);
		Self(Key::from_slice(&key).to_owned())
	}
}

pub fn encrypt(key: &AeadKey, nonce12: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
	let cipher = ChaCha20Poly1305::new(&key.0);
	let nonce = Nonce::from_slice(nonce12);
	cipher.encrypt(nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad }).expect("encrypt")
}

pub fn decrypt(key: &AeadKey, nonce12: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
	let cipher = ChaCha20Poly1305::new(&key.0);
	let nonce = Nonce::from_slice(nonce12);
	cipher.decrypt(nonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad })
}


