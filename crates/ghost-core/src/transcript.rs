use sha2::Digest;
use sha2::Sha512_256;

pub struct Transcript {
	hasher: Sha512_256,
}

impl Transcript {
	pub fn new() -> Self {
		let mut hasher = Sha512_256::new();
		hasher.update(b"ghost/v1 transcript");
		Self { hasher }
	}

	/// Append a labeled message with length prefixes for collision resistance.
	pub fn append(&mut self, label: &[u8], data: &[u8]) {
		let label_len = (label.len() as u64).to_be_bytes();
		let data_len = (data.len() as u64).to_be_bytes();
		self.hasher.update(&label_len);
		self.hasher.update(label);
		self.hasher.update(&data_len);
		self.hasher.update(data);
	}

	pub fn finalize(self) -> [u8; 32] {
		let out = self.hasher.finalize();
		let mut arr = [0u8; 32];
		arr.copy_from_slice(&out);
		arr
	}
}


