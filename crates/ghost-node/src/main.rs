use ghost_core::dv_schnorr::{prove_rotate, verify_rotate};
use ghost_core::keys::{address_for, Ghost};
use ghost_core::kdf::{hkdf_sha512};
use ghost_core::types::Epoch;
use ghost_wire::{GHLO, ROTATE};
use rand::RngCore;
use time::OffsetDateTime;

fn current_epoch(t_seconds: u64, epoch_secs: u64) -> Epoch {
	t_seconds / epoch_secs
}

fn main() {
	// Parameters
	let epoch_len = 300u64;
	let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
	let e_old = current_epoch(now, epoch_len);
	let e_new = e_old + 1;

	// Generate two Ghosts for consecutive epochs
	let ghost_old = Ghost::generate(e_old);
	let ghost_new = Ghost::generate(e_new);

	// Simulate a session key and derive dvk (normally from X25519 DH + transcript)
	let mut ss = [0u8; 32];
	rand::thread_rng().fill_bytes(&mut ss);
	let transcript = b"demo-transcript";
	let k_s = hkdf_sha512(&ss, b"sess", transcript, 32);
	let mut id_context = Vec::new();
	id_context.extend_from_slice(&ghost_old.keypair.public.compress().to_bytes());
	id_context.extend_from_slice(&ghost_new.keypair.public.compress().to_bytes());
	id_context.extend_from_slice(&e_old.to_be_bytes());
	let dvk = hkdf_sha512(&k_s, b"dvk", &id_context, 32);

	// Create DV-Schnorr rotate proof
	let proof = prove_rotate(&dvk, e_old, e_new, &ghost_old.keypair.secret, &ghost_new.keypair.secret);

	// Verify proof (designated verifier knowing dvk)
	let ok = verify_rotate(&dvk, &proof);
	println!("Rotate proof verified: {}", ok);

	// Create a GHLO message example
	let mut nonce = [0u8; 24];
	rand::thread_rng().fill_bytes(&mut nonce);
	let ghlo = GHLO {
		ver: 1,
		e: e_old,
		pk: ghost_old.keypair.public.compress().to_bytes().to_vec(),
		nonce: nonce.to_vec(),
		kex: vec![],  // Placeholder: would include X25519 ephemeral public key
		suite: 1,     // Placeholder suite identifier
		opts: Default::default(),
	};
	let bytes = ghost_wire::to_cbor_bytes(&ghlo).expect("serialize GHLO");
	println!("GHLO (CBOR, {} bytes)", bytes.len());

	// Build a ROTATE message from proof for wire
	let rotate_msg = ROTATE {
		e_old: proof.e_old,
		e_new: proof.e_new,
		pk_old: proof.pk_old.clone(),
		pk_new: proof.pk_new.clone(),
		t1: proof.t1.clone(),
		t2: proof.t2.clone(),
		c: proof.c.clone(),
		s1: proof.s1.clone(),
		s2: proof.s2.clone(),
		null: proof.null.clone(),
	};
	let rotate_bytes = ghost_wire::to_cbor_bytes(&rotate_msg).expect("serialize ROTATE");
	println!("ROTATE (CBOR, {} bytes)", rotate_bytes.len());

	// Example: derive address
	let addr = address_for(&ghost_old.keypair.public, e_old);
	println!("Ghost address (e={}): {:02x?}", e_old, addr);
}


