use ghost_core::dv_schnorr::{prove_rotate, verify_rotate};
use ghost_core::keys::{address_for, Ghost};
use ghost_core::kdf::{hkdf_sha512};
use ghost_core::kex::{X25519Keypair, dh_shared, derive_session_key};
use ghost_core::transcript::Transcript;
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

	// === KEX + Transcript binding demo ===
	// Initiator generates ephemeral X25519 and sends GHLO with its kex pubkey
	let eph_a = X25519Keypair::generate();
	let mut id_context = Vec::new();
	id_context.extend_from_slice(&ghost_old.keypair.public.compress().to_bytes());
	id_context.extend_from_slice(&ghost_new.keypair.public.compress().to_bytes());
	id_context.extend_from_slice(&e_old.to_be_bytes());
	let mut nonce = [0u8; 24];
	rand::thread_rng().fill_bytes(&mut nonce);
	let ghlo = GHLO {
		ver: 1,
		e: e_old,
		pk: ghost_old.keypair.public.compress().to_bytes().to_vec(),
		nonce: nonce.to_vec(),
		kex: eph_a.public.as_bytes().to_vec(),
		suite: 1,
		opts: Default::default(),
	};
	let ghlo_bytes = ghost_wire::to_cbor_bytes(&ghlo).expect("serialize GHLO");
	// Responder generates its ephemeral and replies with GACK (not defined as struct here; reuse GHLO shape for demo or bytes)
	let eph_b = X25519Keypair::generate();
	// Build a fake GACK-like payload carrying responder kex pubkey and nonce
	let gack_like = ghost_wire::GACK {
		e: e_old,
		pk: ghost_new.keypair.public.compress().to_bytes().to_vec(),
		nonce: nonce.to_vec(),
		kex: eph_b.public.as_bytes().to_vec(),
		mac: vec![], // placeholder
	};
	let gack_bytes = ghost_wire::to_cbor_bytes(&gack_like).expect("serialize GACK");
	// Both sides compute DH and bind transcript (GHLO || GACK) into the session key
	let ss_a = dh_shared(eph_a.secret, &eph_b.public);
	let mut tr = Transcript::new();
	tr.append(b"GHLO", &ghlo_bytes);
	tr.append(b"GACK", &gack_bytes);
	let tr_hash = tr.finalize();
	let k_s = derive_session_key(&ss_a, &tr_hash);
	let dvk = hkdf_sha512(&k_s, b"dvk", &id_context, 32);

	// Create DV-Schnorr rotate proof
	let proof = prove_rotate(&dvk, e_old, e_new, &ghost_old.keypair.secret, &ghost_new.keypair.secret);

	// Verify proof (designated verifier knowing dvk)
	let ok = verify_rotate(&dvk, &proof);
	println!("Rotate proof verified: {}", ok);

	println!("GHLO (CBOR, {} bytes)", ghlo_bytes.len());
	println!("GACK (CBOR, {} bytes)", gack_bytes.len());

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


