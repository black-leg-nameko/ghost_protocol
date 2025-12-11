use ghost_core::dv_schnorr::{prove_rotate, verify_rotate};
use ghost_core::keys::{address_for, Ghost};
use ghost_core::kdf::{hkdf_sha512};
use ghost_core::kex::{X25519Keypair, dh_shared, derive_session_key};
use ghost_core::mac::hmac_sha512_256;
use ghost_core::transcript::Transcript;
use ghost_core::types::Epoch;
use ghost_core::aead::AeadKey;
use ghost_core::pow::{solve_pow, verify_pow, PowAlgo};
use ghost_wire::{GHLO, ROTATE};
use ghost_wire::framing::{AeadFramer, NonceMode, NONCE_LEN};
use ghost_wire::router::{encode_response, Router, RouteError};
use ghost_wire::transport::UdpTransport;
use ghost_wire::quic::{quic_echo_client, quic_echo_oneshot_server, quic_start_server, quic_client_send_many, quic_start_relay_server, quic_relay_open};
use ghost_wire::nat::stun_binding_request;
use rand::RngCore;
use time::OffsetDateTime;
use tokio::runtime::Runtime;

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
	// === PoW demo (placeholder → implemented): compute a small PoW over GHLO bytes ===
	let pow_salt = &nonce; // reuse GHLO nonce as salt
	let pow = solve_pow(PowAlgo::Sha512_256, 16, &ghlo_bytes, pow_salt);
	let pow_ok = verify_pow(&pow, &ghlo_bytes, pow_salt);
	println!("PoW over GHLO verified: {} (difficulty {} bits, nonce={})", pow_ok, pow.difficulty_bits, pow.nonce);
	// Responder generates its ephemeral
	let eph_b = X25519Keypair::generate();
	// Compose a GACK without MAC for transcript binding
	let gack_without_mac = ghost_wire::GACK {
		e: e_old,
		pk: ghost_new.keypair.public.compress().to_bytes().to_vec(),
		nonce: nonce.to_vec(),
		kex: eph_b.public.as_bytes().to_vec(),
		mac: vec![],
	};
	let gack_wo_bytes = ghost_wire::to_cbor_bytes(&gack_without_mac).expect("serialize GACK(no mac)");
	// Both sides compute DH and bind transcript (GHLO || GACK-without-mac) into the session key
	let ss_a = dh_shared(eph_a.secret, &eph_b.public);
	let mut tr = Transcript::new();
	tr.append(b"GHLO", &ghlo_bytes);
	tr.append(b"GACK", &gack_wo_bytes);
	let tr_hash = tr.finalize();
	let k_s = derive_session_key(&ss_a, &tr_hash);
	let dvk = hkdf_sha512(&k_s, b"dvk", &id_context, 32);

	// Create DV-Schnorr rotate proof
	let proof = prove_rotate(&dvk, e_old, e_new, &ghost_old.keypair.secret, &ghost_new.keypair.secret);

	// Verify proof (designated verifier knowing dvk)
	let ok = verify_rotate(&dvk, &proof);
	println!("Rotate proof verified: {}", ok);

	println!("GHLO (CBOR, {} bytes)", ghlo_bytes.len());
	// GACK size will be printed after routing response is produced

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

	// === AEAD framing demo: seal and open a frame carrying ROTATE ===
	let key = AeadKey::from_bytes(&k_s);
	let mut framer = AeadFramer::new(key, NonceMode::Random);
	let frame = framer.seal(&rotate_bytes);
	let opened = framer.open(&frame).expect("open frame");
	println!("AEAD frame roundtrip ok: {}", opened == rotate_bytes);
	println!("AEAD frame size: {} bytes (payload {} + header {})", frame.len(), rotate_bytes.len(), ghost_wire::framing::HEADER_LEN);

	// === AEAD v2 features demo: multiplexing, fragmentation, rekeying ===
	// Build TX/RX framers sharing the same initial key and counter nonce mode
	let key_tx = AeadKey::from_bytes(&k_s);
	let key_rx = AeadKey::from_bytes(&k_s);
	let mut base_nonce = [0u8; NONCE_LEN];
	rand::thread_rng().fill_bytes(&mut base_nonce);
	let mut framer_tx = AeadFramer::new(key_tx, NonceMode::Counter { base: base_nonce, counter: 0 });
	let mut framer_rx = AeadFramer::new(key_rx, NonceMode::Counter { base: base_nonce, counter: 0 });
	// Enable HKDF-based rekeying with the session key as base
	framer_tx.set_base_key(k_s);
	framer_rx.set_base_key(k_s);

	// Multiplexing: send two small messages on different stream_ids
	let f1 = framer_tx.seal_on_stream(1, b"hello stream 1");
	let f2 = framer_tx.seal_on_stream(2, b"hello stream 2");
	let (m1, p1) = framer_rx.open_frame(&f1).expect("open f1");
	let (m2, p2) = framer_rx.open_frame(&f2).expect("open f2");
	println!("MUX stream {} seq {} gen {}: {}", m1.stream_id, m1.seq, m1.generation, String::from_utf8_lossy(&p1));
	println!("MUX stream {} seq {} gen {}: {}", m2.stream_id, m2.seq, m2.generation, String::from_utf8_lossy(&p2));

	// Fragmentation: split rotate_bytes across multiple frames on stream 3
	let frags = framer_tx.seal_fragmented(3, &rotate_bytes, 32);
	let mut reassembled = Vec::new();
	for frag in frags.iter() {
		let (_meta, pt) = framer_rx.open_frame(frag).expect("open frag");
		reassembled.extend_from_slice(&pt);
	}
	println!("Fragmentation reassembly ok: {}", reassembled == rotate_bytes);

	// Rekey: derive next key on both ends and exchange a frame (stream 1)
	framer_tx.rekey_hkdf_next();
	framer_rx.rekey_hkdf_next();
	let fr_after_rekey = framer_tx.seal_on_stream(1, b"after rekey");
	let (m_after, p_after) = framer_rx.open_frame(&fr_after_rekey).expect("open after rekey");
	println!("After rekey gen {} seq {}: {}", m_after.generation, m_after.seq, String::from_utf8_lossy(&p_after));

	// === Minimal transport demo (UDP loopback) ===
	let udp = UdpTransport::bind("127.0.0.1:0").expect("bind udp");
	let addr = udp.local_addr().expect("local addr");
	let _sent = udp.send_to(&frame, addr).expect("udp send_to self");
	if let Ok((rx, _peer)) = udp.recv() {
		let opened2 = framer.open(&rx).expect("open frame via UDP");
		println!("UDP frame roundtrip ok: {}", opened2 == rotate_bytes);
	}

	// === QUIC (quinn) echo demo (oneshot) ===
	let rt = Runtime::new().expect("tokio runtime");
	let rotate_bytes_clone = rotate_bytes.clone();
	rt.block_on(async move {
		let (srv_addr, srv_cert, _task) = quic_echo_oneshot_server("127.0.0.1:0").await.expect("start quic server");
		let echoed = quic_echo_client(srv_addr, &srv_cert, &rotate_bytes_clone).await.expect("quic echo");
		println!("QUIC echo roundtrip ok: {}", echoed == rotate_bytes_clone);
	});

	// === QUIC persistent server + multi-stream client demo ===
	let rt2 = Runtime::new().expect("tokio runtime");
	rt2.block_on(async move {
		let (endpoint, srv_addr, srv_cert, handle) = quic_start_server("127.0.0.1:0").await.expect("start persistent quic server");
		let payloads = vec![
			b"stream A".to_vec(),
			b"stream B".to_vec(),
			b"stream C".to_vec(),
		];
		let echoed_many = quic_client_send_many(srv_addr, &srv_cert, payloads.clone()).await.expect("quic many");
		let ok = echoed_many == payloads;
		println!("QUIC multi-stream roundtrip ok: {}", ok);
		// shutdown: drop endpoint and abort server loop
		drop(endpoint);
		handle.abort();
	});

	// === NAT traversal: STUN public address discovery ===
	let rt3 = Runtime::new().expect("tokio runtime");
	rt3.block_on(async {
		let stun_server = "stun.l.google.com:19302".parse().unwrap();
		match stun_binding_request(stun_server).await {
			Ok(addr) => println!("STUN mapped address: {}", addr),
			Err(e) => println!("STUN failed: {}", e),
		}
	});

	// === Relay fallback via QUIC: pair two clients with the same session id ===
	let rt4 = Runtime::new().expect("tokio runtime");
	rt4.block_on(async {
		let (endpoint, srv_addr, srv_cert, handle) = quic_start_relay_server("127.0.0.1:0").await.expect("start relay");
		let session_id = *b"ghost-relay-demo!";
		// Client A
		let payload = b"hello via relay".to_vec();
		let t_a = tokio::spawn({
			let cert = srv_cert.clone();
			let p = payload.clone();
			async move {
				let (mut send, _recv) = quic_relay_open(srv_addr, &cert, session_id).await.expect("relay open A");
				// protocol: A sends length+payload and finishes
				let len = (p.len() as u32).to_be_bytes();
				let _ = send.write_all(&len).await;
				let _ = send.write_all(&p).await;
				let _ = send.finish().await;
			}
		});
		// Client B
		let t_b = tokio::spawn({
			let cert = srv_cert.clone();
			async move {
				let (_send, mut recv) = quic_relay_open(srv_addr, &cert, session_id).await.expect("relay open B");
				let mut len_buf = [0u8; 4];
				recv.read_exact(&mut len_buf).await.expect("read len");
				let len = u32::from_be_bytes(len_buf) as usize;
				let mut buf = vec![0u8; len];
				recv.read_exact(&mut buf).await.expect("read body");
				println!("Relay received: {}", String::from_utf8_lossy(&buf));
			}
		});
		let _ = t_a.await;
		let _ = t_b.await;
		// shutdown relay
		drop(endpoint);
		handle.abort();
	});

	// === Minimal routing demo ===
	let mut router = Router::new();
	// Enforce replay window
	router.set_nonce_capacity(1024);
	// Respond to GHLO with a GACK including MAC (key confirmation)
	let responder_pk = ghost_new.keypair.public.compress().to_bytes().to_vec();
	let responder_nonce = nonce.to_vec();
	router.on_ghlo(move |msg| {
		let mut reply = ghost_wire::GACK {
			e: msg.e,
			pk: responder_pk.clone(),
			nonce: responder_nonce.clone(),
			kex: eph_b.public.as_bytes().to_vec(),
			mac: vec![],
		};
		// Bind transcript to GHLO and GACK-without-mac
		let ghlo_bytes_local = ghost_wire::to_cbor_bytes(msg).map_err(|e| RouteError::Handler(format!("encode ghlo: {e}")))?;
		let gack_wo = ghost_wire::to_cbor_bytes(&reply).map_err(|e| RouteError::Handler(format!("encode gack: {e}")))?;
		let mut tr = Transcript::new();
		tr.append(b"GHLO", &ghlo_bytes_local);
		tr.append(b"GACK", &gack_wo);
		let tr_hash = tr.finalize();
		// Derive session key from responder view using initiator kex
		let ss_b = ghost_core::kex::dh_shared_with_bytes(eph_b.secret, &msg.kex)
			.ok_or_else(|| RouteError::Handler("bad kex".into()))?;
		let k_s_b = derive_session_key(&ss_b, &tr_hash);
		// Compute MAC = HMAC(k_s, "GACK-MAC" || tr_hash)
		let mut mac_input = b"GACK-MAC".to_vec();
		mac_input.extend_from_slice(&tr_hash);
		reply.mac = hmac_sha512_256(&k_s_b, &mac_input).to_vec();
		encode_response(&reply).map(Some)
	});
	// Enforce ROTATE verification in router
	let dvk_for_router = dvk.clone();
	router.set_rotate_verifier(move |msg| {
		let proof = ghost_core::dv_schnorr::RotateProof {
			pk_old: msg.pk_old.clone(),
			pk_new: msg.pk_new.clone(),
			t1: msg.t1.clone(),
			t2: msg.t2.clone(),
			c: msg.c.clone(),
			s1: msg.s1.clone(),
			s2: msg.s2.clone(),
			null: msg.null.clone(),
			e_old: msg.e_old,
			e_new: msg.e_new,
		};
		verify_rotate(&dvk_for_router, &proof)
	});
	// Acknowledge ROTATE (router ensures verification passes)
	router.on_rotate(|msg| {
		let ack = ghost_wire::RACK {
			e_new: msg.e_new,
			ack: true,
			note: Some("ok".to_string()),
		};
		encode_response(&ack).map(Some)
	});

	// Route GHLO
	let ghlo_routed = router.route(&ghlo_bytes).expect("route GHLO").expect("reply");
	println!("Router produced GACK ({} bytes) from GHLO", ghlo_routed.len());
	// Initiator verifies GACK MAC (key confirmation)
	let received_gack: ghost_wire::GACK = ghost_wire::from_cbor_bytes(&ghlo_routed).expect("decode GACK");
	let mut gack_recv_wo = received_gack.clone();
	gack_recv_wo.mac = vec![];
	let gack_recv_wo_bytes = ghost_wire::to_cbor_bytes(&gack_recv_wo).expect("encode GACK(no mac)");
	let mut tr2 = Transcript::new();
	tr2.append(b"GHLO", &ghlo_bytes);
	tr2.append(b"GACK", &gack_recv_wo_bytes);
	let tr2_hash = tr2.finalize();
	let mut mac_input2 = b"GACK-MAC".to_vec();
	mac_input2.extend_from_slice(&tr2_hash);
	let expect_mac = hmac_sha512_256(&k_s, &mac_input2);
	let mac_ok = expect_mac.as_slice() == received_gack.mac.as_slice();
	println!("GACK MAC verified: {}", mac_ok);
	// Route ROTATE
	let rotate_routed = router.route(&rotate_bytes).expect("route ROTATE").expect("reply");
	println!("Router produced RACK ({} bytes) from ROTATE", rotate_routed.len());
}


