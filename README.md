# Ghost Protocol Workspace

This repository contains a Rust implementation scaffold for the Ghost: Ephemeral Network Persona (ENP) protocol.

- Protocol spec: `docs/spec.md`
- Crates:
  - `ghost-core`: crypto primitives (keys, HKDF, AEAD), DV-Schnorr rotate proof
  - `ghost-wire`: CBOR message definitions and helpers
  - `ghost-node`: small demo binary (key gen, GHLO/ROTATE example)

## Build

```bash
cargo build --workspace
```

## Run demo

```bash
cargo run -p ghost-node
```

This prints:
- Verification result of a designated-verifier Schnorr rotate proof
- Serialized CBOR sizes for GHLO and ROTATE messages
- Example per-epoch address

## Notes

This is a minimal scaffold to make the spec concrete and compilable. KEX, transcript binding, AEAD record framing, routing, token/PoW, and transport are placeholders and will be filled in subsequent steps.


