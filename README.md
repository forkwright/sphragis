# sphragis

*σφραγίς - seal / signet*

Post-quantum hybrid sealing for multi-device content-key distribution. Seals a
32-byte content key for one or more recipient devices so only a holder of the
matching secret key can recover it, with security resting on **both** a classical
(X25519) and a post-quantum (ML-KEM-768) assumption.

> **UNAUDITED PREVIEW.** All cryptography is behind the `preview-pq` feature and
> is never on the default binary path. The known-answer tests prove the
> construction matches the published standards; they are not a substitute for a
> cryptographic review. See [`DECISION.md`](DECISION.md).

## Construction (v1)

- **KEM**: X-Wing (`draft-connolly-cfrg-xwing-kem`, IACR 2024/039) - X25519 +
  ML-KEM-768, combined via `SHA3-256(ss_M || ss_X || ct_X || pk_X || "\.//^\")`.
- **Envelope**: HKDF-SHA256 (null salt, versioned domain tag) → ChaCha20-Poly1305
  seals the content key; version + recipient id bound as AEAD associated data.
- **Wire**: versioned, per-recipient `WrappedContentKey` (CBOR).

## Usage

Add to `Cargo.toml`:

```toml
sphragis = { git = "https://github.com/forkwright/sphragis", features = ["preview-pq"] }
```

```rust,ignore
use sphragis::{generate_recipient_keypair, seal_for, unseal};

// Each device holds a keypair; publish the encapsulation (public) key.
let (dk, ek) = generate_recipient_keypair()?;

// Seal a content key for a set of devices (one wrap each, same content key).
let content_key = [0u8; 32];
let wrapped = seal_for(&content_key, &[ek])?;

// A device unseals its wrap with its decapsulation (secret) key.
let recovered = unseal(&dk, &wrapped[0])?;
assert_eq!(recovered.as_slice(), &content_key);
```

This is the entire public contract: the generic hybrid-KEM primitive
underneath (`HybridKem`, a raw shared secret, direct encaps/decaps) is not
exported — see "Features" below and `DECISION.md` for the envelope-vs-primitive
boundary (sphragis#23).

`seal_for` **distributes** a content key to a recipient set; it has no memory
of who has ever recovered one, so re-running it over a smaller list is not
revocation — a recipient who already unsealed the key keeps it regardless of
whether a later call addresses them again. Actually revoking a device is a
typed protocol in the `rotate` module: generate a new content key, publish
wraps of it for the retained recipients only, commit the new epoch, then
retire the old key.

```rust,ignore
use sphragis::{generate_content_key, EpochId, PendingRotation};

let new_content_key = generate_content_key()?;
let pending = PendingRotation::begin(EpochId(1), &new_content_key, &old_content_key)?;
let published = pending.publish_wraps_for(&retained_recipients)?; // device 2 excluded
// Persist `published.wraps()` as epoch 1's live wrap set, then:
let committed = published.commit();
committed.retire_old_key(old_content_key);
```

**What rotation does not protect.** Ciphertext already written under the old
content key stays readable by anyone who holds that key — including a
recipient this rotation just excluded, if they ever unsealed it before now.
Rotation protects data written *after* the switch, not data written before
it; re-encrypting old data under the new key, if wanted, is the consumer's
own operation against their own store. See `src/rotate.rs`'s module doc and
`tests/rotation.rs` for the adversarial proof.

## Features

- `preview-pq` - enables the hybrid KEM + envelope. **Off by default.**
- `hazmat` - exposes the generic hybrid-KEM primitive (`HybridKem`, raw shared
  secret, direct encaps/decaps, `derive_wrap_key`) for known-answer/conformance
  testing. **No stability promise; a normal consumer never enables this.**

## Testing

```sh
cargo test --features preview-pq
```

Every known-answer test's standard revision, vector source, source hash, and
locked dependency version are declared in
[`crypto-provenance.toml`](crypto-provenance.toml) and enforced by
`tests/provenance_lock.rs` — a `cargo update` that moves a locked crypto
dependency, or an edit to a vendored vector fixture, fails the gate.

## Why hybrid, not PQ-only

ML-KEM-768 alone places all trust in a 2024-vintage primitive and its pre-1.0
implementations. The hybrid forces an adversary to break both ML-KEM **and**
X25519 - matching TLS 1.3 (`X25519MLKEM768`), Signal (PQXDH), SSH
(`mlkem768x25519`), and the CFRG general-purpose answer (X-Wing).

Full rationale: [`DECISION.md`](DECISION.md).

## License

AGPL-3.0-only. See [`LICENSE`](LICENSE).
