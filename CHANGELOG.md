# Changelog

## [Unreleased]

Audit-hardening pass (issues #1, #3, #4): error propagation, zeroization
coverage, parse-boundary validation, dependency hygiene, test coverage.

### Changed

- `EncapsulationKey::encapsulate` and `encapsulate_deterministic` now return
  `Result<(Vec<u8>, SharedSecret), SealError>`. Before: a conversion failure on
  the ML-KEM message seed was silently replaced with an all-zero array via
  `unwrap_or_default()` — a fail-open idiom inside the randomness path. The
  error is unreachable for well-formed input, but it now propagates as
  `SealError::WrongLength` per the crate's no-silent-fallback discipline.
- `DecapsulationKey::to_seed` now returns `Zeroizing<[u8; 32]>` instead of a
  bare array, matching the crate invariant that all key material is
  `Zeroizing`. The "caller must zeroize" contract is gone.
- `WrappedContentKey::from_cbor` validates the v1 wire shape after decoding:
  unknown `version` → `UnsupportedVersion`; `kem_ciphertext` /`sealed_key`
  lengths must match the v1 construction → `WrongLength`. Untrusted CBOR can
  no longer hand unbounded `Vec<u8>` fields to the KEM/AEAD paths. Callers
  still bound the input buffer itself.
- `sha3` 0.10 → 0.11 with its `zeroize` feature: hasher and XOF-reader state
  (which absorb seed-derived material during expansion and combining) are now
  wiped on drop; 0.10 had no digest-state zeroization. Also collapses the two
  sha3 majors in the tree (`ml-kem` already used 0.11). KATs unchanged
  byte-for-byte.

### Fixed

- Zeroization of transient secrets: the ML-KEM message seed and both ML-KEM
  shared-secret copies (encaps + decaps) are now held in `Zeroizing`;
  `generate()` fills its seed inside `Zeroizing` (no bare stack copy);
  `from_seed` wipes its residual `Copy` parameter; `expand()` reads the XOF
  directly into a `Zeroizing` seed buffer (the former `seed_arr` binding
  leaked a plaintext ML-KEM seed copy). `decapsulate` parses all fallible
  input before deriving secrets, so no early return can leak a live secret.
- Removed the unused direct `subtle` dependency. The crate compares only
  public values; the secret-dependent Poly1305 tag comparison lives inside
  `chacha20poly1305` (which uses `subtle` internally). Rationale recorded in
  `DECISION.md` §6.

### Added

- `envelope::TAG_LEN` (Poly1305 tag length) for wire-shape validation.
- Tests: seed export round-trip (`to_seed`/`from_seed`), encapsulation-key
  wire round-trip, wrong-length ek/ct rejection, encapsulation and `seal_for`
  randomness freshness, empty-recipient (full revocation) boundary, isolated
  recipient-id AAD binding, `from_cbor` parse-boundary rejection (oversized
  KEM ciphertext, wrong-length sealed key, unknown version), and a
  `to_seed` assertion inside the X-Wing KAT.

## [0.1.0] — initial extraction

Origin: `forkwright/akroasis` workspace crate `crates/sphragis` (PR #173,
commit `9d7ef5f`). Design unchanged; relocated to standalone fleet repo so
consumers outside akroasis can depend on it without a workspace dependency.

### Changes from in-akroasis version

- `WRAP_DOMAIN_V1` updated from `akroasis-sphragis-ck-wrap-v1` to
  `sphragis-ck-wrap-v1`. Sealed data from the in-akroasis crate is NOT
  forward-compatible; akroasis consumer dependency was repointed concurrently
  (akroasis PR #174).
- Cargo.toml is now a standalone crate manifest (no `workspace = true`
  inheritance); versions pinned to the same values that were in the akroasis
  workspace.
- `dev-dependencies` for `hkdf`/`sha2`/`x25519-dalek` are now explicit (they
  were previously workspace-inherited and visible to all crates).

### Construction (v1)

- KEM: X-Wing (X25519 + ML-KEM-768), `draft-connolly-cfrg-xwing-kem`
- Envelope: HKDF-SHA256 (null salt) → ChaCha20-Poly1305
- Wire: versioned, per-recipient `WrappedContentKey` (CBOR)
- Gate: X-Wing draft KAT + RFC 5869 + RFC 7748 + round-trip + negatives
