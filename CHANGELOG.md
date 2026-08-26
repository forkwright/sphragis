# Changelog

## [0.2.3](https://github.com/forkwright/sphragis/compare/v0.2.2...v0.2.3) (2026-08-26)


### Bug Fixes

* **ci:** name the real major on the checkout pin ([#65](https://github.com/forkwright/sphragis/issues/65)) ([113e08c](https://github.com/forkwright/sphragis/commit/113e08cfe87e3ef90b0caa7b7e4ceee6d6587518))
* **sphragis:** correct verification authority ([#69](https://github.com/forkwright/sphragis/issues/69)) ([ce0bcf6](https://github.com/forkwright/sphragis/commit/ce0bcf682fc1867d38e664323cc7761d057b3c7a))
* **sphragis:** tighten license policy ([#68](https://github.com/forkwright/sphragis/issues/68)) ([311a5c4](https://github.com/forkwright/sphragis/commit/311a5c4515fea6945c5f6fda66964415c6530ab1))

## [0.2.2](https://github.com/forkwright/sphragis/compare/v0.2.1...v0.2.2) (2026-08-16)


### Bug Fixes

* **sphragis:** clear pre-existing kanon-lint debt blocking the dispatch gate ([#39](https://github.com/forkwright/sphragis/issues/39)) ([cf0d8e7](https://github.com/forkwright/sphragis/commit/cf0d8e7f1aa7f3c7ca2eacc0c5b6596e9d926c61))

## [0.2.1](https://github.com/forkwright/sphragis/compare/v0.2.0...v0.2.1) (2026-08-16)


### Bug Fixes

* **ci:** run CI on a pull request whose base is not main ([#35](https://github.com/forkwright/sphragis/issues/35)) ([77c86c8](https://github.com/forkwright/sphragis/commit/77c86c848d3925d214f00bead539de24c43c9cff))

## [0.2.0](https://github.com/forkwright/sphragis/compare/v0.1.2...v0.2.0) (2026-08-16)


### ⚠ BREAKING CHANGES

* **sphragis:** make deterministic encapsulation private ([#31](https://github.com/forkwright/sphragis/issues/31))

### Features

* **sphragis:** define revocation as key rotation, not re-wrapping ([#34](https://github.com/forkwright/sphragis/issues/34)) ([37ba8e3](https://github.com/forkwright/sphragis/commit/37ba8e3a678ecb176b5474f36ec71131a1b73c59))
* **sphragis:** narrow the public API to the envelope profile, define the adapter seam ([#32](https://github.com/forkwright/sphragis/issues/32)) ([d0a0bb8](https://github.com/forkwright/sphragis/commit/d0a0bb87f28433c4c28c0a809e7b3e49f109c192))


### Bug Fixes

* **sphragis:** bind the KAT gate to a machine-readable crypto provenance lock ([#27](https://github.com/forkwright/sphragis/issues/27)) ([65e3433](https://github.com/forkwright/sphragis/commit/65e3433ca529d4a9403f8643ea3e8ae2f165f578))
* **sphragis:** bound and fully consume untrusted CBOR before accepting a wrapped key ([#24](https://github.com/forkwright/sphragis/issues/24)) ([d165e5b](https://github.com/forkwright/sphragis/commit/d165e5b5f5a5a7f6c952b0e06983d8f8e0dc6a97))
* **sphragis:** make deterministic encapsulation private ([#31](https://github.com/forkwright/sphragis/issues/31)) ([cf48668](https://github.com/forkwright/sphragis/commit/cf486684d6fd13ebc6e81f12477a9c08a2698779))
* **sphragis:** redact SharedSecret's Debug and retrofit SealError location ([#33](https://github.com/forkwright/sphragis/issues/33)) ([11216eb](https://github.com/forkwright/sphragis/commit/11216ebddae8b28d758a9e91aa8cbd86f41e7be6))
* **sphragis:** return typed entropy failures instead of panicking ([#28](https://github.com/forkwright/sphragis/issues/28)) ([2ff3a08](https://github.com/forkwright/sphragis/commit/2ff3a081164428ff33276a236b19dd9037e03359))

## [Unreleased]

### Changed

- `HybridKem::generate` now returns `Result<(DecapsulationKey,
  EncapsulationKey), SealError>` instead of a bare tuple — **breaking**,
  taken deliberately before the `preview-pq` API stabilizes (#16).
- `EncapsulationKey::encapsulate` and `seal_for` now return
  `SealError::Entropy` if the OS entropy source fails, in addition to their
  existing error paths.

### Fixed

- OS entropy failure no longer panics (#16). `rand_core` 0.6's
  `OsRng::fill_bytes` panics on OS-RNG failure; every entropy draw — key
  generation, encapsulation, and the AEAD nonce inside `seal_for` — now uses
  `try_fill_bytes` and propagates as the new `SealError::Entropy { source:
  rand_core::Error, location }`. A recoverable host entropy failure is now a
  typed, auditable `Result`, not a process abort.

### Added

- `HybridKem::generate_with_rng`, `EncapsulationKey::encapsulate_with_rng`,
  and `seal_for_with_rng`: the same operations with a caller-supplied
  `&mut R: RngCore + CryptoRng`, the trait bound `x25519-dalek`'s own
  `random_from_rng` requires (by reference here, so one RNG's state threads
  through every draw in a call). The OS RNG cannot be made to fail on demand,
  so this is what makes the entropy-failure path (above) testable at all —
  proven in `tests/entropy_failure.rs` with an injected RNG that fails on
  demand, including mid-batch inside `seal_for_with_rng` (no partial wrap set
  is ever returned).
- `rand_core`'s `std` feature (alongside `getrandom`), so `rand_core::Error`
  implements `std::error::Error` and chains behind `SealError::Entropy`.

## [0.1.2](https://github.com/forkwright/sphragis/compare/v0.1.1...v0.1.2) (2026-07-29)


### Bug Fixes

* **release:** keep Cargo.lock in lockstep with the package version ([#19](https://github.com/forkwright/sphragis/issues/19)) ([6964d47](https://github.com/forkwright/sphragis/commit/6964d4711ac07fafeb49bf70d72823ea27342dcd))

## [0.1.1](https://github.com/forkwright/sphragis/compare/v0.1.0...v0.1.1) (2026-07-08)


### Features

* **sphragis:** initial extraction — X-Wing hybrid KEM standalone crate ([24c0db6](https://github.com/forkwright/sphragis/commit/24c0db691fe692781963b83df58cc56d6b9b768a))


### Bug Fixes

* resolve all open audit findings (crypto correctness + zeroization) + lint-clean + Tier-U CI ([#5](https://github.com/forkwright/sphragis/issues/5)) ([3ddcf0e](https://github.com/forkwright/sphragis/commit/3ddcf0edbb7b21039edfc75a8e47e345eba54a47))
* **sphragis:** zeroize HKDF/sha2 digest state via the digest-0.11 generation ([#7](https://github.com/forkwright/sphragis/issues/7)) ([860d7f9](https://github.com/forkwright/sphragis/commit/860d7f95ca4c51868116fa3eabfe9a370a2d37e9))

Audit-hardening pass (issues #1, #3, #4): error propagation, zeroization
coverage, parse-boundary validation, dependency hygiene, test coverage.
Follow-up (#6): HKDF/sha2 digest-state zeroization.

### Changed

- sha2 0.10 → 0.11 (`zeroize` feature) and hkdf 0.12 → 0.13, closing the
  deferred half of the zeroization invariant (#6): the HMAC-keyed Sha256
  cores, block buffers, and PRK-keyed HKDF state now wipe on drop. Before:
  the shared-secret-derived digest state inside the HKDF stack outlived the
  derivation un-zeroized (sha2 0.10 offers no digest-state zeroization).
  `derive_wrap_key` now uses extract-then-wipe instead of `Hkdf::new`, which
  discards an un-zeroized PRK copy internally. HKDF output is unchanged —
  the RFC 5869 KAT is the byte-exactness gate. Residual: safe-Rust move
  semantics can still leave transient stack copies (best-effort stance, as
  with the sha3 0.11 bump). This also unifies the tree on the digest 0.11
  generation — digest 0.10 / hmac 0.12 / sha2 0.10 leave the lockfile.

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
