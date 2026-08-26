<!--
scope: sphragis repo navigation for coding agents
defers_to: CLAUDE.md for project conventions
tightens: none
-->

# AGENTS.md

Agent navigation index for `sphragis`.

## Repo layout

```
src/
  lib.rs       — public API surface + version/domain constants
  hybrid.rs    — X-Wing KEM (X25519 + ML-KEM-768) over released RustCrypto primitives
  envelope.rs  — HKDF-SHA256 key derivation + ChaCha20-Poly1305 seal/open
  seal.rs      — multi-recipient WrappedContentKey sealing API (key DISTRIBUTION, not revocation)
  rotate.rs    — typed key-rotation protocol (actual device revocation, sphragis#14)
  error.rs     — SealError (snafu)
tests/
  known_answer_vectors.rs — X-Wing KAT, FIPS-203 ML-KEM-768 ACVP KAT, RFC KATs
  seal_roundtrip.rs        — envelope API: round-trip, multi-recipient, negatives,
                             wire/parse boundaries (split from known_answer_vectors.rs,
                             forkwright/sphragis#37)
  rotation.rs              — adversarial revocation proof: a device holding the
                             old content key fails to read the completed new epoch
  gate_fitness.rs          — locks required public-gate feature coverage and
                             the no-docs-exemption choice
  provenance_lock.rs      — enforces crypto-provenance.toml against Cargo.lock
                             and the vendored vector files
  vectors/                — vendored, hash-locked upstream vector fixtures
crypto-provenance.toml — SSOT: standard revision / source URL / vector hash /
                          locked dependency version per KAT
DECISION.md    — full rationale: why hybrid, why X-Wing, why this envelope
```

## Status

Unaudited preview: every cryptographic operation lives behind the
`preview-pq` feature flag, off by default, so the crate ships inert until a
caller opts in explicitly. No downstream consumer currently exists; the
intended future integration is akroasis's reference-store layer.
The required public gate exercises default, `preview-pq`, and
`preview-pq,hazmat` profiles; passing it does not replace the required
independent cryptographic review.

## Known design constraints

- `WRAP_DOMAIN_V1 = "sphragis-ck-wrap-v1"` — domain tag is now repo-scoped
  (changed from the akroasis-internal `akroasis-sphragis-ck-wrap-v1` on extraction).
  Any future akroasis integration must use this tag; sealed data from the
  in-akroasis crate is NOT forward-compatible with this standalone version.
- `similar_names` clippy `#[expect]` on `decapsulate` + `encapsulate_deterministic`:
  ss_m/ss_x/ct_x/pk_x mirror X-Wing spec notation; suppression is intentional.
- ML-KEM 0.3.2 and x25519-dalek 3.x pull `rand_core 0.10` transitively. This
  crate's injectable seams remain on direct `rand_core 0.6` and pass owned
  bytes, not RNG handles, across either provider boundary.
- `seal_for` is recipient-key **distribution**, not revocation — a recipient
  who ever unsealed a content key keeps it regardless of a later `seal_for`
  call omitting them. `rotate` is the actual revocation protocol, and it
  cannot retroactively protect ciphertext already written under the key it
  replaces (sphragis#14; see DECISION.md §11 and `tests/rotation.rs`).
