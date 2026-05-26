# AGENTS.md

Agent navigation index for `sphragis`.

## Repo layout

```
src/
  lib.rs       — public API surface + version/domain constants
  hybrid.rs    — X-Wing KEM (X25519 + ML-KEM-768) over released RustCrypto primitives
  envelope.rs  — HKDF-SHA256 key derivation + ChaCha20-Poly1305 seal/open
  seal.rs      — multi-recipient WrappedContentKey sealing API
  error.rs     — SealError (snafu)
tests/
  known_answer_vectors.rs — X-Wing KAT, RFC KATs, round-trip, negatives
DECISION.md    — full rationale: why hybrid, why X-Wing, why this envelope
```

## Status

Unaudited preview. All crypto behind `preview-pq`. First consumer: akroasis
(`pinax` reference store). Gate: `cargo test --features preview-pq` green.

## Known design constraints

- `WRAP_DOMAIN_V1 = "sphragis-ck-wrap-v1"` — domain tag is now repo-scoped
  (changed from the akroasis-internal `akroasis-sphragis-ck-wrap-v1` on extraction).
  akroasis consumer must use this tag; any sealed data from the in-akroasis crate
  is NOT forward-compatible with this standalone version.
- `similar_names` clippy allow on `decapsulate` + `encapsulate_deterministic`:
  ss_m/ss_x/ct_x/pk_x mirror X-Wing spec notation; suppression is intentional.
- ML-KEM 0.3.2 pulls `rand_core 0.10` transitively; x25519-dalek 2.0.1 uses
  `rand_core 0.6` at call sites. The two majors coexist.
