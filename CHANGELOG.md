# Changelog

## [0.1.0] — initial extraction

Extracted from `forkwright/akroasis` workspace crate `crates/sphragis` (PR #173,
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
