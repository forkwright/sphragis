<!--
scope: sphragis repo conventions
defers_to: ~/.claude/CLAUDE.md for operator principles
tightens: none
-->

# CLAUDE.md

Project conventions for AI coding agents working on this codebase.

## What this is

A standalone fleet crate providing the X-Wing hybrid KEM (X25519 + ML-KEM-768)
plus an HKDF-SHA256 + ChaCha20-Poly1305 envelope for multi-device content-key
sealing. All crypto is behind `preview-pq` and unaudited.

## Standards

Universal: `crates/basanos/standards/STANDARDS.md` in `forkwright/kanon`

## Key patterns

- **Errors:** `snafu` with `.context()` propagation
- **Zeroize:** all key material is `Zeroizing<>` or `ZeroizeOnDrop`
- **Features:** `preview-pq` gates all crypto; default build is inert
- **Lints:** `#[expect(lint, reason = "...")]` over `#[allow]`, always
- **Visibility:** `pub(crate)` by default

## Testing

```bash
cargo test --features preview-pq        # all tests incl. X-Wing KAT
cargo clippy --all-targets --features preview-pq -- -D warnings
cargo fmt --all -- --check
```

## Before submitting

1. `cargo test --features preview-pq` passes
2. `cargo clippy --all-targets --features preview-pq -- -D warnings` passes
3. `cargo fmt --all -- --check` clean
4. Gate-Passed trailer present on commit

## Git

Conventional commits: `<type>(<scope>): <description>`. Scope is `sphragis`.
Branch from `main`. Squash merge.
