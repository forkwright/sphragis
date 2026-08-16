# Decision: Fleet-wide post-quantum hybrid sealing (`sphragis`)

Status: adopted — extracted to standalone repo `forkwright/sphragis`
Trigger: akroasis #131 (multi-device content-key wrapping for the offline reference store)
Scope: fleet-wide capability; first consumer akroasis (`pinax` reference store + `kryphos` vault)

## TL;DR

- KEM: **X-Wing** (X25519 + ML-KEM-768), per `draft-connolly-cfrg-xwing-kem` / IACR 2024/039.
  Not a bespoke HKDF combiner, not PQ-only.
- Combiner: **SHA3-256(ss_M || ss_X || ct_X || pk_X || `\.//^\`)** — the X-Wing
  construction. ML-KEM secret first (FIPS SP 800-56C ordering), binds the X25519
  ciphertext + recipient public key.
- Envelope: **HKDF-SHA256 (null salt)** expands the X-Wing shared secret with a
  versioned domain tag, then **ChaCha20-Poly1305** seals the 32-byte content key.
- Wire format: versioned, per-recipient `WrappedContentKey` (CBOR).
- Home: **standalone fleet repo `forkwright/sphragis`** (origin: the akroasis
  workspace, akroasis PR #173).
- Gate: X-Wing draft KAT + RFC 5869 + RFC 8439 + RFC 7748 + FIPS-203 ACVP, behind
  `preview-pq`. Unaudited until cryptographic review.

## 1. Why hybrid, not PQ-only (reversing the 2026-05-26 doc)

`docs/pq-content-key-wrapping.md` (commit dbd91a9) records a "PQ-only ML-KEM"
direction and forbids the classical half. That is cryptographically regressive
and is **not** adopted here. Reasons:

1. ML-KEM was standardized in 2024 (FIPS-203). It is young. A future
   cryptanalytic break of ML-KEM alone — or, more likely, an *implementation*
   break in a pre-1.0 Rust ML-KEM crate — fully compromises a PQ-only system.
   Hybrid means an adversary must break **both** ML-KEM **and** X25519.
2. Every serious deployment is hybrid for exactly this reason: TLS 1.3
   (`X25519MLKEM768`, the de-facto browser/server default), Signal (PQXDH keeps
   classical X3DH), SSH (`sntrup761x25519`, `mlkem768x25519`), and the CFRG
   general-purpose answer, X-Wing. None ship PQ-only.
3. The "smaller audit surface" rationale is inverted: the classical half
   (X25519) is the *most* reviewed asymmetric primitive in existence; dropping
   it removes the trusted half and keeps the unproven one.
4. "No Web Crypto compatibility needed" is true and irrelevant — it argued
   against P-256, not against hybrid. Dropping P-256 in favour of the existing
   X25519 dependency is correct; dropping the classical half entirely is not.

The operator directive ("X25519 + ML-KEM-768 hybrid ... best-in-class,
no-compromise") supersedes the stale doc. This decision recommends replacing
`docs/pq-content-key-wrapping.md` with a hybrid spec.

## 2. Why X-Wing, not the baseline HKDF combiner

The directive's baseline was a PQXDH-style `HKDF-Extract(salt=null, ikm=DH||SS)`
combiner. That is sound, but X-Wing is *genuinely better-justified* for the
specific X25519+ML-KEM-768 pairing:

| Property | Baseline HKDF combiner | Thunderbolt port (#131) | **X-Wing (chosen)** |
|---|---|---|---|
| Standard | generic (PQXDH-shaped) | none (unaudited TS) | CFRG draft, IACR 2024/039 |
| Secret ordering | unspecified | X25519 first (wrong) | ML-KEM first (FIPS SP 800-56C) |
| Binds KEM ct / pk | no | no | binds ct_X + pk_X |
| Combiner primitive | HKDF-SHA256 | HKDF | SHA3-256 (matches ML-KEM's QROM) |
| IND-CCA proof | informal | none | formal (paper §6) |
| Published KAT | no | no | yes (draft Appendix C) |

X-Wing's security theorem: classically IND-CCA if the strong DH assumption holds
in the X25519 group, and post-quantum IND-CCA if ML-KEM-768 is IND-CCA and
SHA3-256 is a secure PRF. It deliberately omits `ct_M` from the combiner — proven
safe via ML-KEM's Fujisaki-Okamoto transform under QROM (paper §6); this is a
deliberate, justified optimization, not an oversight.

X-Wing replaces the *KEM*. HKDF-SHA256 + ChaCha20-Poly1305 are retained for the
*envelope* layer (key-wrapping of the content key) — that is where the directive's
HKDF/ChaCha baseline lands, and it keeps the wrapping AEAD identical to the
existing kryphos stack.

## 3. ML-KEM-768 vs -1024

**ML-KEM-768.** It is NIST Category 3 (≈AES-192). X-Wing is *defined only* over
ML-KEM-768 — choosing -1024 means abandoning the proven hybrid construction for a
bespoke one, a strictly worse trade. Cat-3 is the universal default (TLS, Signal,
X-Wing) precisely because the marginal security of Cat-5 buys little against any
realistic adversary while inflating ciphertext (1568 vs 1088 bytes) and key sizes.
For an offline reference-store wrapping a 32-byte content key, the size delta is
irrelevant, but the loss of the X-Wing proof and KATs is decisive. If a future
Cat-5 requirement appears, it is a new versioned construction (`v2`), not a tweak.

## 4. Envelope, key-wrapping, format

The content key (the symmetric key that actually encrypts reference-store
payloads / vault entries) is wrapped once per recipient device:

```
ss        = XWing.Encaps(recipient_xwing_pubkey)            # 32-byte hybrid secret + ct
wrap_key  = HKDF-SHA256(salt=<32 zero bytes>, ikm=ss,
                        info="sphragis-ck-wrap-v1") # 32 bytes
sealed    = ChaCha20-Poly1305(key=wrap_key, nonce=random12,
                              aad=<canonical recipient-id || version>,
                              pt=content_key[32])
```

`WrappedContentKey` (CBOR, ciborium — matches akroasis serialization). Every
byte-blob field carries `#[serde(with = "serde_bytes")]`, so it wire-encodes as
a single CBOR byte string rather than an array of per-byte integers:

| Field | Type | Notes |
|---|---|---|
| `version` | `u8` | 1; future protocol changes increment, never silent |
| `recipient_id` | `RecipientId([u8; 32])` | BLAKE3 of the recipient X-Wing encapsulation key |
| `kem_ciphertext` | `Vec<u8>`, exactly 1120 | X-Wing ciphertext (ML-KEM ct 1088 \|\| X25519 ct 32) |
| `aead_nonce` | `[u8; 12]` | random per wrap |
| `sealed_key` | `Vec<u8>`, exactly 48 | ChaCha20-Poly1305(content_key) = 32 + 16 tag |

`from_cbor` bounds the parse boundary before trusting any field: input above a
size derived from these lengths is rejected before deserializing, unknown or
duplicate map keys are rejected rather than ignored or last-value-wins, and
decoding fails unless every supplied byte belongs to exactly one top-level
value — a decoder that accepts trailing bytes lets two different byte strings
mean the same envelope, which breaks canonicity for anything that hashes,
signs, or frames the sealed bytes (sphragis#15).

Key-wrapping choice — **ChaCha20-Poly1305, not AES-KW**:
- AES-KW (RFC 3394) has no nonce and no AAD; it cannot bind the recipient-id /
  version into the wrap, and it adds an AES dependency the fleet does not have.
- The released `aes-kw` crate (0.3.0) had a failed release build in the current
  ecosystem churn — a fragile dependency for a no-compromise stack.
- ChaCha20-Poly1305 is already the akroasis AEAD; reuse keeps the trusted-compute
  base minimal and gives nonce + AAD domain-binding for free. The directive's
  "AES-GCM/AES-KW" were offered as options, not mandates; this is the
  better-justified envelope for *this* stack.

Multi-device key distribution vs. revocation (sphragis#14):
- `seal_for(content_key, recipients) -> Vec<WrappedContentKey>` — one wrap per
  device, all decapsulating to the same content key. This **distributes** a
  content key; it has no memory of who has ever recovered one, so re-running
  it over a smaller recipient list only changes who receives the *next*
  wrap — a recipient who already unsealed the key keeps it regardless.
  Describing that as revocation (this section previously did, calling the
  same-key case a "cheap revoke") is a security-contract failure: a consumer
  who implements it believes access was removed when the former device
  still holds the only secret needed to read current and future ciphertext
  under that key.
- Actual revocation is `rotate`'s typed protocol (§11): a new key,
  independent of the old one, wrapped only for the retained set, switched to
  atomically (from the consumer's side), with the old key then retired.
  Ciphertext already written under the old key is unaffected either way —
  see §11 for the boundary this crate cannot cross.

Crypto-agility / versioning:
- `version: u8` in the wire struct + the domain tag string both carry `v1`.
- The KEM identifier is implied by `version` (v1 = X-Wing/X25519+ML-KEM-768).
- A new primitive set = new `version` + new domain tag (`...-v2`); decoders reject
  unknown versions rather than guessing. Negative test enforces this.

## 5. Where it lives

**Standalone fleet repo: `forkwright/sphragis`** (origin: the akroasis
workspace, akroasis PR #173).

- Not folded into `kryphos`: kryphos is "credential vault + installation
  identity" (passphrase-derived symmetric vault key). Multi-recipient hybrid
  key-wrapping is a different concern; mixing them muddies both.
- Standalone: the operator approved extraction so consumers outside akroasis
  can depend on this without a workspace coupling.
- Consumer-agnostic surface: `sphragis` takes only byte arrays and its
  own key types -- zero akroasis-domain coupling. `theke` sync, `arche` secrets,
  and any future fleet crypto consumer can depend on this repo directly.

## 6. Dependencies (released, no release-candidates)

| Crate | Version | Role |
|---|---|---|
| `ml-kem` | 0.3.2 | FIPS-203 ML-KEM-768 (RustCrypto) |
| `x25519-dalek` | 2.0.1 | X25519 (already a workspace dep) |
| `sha3` | 0.11 | SHA3-256 combiner + SHAKE-256 seed expansion (`zeroize` feature wipes digest/XOF state on drop; same digest generation as `ml-kem`) |
| `sha2` | 0.10 | HKDF-SHA256 hash |
| `hkdf` | 0.12 | RFC 5869 extract/expand (digest 0.10 generation — coherent with `sha2` 0.10; hkdf 0.13 requires sha2 0.11 and is incompatible) |
| `chacha20poly1305` | 0.10 | envelope AEAD (already a workspace dep) |
| `zeroize`, `blake3`, `ciborium`, `snafu` | workspace | hygiene/serde/errors |

`subtle` is a direct dependency as of §11 (key rotation): `rotate::PendingRotation::begin`
is this crate's first *direct* secret-vs-secret comparison (the new epoch's
content key against the one it replaces), so it needs `subtle::ConstantTimeEq`
explicitly rather than relying on a transitive copy. Every other comparison in
the crate is over public values (`RecipientId` is the BLAKE3 hash of a public
encapsulation key, carried in plaintext on the wire), or is the Poly1305 tag
check inside `chacha20poly1305`, which already uses `subtle` internally.

Deliberately NOT the `x-wing` crate (0.1.0-rc.0): it pins a *release-candidate*
stack (`ml-kem 0.3.0-rc.0`, `x25519-dalek 3.0.0-pre.6`, `sha3 0.11.0-rc.7`) and
would pull a second, duplicate major of `x25519-dalek` alongside the workspace's
stable 2.0.1. We transcribe the ~15-line X-Wing combiner over the *released*
primitives and gate it on X-Wing's own published KAT — correctness is proven by
the vector, and the trusted-compute base stays on shipped crates. `x-wing` is the
migration target once it reaches a stable release and an audit.

`rand_core` coexistence: `ml-kem` 0.3.2's high-level API is `getrandom`-backed
(no rng handle), so it pulls `rand_core 0.10` purely transitively; `x25519-dalek`
2.0.1 uses `rand_core 0.6` at our call sites. The two majors coexist with no
call-site clash.

## 7. Acceptance gate (KATs)

Behind `preview-pq`, the test suite is the acceptance gate. Which standard
revision, which vector, which vendored/hash-checked source, and which
dependency version each KAT is bound to is **machine-readable** in
[`crypto-provenance.toml`](crypto-provenance.toml) — read there, not here,
and never restate a revision number or vector source in prose again: a
sentence naming a draft revision cannot be checked and drifts silently
(the exact failure mode `crypto-provenance.toml` + `tests/provenance_lock.rs`
replace). In outline, the gate executes:
- X-Wing draft KAT (full hybrid keypair, ciphertext, and shared secret).
- FIPS-203 ML-KEM-768 ACVP KAT (keygen, encapsulation, decapsulation).
- RFC 7748 §5.2 X25519 KAT.
- RFC 5869 HKDF-SHA256 KAT.
- RFC 8439 §2.8.2 ChaCha20-Poly1305 KAT (full AEAD).
- Negative tests: wrong recipient, wrong domain tag, corrupted KEM ciphertext,
  corrupted sealed key, unsupported version.
- `tests/provenance_lock.rs`: every dependency above resolves to the version
  its vector was verified against, and every vendored vector file matches its
  recorded hash — a `cargo update` or a hand-edited fixture fails the gate
  instead of drifting past it.

## 8. Unverified / preview status

Per akroasis#131 done-criterion 6 (crypto lands preview-only until a
cryptographic review closes it), this lands explicitly **unaudited / Preview**:
- `preview-pq` feature, off by default; never in the default binary path.
- Crate-level `//! WARNING` and a `#[deprecated]`-style notice in docs until
  cryptographic review.
- The KATs prove the construction matches the published standard; they do **not**
  substitute for an audit of the implementation.

## 9. Public API boundary: envelope profile, not a primitive library (sphragis#23)

Sphragis earns authority as a versioned, multi-recipient content-key
envelope — wire versioning, recipient identity, domain/AAD binding,
sealing/unsealing, key-epoch semantics. It does not earn authority over the
generic X-Wing/KEM primitive underneath it: that primitive is unaudited (§8),
pinned to this repo's own transcription of the draft (§6), and named in §6 as
something to be *replaced*, not depended on directly.

**What's public.** `generate_recipient_keypair`, `seal_for`, `unseal`,
`RecipientId`, `WrappedContentKey`, `EncapsulationKey`, `DecapsulationKey`.
The last two stay public because they are the profile's recipient-identity
types — `seal_for`/`unseal` take and return them — not because they are
primitives; their key-management operations (`to_bytes`/`from_bytes`,
`from_seed`/`to_seed`, `encapsulation_key`) are profile-level (publish a
device's key, persist a device's secret) and stay reachable. Their *KEM*
operations (raw `encapsulate`/`decapsulate`) do not.

**What moved behind `hazmat`.** `HybridKem`, the raw `SharedSecret` type,
direct `EncapsulationKey::encapsulate`/`DecapsulationKey::decapsulate`, and
`derive_wrap_key` — the generic hybrid-KEM primitive and its raw output. A
normal consumer has no way to assemble a bespoke construction from these
because it cannot name them; it can only call the versioned envelope
operations. `hazmat` carries no stability promise and exists solely so
`tests/known_answer_vectors.rs` can validate the primitive against published
vectors (X-Wing draft, RFC 5869) — the same justification RustCrypto and
rustls use the word "hazmat" for.

**The adapter seam.** `src/hybrid.rs` is now the *only* module that performs
a raw KEM operation; `src/seal.rs` calls it exclusively through
`EncapsulationKey`/`DecapsulationKey`'s key-management surface plus the
crate-private `generate`/`encapsulate`/`decapsulate`/`derive_wrap_key` paths.
Swapping the local X-Wing combiner (§6) for a stable, audited upstream
implementation is therefore a change to `src/hybrid.rs` alone: the
`EncapsulationKey`/`DecapsulationKey` wire forms (`ENCAPSULATION_KEY_LEN`,
`CIPHERTEXT_LEN`, `DECAPSULATION_KEY_LEN`), `seal.rs`'s call shapes, and the
`seal_for`/`unseal`/`generate_recipient_keypair` public API do not move.

**What this decision does not do.** It does not perform the migration §6
already names as the target — upstream `x-wing` is still a release-candidate
stack (§6), and building the seam does not make a pre-release dependency
production-grade. The gate for the actual swap is unchanged from §6: a
stable, audited upstream X-Wing release, whose keypair/ciphertext/shared-secret
KATs are byte-identical to the vectors this repo already pins (a `v1`-wire
adapter, not a `v2` construction) — otherwise it is a new version, not a
drop-in. Until that gate is met, `src/hybrid.rs`'s transcription remains the
implementation and `hazmat` remains the only way to reach it directly.

## 10. Entropy failures are typed, not panics (#16)

`rand_core` 0.6's `OsRng::fill_bytes` panics on OS-RNG failure instead of
returning a `Result` — a transient host entropy failure would otherwise abort
the process rather than surface through `SealError`. Every entropy draw
(`HybridKem::generate`, `EncapsulationKey::encapsulate`, and the AEAD nonce
inside `seal_for`) now goes through `try_fill_bytes`, propagated as
`SealError::Entropy { source: rand_core::Error, location }`.

`HybridKem::generate` becomes fallible (`-> Result<(DecapsulationKey,
EncapsulationKey), SealError>`) — a breaking change taken now, before the
crate's `preview-pq` API stabilizes. `generate_recipient_keypair` (§9's
actual public entry point) becomes fallible with it, for the same reason:
it is a thin wrapper over `HybridKem::generate` and cannot swallow the
`Result` without either panicking (the exact defect this section fixes) or
silently discarding the OS-entropy-failure case its caller needs to see.

The RNG is caller-injectable at the primitive layer
(`HybridKem::generate_with_rng` / `EncapsulationKey::encapsulate_with_rng`,
each `<R: RngCore + CryptoRng>`) — the same trait bound `x25519-dalek`'s own
`random_from_rng` requires, taken by `&mut R` rather than by value so one
injected RNG's state carries across every draw in a call. Per §9's hazmat
boundary, both seams follow `HybridKem::generate`'s own split: `pub(crate)`
without `hazmat`, `pub` with it — an injectable RNG is a
conformance-testing affordance (`tests/entropy_failure.rs`), not something
a normal consumer needs, since `generate_recipient_keypair` always draws
fresh OS randomness. `EncapsulationKey::encapsulate` (the fixed-OsRng
convenience wrapper around `encapsulate_with_rng`) goes one step further and
is `hazmat`-only outright, with no `pub(crate)` variant: `seal_for` never
calls it — `seal_for_with_rng` is itself generic over the RNG and calls
`encapsulate_with_rng` directly — so a non-`hazmat` build has no internal
caller for it (`dead_code`, denied under `-D warnings`) and does not
compile it at all. The envelope layer gets its own seam instead:
`seal_for_with_rng` (not hazmat-gated, alongside `seal_for`) draws twice per
recipient across N recipients — the KEM encapsulation randomness and the
AEAD nonce — which is why it takes
`&mut R` rather than by-value: a by-value take-and-drop parameter would not
let one injected RNG's state carry across every draw in a multi-recipient
batch. This is not a cryptographic choice — the OS RNG cannot be made to
fail on demand, so injection is the only way to exercise the
entropy-failure branch under test at all; a failure mode with no test is an
unverified claim. `rand_core`'s `std` feature is enabled (in addition to
`getrandom`) so `rand_core::Error` implements `std::error::Error` and can
sit behind `SealError::Entropy`'s `source` field with a real chain, rather
than being flattened to a string.

## 11. Key rotation is revocation; `seal_for` alone is not (sphragis#14)

§4's original "Multi-device + revocation" text called re-running `seal_for`
over a smaller recipient list — optionally with a fresh content key —
revocation, including a "cheap revoke" that reused the same key. That is
wrong: a device that has ever unsealed a content key retains it regardless
of whether a later `seal_for` call addresses it, so omitting a wrap changes
who receives the *next* one, not what a former recipient already holds. The
`rotate` module (`src/rotate.rs`) replaces that guidance with a typed
protocol and this section replaces the misnamed one.

**Protocol.** Five stages, enforced in order by a typestate chain
(`PendingRotation -> PublishedWraps -> CommittedEpoch -> RotationComplete`)
so the ordering is a compile error to violate, not a convention to remember:
new content key -> publish wraps for the retained recipients -> the consumer
durably persists those wraps as the epoch's live set -> `commit()`
acknowledges the switch -> `retire_old_key()` erases the orchestrating
caller's copy of the old key. Wire-compatible: rotation calls the same
`seal_for_with_rng` internals `seal_for` does, so `WrappedContentKey`'s CBOR
shape and version do not change.

**What this crate cannot do, stated once, plainly.** Ciphertext already
written under the old content key stays readable by anyone holding that
key, forever — rotation cannot retract a secret from memory it does not
control, so it protects payloads written *after* the epoch switch, not
payloads written before it. `tests/rotation.rs` is the adversarial proof: a
device that recovers the old key before rotation runs remains able to
decrypt payloads already protected under it, and specifically fails to
decrypt payloads protected under the completed new epoch — the property
the issue's evidence found the prior test never modeled. Whether a
consumer re-encrypts its already-stored payloads under the new key is a
decision sphragis has no way to make or enforce, because it never touches
payloads; the conservative default is that rotation does not attempt it,
and `rotate`'s module doc says so rather than leaving a reader to assume
otherwise.

**Design decisions the issue left open:**
- *Does rotation re-encrypt existing payloads, or only protect payloads
  written after the switch?* Forward-only, by construction (the crate has
  no payload to act on) — the conservative reading, chosen explicitly
  rather than left ambiguous. A consumer that wants old payloads
  re-protected performs that itself, against its own store.
- *Who allocates the epoch identifier `rotate::EpochId` carries through the
  protocol?* The caller, not sphragis: this crate holds no persistent state
  across calls, so it cannot allocate or validate a monotonic sequence
  itself — that bookkeeping already belongs to whatever store tracks "which
  wrap set is current" for a device. `EpochId` is an opaque `u64` sphragis
  carries through the typestate chain unmodified, mirroring how content-key
  generation itself has always been caller-visible (`generate_content_key`
  exists for convenience, not because sphragis owns key material lifecycle).
- *What does "atomically switch the epoch" mean for a crate with no
  storage?* Only the consumer's own store transaction can make an epoch
  switch atomic. `PublishedWraps::commit()` cannot perform that transaction;
  what it can and does guarantee is ordering — the type system refuses to
  produce a `CommittedEpoch` (and therefore refuses `retire_old_key`) until
  the caller has called `commit()`, so the old key cannot be destroyed
  before the caller has at least acknowledged the new epoch is durably live.
- *Same-key rotation.* `PendingRotation::begin` rejects a new content key
  equal to the old one (`SealError::ContentKeyUnchanged`), compared via
  `subtle::ConstantTimeEq` since both operands are secret (see §6). Without
  this check a caller could accidentally rotate into a no-op that produces a
  full new wrap set while changing nothing a revoked recipient cannot
  already decrypt.
