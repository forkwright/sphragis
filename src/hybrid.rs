//! X-Wing hybrid KEM (X25519 + ML-KEM-768).
//!
//! Faithful transcription of `draft-connolly-cfrg-xwing-kem` over released
//! `RustCrypto` primitives. The draft revision this is bound to, and the pinned
//! version of every crate the construction was verified against, live in
//! `crypto-provenance.toml` and are enforced by `tests/provenance_lock.rs`. The
//! combiner binds the ML-KEM shared secret (first, per FIPS SP 800-56C ordering),
//! the X25519 shared secret, the X25519 ciphertext, and the recipient X25519
//! public key, under the X-Wing domain label.
//!
//! WARNING: unaudited. Validated against the X-Wing draft known-answer vectors.
//!
//! INVARIANT: this module is the primitive side of the envelope seam
//! (sphragis#23). [`EncapsulationKey`]/[`DecapsulationKey`] are the stable,
//! always-public identity types [`crate::seal::seal_for`]/
//! [`crate::seal::unseal`] operate on; everything that performs a raw KEM
//! operation on them (`HybridKem`, `SharedSecret`, direct encaps/decaps) is
//! reachable only with the `hazmat` feature. RustCrypto publishes `x-wing`
//! 0.1.0, but its security warning says it has never been independently
//! audited. This module and the exact resolved provider graph remain the
//! current review target. A future migration stays behind this seam, but its
//! graph, provenance, and key hygiene require separate review; `seal.rs`'s
//! calls and the public identity types do not change.

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Key, KeyExport};
use ml_kem::{B32, Ciphertext as MlKemCiphertext, MlKem768, Seed};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, Zeroizing};

use rand_core::{CryptoRng, OsRng, RngCore};
use snafu::{ResultExt, ensure};

use crate::error::{EntropySnafu, InvalidMlKemSnafu, SealError, WrongLengthSnafu};

/// X-Wing domain-separation label: ASCII `\.//^\`.
const X_WING_LABEL: &[u8; 6] = br"\.//^\";

/// ML-KEM-768 ciphertext length in bytes.
const ML_KEM_CT_LEN: usize = 1088;
/// ML-KEM-768 encapsulation-key length in bytes.
const ML_KEM_EK_LEN: usize = 1184;
/// X25519 public-key / ciphertext length in bytes.
const X25519_LEN: usize = 32;

/// X-Wing encapsulation-key (public) length: ML-KEM ek || X25519 pk.
pub const ENCAPSULATION_KEY_LEN: usize = ML_KEM_EK_LEN + X25519_LEN; // kanon:ignore RUST/pub-visibility -- public wire-shape constant (KAT gate consumes it)
/// X-Wing ciphertext length: ML-KEM ct || X25519 ct.
pub const CIPHERTEXT_LEN: usize = ML_KEM_CT_LEN + X25519_LEN; // kanon:ignore RUST/pub-visibility -- public wire-shape constant (KAT gate consumes it)
/// X-Wing decapsulation-key (private) seed length.
pub const DECAPSULATION_KEY_LEN: usize = 32; // kanon:ignore RUST/pub-visibility -- public constant in from_seed/to_seed signatures
/// Hybrid shared-secret length.
pub const SHARED_SECRET_LEN: usize = 32; // kanon:ignore RUST/pub-visibility -- public constant in the SharedSecret newtype

/// A hybrid shared secret. Zeroized on drop.
///
/// A newtype, not a bare `Zeroizing<[u8; N]>` alias (sphragis#25): a plain
/// alias derives `Debug` from `[u8; N]` itself, so `{:?}` would print the
/// live secret bytes — `Zeroizing` protects memory on drop, not the value
/// while it is alive. This type's `Debug` (below) is hand-written to redact
/// them instead, matching [`DecapsulationKey`]'s existing redacted `Debug`.
/// `Zeroizing` still owns the storage, so drop-zeroize is unchanged.
///
/// Internal: without `hazmat`, no operation (`HybridKem::generate`, direct
/// `encapsulate`/`decapsulate`, `derive_wrap_key` — see sphragis#23) can
/// produce one, so the type itself is `pub(crate)`, matching `HybridKem`'s
/// own `pub(crate)`/`pub` split below. `EncapsulationKey::encapsulate_deterministic`
/// (the one other former source of a `SharedSecret`) is a private method
/// (forkwright/sphragis#17), not a public one, so it does not force this
/// type to stay reachable.
#[cfg(not(feature = "hazmat"))]
pub(crate) struct SharedSecret(Zeroizing<[u8; SHARED_SECRET_LEN]>);
/// A hybrid shared secret. Zeroized on drop.
///
/// A newtype, not a bare `Zeroizing<[u8; N]>` alias — see the non-`hazmat`
/// doc comment above for why (sphragis#25).
///
/// HAZMAT: the generic hybrid-KEM primitive's raw output, reachable only
/// with the `hazmat` feature — no stability promise (sphragis#23).
// kanon:ignore RUST/pub-visibility -- hazmat-only primitive surface (sphragis#23): re-exported for KAT/conformance testing, feature-gated off the normal public API
#[cfg(feature = "hazmat")]
pub struct SharedSecret(Zeroizing<[u8; SHARED_SECRET_LEN]>);

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}

impl SharedSecret {
    /// Returns the shared secret's bytes.
    ///
    /// WARNING: the returned slice must never be logged, printed, or
    /// otherwise persisted outside the derivation it feeds — that is
    /// exactly the leak this type's redacting `Debug` exists to prevent one
    /// layer up.
    // kanon:ignore PERFORMANCE/missing-complexity-docs -- false positive (forkwright/kanon#3088):
    // the rule's self-recursion detector is a bare substring match on `"as_slice("`, so
    // `self.0.as_slice()` (calling the WRAPPED `Zeroizing<[u8; N]>`'s own method, a different
    // receiver) reads as this function recursing into itself. It is a single field access, O(1),
    // no recursion.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

type MlKemDk = ml_kem::DecapsulationKey<MlKem768>;
type MlKemEk = ml_kem::EncapsulationKey<MlKem768>;

/// The X-Wing hybrid KEM over X25519 + ML-KEM-768.
///
/// Internal: a normal consumer calls
/// [`crate::seal::generate_recipient_keypair`] instead of naming this type —
/// see sphragis#23 (envelope-vs-primitive API boundary).
///
/// Without `hazmat`, `HybridKem` is not exported from the crate root or
/// `hybrid` module — a downstream consumer cannot name it:
///
/// ```compile_fail
/// # fn _f() -> Result<(), Box<dyn std::error::Error>> {
/// let _ = sphragis::HybridKem::generate(); // unresolved: not exported without `hazmat`
/// # Ok(())
/// # }
/// ```
#[cfg(not(feature = "hazmat"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct HybridKem;
/// The X-Wing hybrid KEM over X25519 + ML-KEM-768.
///
/// HAZMAT: the generic hybrid-KEM primitive, reachable only with the
/// `hazmat` feature — no stability promise, and no upstream-adapter
/// migration promise either (see `DECISION.md`). A normal consumer calls
/// [`crate::seal::generate_recipient_keypair`] instead.
// kanon:ignore RUST/pub-visibility -- hazmat-only primitive surface (sphragis#23): re-exported for KAT/conformance testing, feature-gated off the normal public API
#[cfg(feature = "hazmat")]
#[derive(Clone, Copy, Debug)]
pub struct HybridKem;

/// X-Wing public (encapsulation) key.
///
/// Public data: freely serializable and shareable. Wire form is
/// `ML-KEM-768 ek (1184) || X25519 pk (32)`.
///
/// [`encapsulate`](Self::encapsulate) — which always draws fresh OS
/// randomness — is the only encapsulation entry point reachable from outside
/// this crate. The deterministic path the known-answer test needs is a
/// private method, not part of this type's public API:
///
/// ```compile_fail
/// # use sphragis::HybridKem;
/// let (_dk, ek) = HybridKem::generate();
/// let randomness = [0u8; 64];
/// // `encapsulate_deterministic` is private — this does not compile.
/// let _ = ek.encapsulate_deterministic(&randomness);
/// ```
#[derive(Clone)]
pub struct EncapsulationKey {
    ek_m: MlKemEk,
    pk_x: XPublic,
}

/// X-Wing private (decapsulation) key.
///
/// Stored as the 32-byte X-Wing seed; the ML-KEM decapsulation key and X25519
/// secret are expanded deterministically. Zeroized on drop.
// kanon:ignore RUST/pub-visibility -- re-exported in lib.rs; no derive (manual REDACTED Debug), so the derive skip cannot engage
pub struct DecapsulationKey {
    seed: Zeroizing<[u8; DECAPSULATION_KEY_LEN]>,
}

impl core::fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DecapsulationKey([REDACTED])")
    }
}

impl HybridKem {
    /// Generates a fresh X-Wing keypair using the OS CSPRNG.
    ///
    /// Internal: [`crate::seal::generate_recipient_keypair`] is the stable
    /// entry point.
    ///
    /// WHY: thin on purpose — fixes the RNG to `OsRng` so a normal caller
    /// never has to choose one; `generate_with_rng`'s own doc comment
    /// carries the entropy-injection rationale for the one caller (tests)
    /// that needs a deterministically-failing source.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Entropy`] if the OS entropy source fails.
    #[cfg(not(feature = "hazmat"))]
    pub(crate) fn generate() -> Result<(DecapsulationKey, EncapsulationKey), SealError> {
        Self::generate_with_rng(&mut OsRng)
    }

    /// Generates a fresh X-Wing keypair using the OS CSPRNG.
    ///
    /// HAZMAT: reachable only with the `hazmat` feature — no stability
    /// promise. A normal consumer calls
    /// [`crate::seal::generate_recipient_keypair`] instead.
    ///
    /// WHY: thin on purpose — fixes the RNG to `OsRng` so a normal caller
    /// never has to choose one; `generate_with_rng`'s own doc comment
    /// carries the entropy-injection rationale for the KAT gate's
    /// deterministic-failure test.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Entropy`] if the OS entropy source fails.
    // kanon:ignore RUST/pub-visibility -- hazmat-only primitive surface (sphragis#23): reachable for KAT/conformance testing, feature-gated off the normal public API
    #[cfg(feature = "hazmat")]
    pub fn generate() -> Result<(DecapsulationKey, EncapsulationKey), SealError> {
        Self::generate_with_rng(&mut OsRng)
    }

    /// Generates a fresh X-Wing keypair from the given CSPRNG.
    ///
    /// Internal: no envelope-level equivalent exists — an injectable RNG is
    /// a primitive/conformance-testing affordance (proves the entropy-typed
    /// error path, sphragis#16), not something a normal consumer needs;
    /// [`crate::seal::generate_recipient_keypair`] always draws fresh OS
    /// randomness.
    ///
    /// WHY: isolates the entropy source behind an injectable seam. `OsRng`'s
    /// infallible `fill_bytes` panics on OS-RNG failure (`rand_core` 0.6
    /// `os.rs`); a generic caller-supplied `rng` lets tests substitute a
    /// deterministically-failing source and prove the typed-error path
    /// without depending on the real OS RNG ever failing.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Entropy`] if `rng` fails to supply randomness.
    #[cfg(not(feature = "hazmat"))]
    pub(crate) fn generate_with_rng<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(DecapsulationKey, EncapsulationKey), SealError> {
        generate_with_rng_impl(rng)
    }

    /// Generates a fresh X-Wing keypair from the given CSPRNG.
    ///
    /// HAZMAT: reachable only with the `hazmat` feature — no stability
    /// promise. See [`generate`](Self::generate)'s doc comment for the
    /// entropy-source rationale; `tests/entropy_failure.rs` is the consumer
    /// (sphragis#16).
    ///
    /// WHY: HAZMAT-gates the injectable-RNG seam so the KAT/conformance
    /// suite can supply a deterministically-failing source and prove the
    /// typed-error path — the same rationale as the non-hazmat
    /// `generate_with_rng` above, restated here because the two are
    /// compiled under mutually exclusive `cfg`s and neither doc is visible
    /// alongside the other.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Entropy`] if `rng` fails to supply randomness.
    // kanon:ignore RUST/pub-visibility -- hazmat-only primitive surface (sphragis#23): reachable for KAT/conformance testing, feature-gated off the normal public API
    #[cfg(feature = "hazmat")]
    pub fn generate_with_rng<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(DecapsulationKey, EncapsulationKey), SealError> {
        generate_with_rng_impl(rng)
    }
}

// WHY: the seed is born inside Zeroizing so no bare stack copy ever exists;
// on entropy failure the partially/un-filled buffer is dropped (zeroized)
// here and no key is returned.
fn generate_with_rng_impl<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(DecapsulationKey, EncapsulationKey), SealError> {
    let mut seed = Zeroizing::new([0u8; DECAPSULATION_KEY_LEN]);
    rng.try_fill_bytes(seed.as_mut_slice())
        .context(EntropySnafu)?;
    let dk = DecapsulationKey { seed };
    let ek = dk.encapsulation_key();
    Ok((dk, ek))
}

impl DecapsulationKey {
    /// Reconstructs a decapsulation key from its 32-byte seed.
    // WHY: the parameter is a Copy array; the caller's binding is out of reach,
    // but the residual copy in this frame is wiped before returning.
    #[must_use]
    pub fn from_seed(mut seed: [u8; DECAPSULATION_KEY_LEN]) -> Self {
        let dk = Self {
            seed: Zeroizing::new(seed),
        };
        seed.zeroize();
        dk
    }

    /// Returns the 32-byte seed, zeroized on drop.
    #[must_use]
    pub fn to_seed(&self) -> Zeroizing<[u8; DECAPSULATION_KEY_LEN]> {
        self.seed.clone()
    }

    /// Derives the matching public encapsulation key.
    // kanon:ignore PERFORMANCE/missing-complexity-docs -- false positive (forkwright/kanon#3088):
    // the rule's self-recursion detector is a bare substring match on `"encapsulation_key("`, so
    // `dk_m.encapsulation_key()` (calling `ml_kem::DecapsulationKey`'s own method, a completely
    // different type) reads as this function recursing into itself. It derives a keypair from a
    // seed via one HKDF-shaped expansion, O(1) in the number of calls this makes -- no iteration
    // over caller-controlled input, no recursion.
    #[must_use]
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        let (dk_m, sk_x) = expand(&self.seed);
        let ek_m = dk_m.encapsulation_key().clone();
        let pk_x = XPublic::from(&sk_x);
        EncapsulationKey { ek_m, pk_x }
    }

    /// Decapsulates a ciphertext to recover the hybrid shared secret.
    ///
    /// Internal: [`crate::seal::unseal`] is the stable entry point.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::WrongLength`] if the ciphertext is malformed, or
    /// [`SealError::InvalidMlKem`] if the ML-KEM component is rejected.
    #[cfg(not(feature = "hazmat"))]
    pub(crate) fn decapsulate(&self, ct: &[u8]) -> Result<SharedSecret, SealError> {
        self.decapsulate_impl(ct)
    }

    /// Decapsulates a ciphertext to recover the hybrid shared secret.
    ///
    /// HAZMAT: reachable only with the `hazmat` feature, for known-answer
    /// testing only — no stability promise. A normal consumer calls
    /// [`crate::seal::unseal`] instead, which decapsulates internally.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::WrongLength`] if the ciphertext is malformed, or
    /// [`SealError::InvalidMlKem`] if the ML-KEM component is rejected.
    // kanon:ignore RUST/pub-visibility -- hazmat-only primitive surface (sphragis#23): reachable for KAT/conformance testing, feature-gated off the normal public API
    #[cfg(feature = "hazmat")]
    pub fn decapsulate(&self, ct: &[u8]) -> Result<SharedSecret, SealError> {
        self.decapsulate_impl(ct)
    }

    #[expect(
        clippy::similar_names,
        reason = "ss_m/ss_x/ct_x/sk_x/pk_x mirror the X-Wing spec notation; spec-faithful names beat the similar_names heuristic (upstream does the same)"
    )]
    fn decapsulate_impl(&self, ct: &[u8]) -> Result<SharedSecret, SealError> {
        ensure!(
            ct.len() == CIPHERTEXT_LEN,
            WrongLengthSnafu {
                what: "ciphertext",
                expected: CIPHERTEXT_LEN,
                actual: ct.len(),
            }
        );
        let (ct_m_bytes, ct_x_bytes) = ct.split_at(ML_KEM_CT_LEN);

        // WHY: all fallible parsing precedes decapsulation so no early return
        // can exist while a shared secret is live on the stack.
        let ct_m: MlKemCiphertext<MlKem768> = Array::try_from(ct_m_bytes).map_err(|_| {
            InvalidMlKemSnafu {
                reason: "ciphertext length".to_string(),
            }
            .build()
        })?;
        let ct_x = x_public_from_slice(ct_x_bytes)?;

        let (dk_m, sk_x) = expand(&self.seed);
        let pk_x = XPublic::from(&sk_x);

        // ML-KEM decapsulation is infallible (implicit rejection on bad ct).
        let ss_m = Zeroizing::new(dk_m.decapsulate(&ct_m));
        let ss_x = sk_x.diffie_hellman(&ct_x);

        Ok(combine(
            ss_m.as_slice(),
            ss_x.as_bytes(),
            ct_x.as_bytes(),
            pk_x.as_bytes(),
        ))
    }
}

impl EncapsulationKey {
    /// Encapsulates to this public key, returning `(ciphertext, shared_secret)`.
    ///
    /// HAZMAT: reachable only with the `hazmat` feature, for known-answer
    /// testing only — no stability promise. A normal consumer calls
    /// [`crate::seal::seal_for`] instead: it does not route through this
    /// fixed-OsRng convenience wrapper, since [`crate::seal::seal_for_with_rng`]
    /// is itself generic over the RNG and calls
    /// [`encapsulate_with_rng`](Self::encapsulate_with_rng) directly — so
    /// without `hazmat` this method would have no caller in the crate at all
    /// (`dead_code`, denied under `-D warnings`) and is not compiled.
    ///
    /// Uses the OS CSPRNG. Ciphertext wire form is `ML-KEM ct || X25519 ct`.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Entropy`] if the OS entropy source fails, or
    /// [`SealError::WrongLength`] if the ML-KEM message seed cannot be formed
    /// from the sampled randomness (unreachable for a well-formed 64-byte
    /// buffer; propagated rather than silently defaulted).
    // kanon:ignore RUST/pub-visibility -- hazmat-only primitive surface (sphragis#23): reachable for KAT/conformance testing, feature-gated off the normal public API
    #[cfg(feature = "hazmat")]
    pub fn encapsulate(&self) -> Result<(Vec<u8>, SharedSecret), SealError> {
        self.encapsulate_with_rng(&mut OsRng)
    }

    /// Encapsulates to this public key using the given CSPRNG.
    ///
    /// Internal: no envelope-level equivalent exists — an injectable RNG is
    /// a primitive/conformance-testing affordance (proves the entropy-typed
    /// error path, sphragis#16), not something a normal consumer needs;
    /// [`crate::seal::seal_for`] always draws fresh OS randomness. WHY: see
    /// [`HybridKem::generate_with_rng`] — same injectable-entropy seam, so a
    /// failing `rng` proves this call site returns [`SealError::Entropy`]
    /// rather than panicking.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Entropy`] if `rng` fails, or
    /// [`SealError::WrongLength`] per [`Self::encapsulate_deterministic`].
    #[cfg(not(feature = "hazmat"))]
    pub(crate) fn encapsulate_with_rng<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret), SealError> {
        self.encapsulate_with_rng_impl(rng)
    }

    /// Encapsulates to this public key using the given CSPRNG.
    ///
    /// HAZMAT: reachable only with the `hazmat` feature — no stability
    /// promise. See [`HybridKem::generate_with_rng`] for the entropy-source
    /// rationale; `tests/entropy_failure.rs` is the consumer (sphragis#16).
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Entropy`] if `rng` fails, or
    /// [`SealError::WrongLength`] per [`Self::encapsulate_deterministic`].
    // kanon:ignore RUST/pub-visibility -- hazmat-only primitive surface (sphragis#23): reachable for KAT/conformance testing, feature-gated off the normal public API
    #[cfg(feature = "hazmat")]
    pub fn encapsulate_with_rng<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret), SealError> {
        self.encapsulate_with_rng_impl(rng)
    }

    fn encapsulate_with_rng_impl<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Vec<u8>, SharedSecret), SealError> {
        let mut randomness = Zeroizing::new([0u8; 64]);
        rng.try_fill_bytes(randomness.as_mut_slice())
            .context(EntropySnafu)?;
        self.encapsulate_deterministic(&randomness)
    }

    /// Deterministic encapsulation from 64 bytes of randomness (first 32 → ML-KEM
    /// message, last 32 → X25519 ephemeral).
    ///
    /// INVARIANT: private by construction. Deterministic KEM encapsulation
    /// with caller-supplied randomness is a known-answer-test affordance: on
    /// reused or non-uniform input it deterministically collapses the
    /// ephemeral X25519 secret, the ML-KEM coins, the ciphertext, and the
    /// shared secret — the exact failure [`encapsulate`](Self::encapsulate)
    /// exists to make impossible. It stays a private inherent method rather
    /// than gaining a `cfg(test)` gate because [`encapsulate`] itself calls
    /// straight through to it in every build (with fresh `OsRng` bytes), so
    /// the method must compile unconditionally; privacy alone already keeps
    /// it unreachable from any downstream crate. The known-answer test that
    /// exercises this method directly with the published draft vector lives
    /// beside it, in this module's own `#[cfg(test)] mod tests` below — a
    /// `tests/` integration file compiles as a separate crate and cannot
    /// name a private item.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::WrongLength`] if the ML-KEM message seed cannot be
    /// formed from `randomness` (unreachable for a `[u8; 64]` input; propagated
    /// per the crate's no-silent-fallback discipline).
    fn encapsulate_deterministic(
        &self,
        randomness: &[u8; 64],
    ) -> Result<(Vec<u8>, SharedSecret), SealError> {
        let (m_bytes, x_bytes) = randomness.split_at(32);
        let m: Zeroizing<B32> = Zeroizing::new(Array::try_from(m_bytes).map_err(|_| {
            WrongLengthSnafu {
                what: "ml-kem message seed",
                expected: 32_usize,
                actual: m_bytes.len(),
            }
            .build()
        })?);
        // ML-KEM deterministic encapsulation is infallible.
        let (ct_m, ss_m) = self.ek_m.encapsulate_deterministic(&m);
        let ss_m = Zeroizing::new(ss_m);

        let mut eph: [u8; 32] = x_bytes.try_into().map_err(|_| {
            WrongLengthSnafu {
                what: "x25519 ephemeral seed",
                expected: 32_usize,
                actual: x_bytes.len(),
            }
            .build()
        })?;
        let eph_x = XSecret::from(eph);
        eph.zeroize();
        let ct_x = XPublic::from(&eph_x);
        let ss_x = eph_x.diffie_hellman(&self.pk_x);

        let ss = combine(
            ss_m.as_slice(),
            ss_x.as_bytes(),
            ct_x.as_bytes(),
            self.pk_x.as_bytes(),
        );

        let mut ct = Vec::with_capacity(CIPHERTEXT_LEN);
        ct.extend_from_slice(ct_m.as_slice());
        ct.extend_from_slice(ct_x.as_bytes());
        Ok((ct, ss))
    }

    /// Serializes to `ML-KEM ek (1184) || X25519 pk (32)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENCAPSULATION_KEY_LEN);
        out.extend_from_slice(self.ek_m.to_bytes().as_slice());
        out.extend_from_slice(self.pk_x.as_bytes());
        out
    }

    /// Deserializes an encapsulation key from its wire form.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::WrongLength`] / [`SealError::InvalidMlKem`] on
    /// malformed input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SealError> {
        ensure!(
            bytes.len() == ENCAPSULATION_KEY_LEN,
            WrongLengthSnafu {
                what: "encapsulation key",
                expected: ENCAPSULATION_KEY_LEN,
                actual: bytes.len(),
            }
        );
        let (m_bytes, x_bytes) = bytes.split_at(ML_KEM_EK_LEN);
        let key: Key<MlKemEk> = Array::try_from(m_bytes).map_err(|_| {
            InvalidMlKemSnafu {
                reason: "encapsulation key length".to_string(),
            }
            .build()
        })?;
        let ek_m = MlKemEk::new(&key).map_err(|_| {
            InvalidMlKemSnafu {
                reason: "encapsulation key decode".to_string(),
            }
            .build()
        })?;
        let pk_x = x_public_from_slice(x_bytes)?;
        Ok(Self { ek_m, pk_x })
    }
}

/// Expands the 32-byte X-Wing seed into the ML-KEM decapsulation key and X25519
/// secret via SHAKE-256 (per the X-Wing spec): 64 bytes → ML-KEM seed,
/// 32 bytes → X25519 secret scalar.
// NOTE: hasher + XOF-reader state absorb seed-derived material; sha3's
// `zeroize` feature wipes both on drop.
fn expand(seed: &[u8; DECAPSULATION_KEY_LEN]) -> (MlKemDk, XSecret) {
    let mut shaker = Shake256::default();
    shaker.update(seed);
    let mut xof = shaker.finalize_xof();

    // WHY: the XOF writes directly into a Zeroizing buffer; the only bare copy
    // is the rvalue moved into `from_seed` (ml-kem's `zeroize` feature owns it
    // from there).
    let mut mlkem_seed: Zeroizing<Seed> = Zeroizing::new(Array::default());
    xof.read(mlkem_seed.as_mut_slice());
    let dk_m = MlKemDk::from_seed(Seed::clone(&mlkem_seed));

    let mut x_sk = [0u8; 32];
    xof.read(&mut x_sk);
    let sk_x = XSecret::from(x_sk);
    x_sk.zeroize();

    (dk_m, sk_x)
}

/// The X-Wing combiner: `SHA3-256(ss_M || ss_X || ct_X || pk_X || label)`.
fn combine(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> SharedSecret {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, X_WING_LABEL);
    SharedSecret(Zeroizing::new(h.finalize().into()))
}

fn x_public_from_slice(bytes: &[u8]) -> Result<XPublic, SealError> {
    let arr: [u8; X25519_LEN] = bytes.try_into().map_err(|_| {
        WrongLengthSnafu {
            what: "x25519 point",
            expected: X25519_LEN,
            actual: bytes.len(),
        }
        .build()
    })?;
    Ok(XPublic::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a vendored vector fixture (`tests/vectors/<name>`) as JSON.
    ///
    /// `crypto-provenance.toml` records this file's provenance and hash;
    /// `tests/provenance_lock.rs` checks the hash. Reading it here rather
    /// than re-typing its fields as a parallel set of hex literals means the
    /// executed assertion and the hash-locked file can never silently
    /// desync.
    #[expect(
        clippy::unwrap_used,
        reason = "KAT harness: this repo's own vendored, hash-locked vector fixture; a failed read/parse IS the test failure"
    )]
    fn vector_json(name: &str) -> serde_json::Value {
        let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
        let raw = std::fs::read_to_string(&path).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[expect(
        clippy::unwrap_used,
        reason = "KAT harness: inputs are fixed known-answer vectors; a failed unwrap IS the test failure"
    )]
    fn hex_field(v: &serde_json::Value, field: &str) -> Vec<u8> {
        hex::decode(v[field].as_str().unwrap()).unwrap()
    }

    /// X-Wing draft known-answer vector (`crypto-provenance.toml`:
    /// xwing-kat-0; draft-connolly-cfrg-xwing-kem). `seed` -> keypair;
    /// `eseed` -> deterministic encapsulation. Only this crate's own test
    /// build can name `encapsulate_deterministic` — see its doc comment
    /// above.
    #[test]
    #[expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::similar_names,
        reason = "KAT harness: inputs are fixed known-answer vectors, a failed unwrap or out-of-bounds index IS the test failure; expected_sk/pk/ct/ss mirror the vendored vector's own field names (sk/pk/ct/ss), which mirror the X-Wing spec notation; spec-faithful names beat the similar_names heuristic"
    )]
    fn deterministic_encapsulate_reproduces_xwing_draft_kat() {
        let doc = vector_json("xwing-draft-connolly-test-vectors.json");
        let v = &doc[0];
        let seed: [u8; DECAPSULATION_KEY_LEN] = hex_field(v, "seed").try_into().unwrap();
        let eseed: [u8; 64] = hex_field(v, "eseed").try_into().unwrap();
        let expected_sk = hex_field(v, "sk");
        let expected_pk = hex_field(v, "pk");
        let expected_ct = hex_field(v, "ct");
        let expected_ss = hex_field(v, "ss");

        let dk = DecapsulationKey::from_seed(seed);
        assert_eq!(
            dk.to_seed().as_slice(),
            expected_sk.as_slice(),
            "to_seed must export exactly the seed the key was built from"
        );
        let ek = dk.encapsulation_key();
        assert_eq!(
            ek.to_bytes(),
            expected_pk,
            "X-Wing keygen must reproduce the draft KAT encapsulation key"
        );

        let (ct, ss_send) = ek.encapsulate_deterministic(&eseed).unwrap();
        assert_eq!(
            ct, expected_ct,
            "X-Wing deterministic encaps must reproduce the draft KAT ciphertext"
        );
        assert_eq!(
            ss_send.as_slice(),
            expected_ss.as_slice(),
            "X-Wing deterministic encaps must reproduce the draft KAT shared secret"
        );

        let ss_recv = dk.decapsulate(&ct).unwrap();
        assert_eq!(
            ss_recv.as_slice(),
            expected_ss.as_slice(),
            "X-Wing decaps must recover the draft KAT shared secret"
        );
    }
}
