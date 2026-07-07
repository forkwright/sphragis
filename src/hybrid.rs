//! X-Wing hybrid KEM (X25519 + ML-KEM-768).
//!
//! Faithful transcription of `draft-connolly-cfrg-xwing-kem` over the released
//! `RustCrypto` primitives (`ml-kem` 0.3, `x25519-dalek` 2, `sha3` 0.10). The
//! combiner binds the ML-KEM shared secret (first, per FIPS SP 800-56C ordering),
//! the X25519 shared secret, the X25519 ciphertext, and the recipient X25519
//! public key, under the X-Wing domain label.
//!
//! WARNING: unaudited. Validated against the X-Wing draft known-answer vectors.

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Key, KeyExport};
use ml_kem::{Ciphertext as MlKemCiphertext, MlKem768, Seed, B32};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, Zeroizing};

use rand_core::{OsRng, RngCore};
use snafu::ensure;

use crate::error::{SealError, WrongLengthSnafu};

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
pub const SHARED_SECRET_LEN: usize = 32; // kanon:ignore RUST/pub-visibility -- public constant in the SharedSecret alias

/// A hybrid shared secret. Zeroized on drop.
pub type SharedSecret = Zeroizing<[u8; SHARED_SECRET_LEN]>; // kanon:ignore RUST/pub-visibility -- re-exported in lib.rs

type MlKemDk = ml_kem::DecapsulationKey<MlKem768>;
type MlKemEk = ml_kem::EncapsulationKey<MlKem768>;

/// The X-Wing hybrid KEM over X25519 + ML-KEM-768.
#[derive(Clone, Copy, Debug)]
pub struct HybridKem;

/// X-Wing public (encapsulation) key.
///
/// Public data: freely serializable and shareable. Wire form is
/// `ML-KEM-768 ek (1184) || X25519 pk (32)`.
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
    // WHY: the seed is born inside Zeroizing so no bare stack copy ever exists.
    #[must_use]
    pub fn generate() -> (DecapsulationKey, EncapsulationKey) {
        let mut seed = Zeroizing::new([0u8; DECAPSULATION_KEY_LEN]);
        OsRng.fill_bytes(seed.as_mut_slice());
        let dk = DecapsulationKey { seed };
        let ek = dk.encapsulation_key();
        (dk, ek)
    }
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
    #[must_use]
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        let (dk_m, sk_x) = expand(&self.seed);
        let ek_m = dk_m.encapsulation_key().clone();
        let pk_x = XPublic::from(&sk_x);
        EncapsulationKey { ek_m, pk_x }
    }

    /// Decapsulates a ciphertext to recover the hybrid shared secret.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::WrongLength`] if the ciphertext is malformed, or
    /// [`SealError::InvalidMlKem`] if the ML-KEM component is rejected.
    #[expect(
        clippy::similar_names,
        reason = "ss_m/ss_x/ct_x/sk_x/pk_x mirror the X-Wing spec notation; spec-faithful names beat the similar_names heuristic (upstream does the same)"
    )]
    pub fn decapsulate(&self, ct: &[u8]) -> Result<SharedSecret, SealError> {
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
        let ct_m: MlKemCiphertext<MlKem768> =
            Array::try_from(ct_m_bytes).map_err(|_| SealError::InvalidMlKem {
                reason: "ciphertext length".into(),
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
    /// Uses the OS CSPRNG. Ciphertext wire form is `ML-KEM ct || X25519 ct`.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::WrongLength`] if the ML-KEM message seed cannot be
    /// formed from the sampled randomness (unreachable for a well-formed
    /// 64-byte buffer; propagated rather than silently defaulted).
    pub fn encapsulate(&self) -> Result<(Vec<u8>, SharedSecret), SealError> {
        let mut rnd = Zeroizing::new([0u8; 64]);
        OsRng.fill_bytes(rnd.as_mut_slice());
        self.encapsulate_deterministic(&rnd)
    }

    /// Deterministic encapsulation from 64 bytes of randomness (first 32 → ML-KEM
    /// message, last 32 → X25519 ephemeral). For known-answer testing only.
    ///
    /// WARNING: never call with non-uniform or reused randomness.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::WrongLength`] if the ML-KEM message seed cannot be
    /// formed from `randomness` (unreachable for a `[u8; 64]` input; propagated
    /// per the crate's no-silent-fallback discipline).
    #[doc(hidden)]
    pub fn encapsulate_deterministic(
        &self,
        randomness: &[u8; 64],
    ) -> Result<(Vec<u8>, SharedSecret), SealError> {
        let (m_bytes, x_bytes) = randomness.split_at(32);
        let m: Zeroizing<B32> =
            Zeroizing::new(
                Array::try_from(m_bytes).map_err(|_| SealError::WrongLength {
                    what: "ml-kem message seed",
                    expected: 32,
                    actual: m_bytes.len(),
                })?,
            );
        // ML-KEM deterministic encapsulation is infallible.
        let (ct_m, ss_m) = self.ek_m.encapsulate_deterministic(&m);
        let ss_m = Zeroizing::new(ss_m);

        let mut eph: [u8; 32] = x_bytes.try_into().map_err(|_| SealError::WrongLength {
            what: "x25519 ephemeral seed",
            expected: 32,
            actual: x_bytes.len(),
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
        let key: Key<MlKemEk> = Array::try_from(m_bytes).map_err(|_| SealError::InvalidMlKem {
            reason: "encapsulation key length".into(),
        })?;
        let ek_m = MlKemEk::new(&key).map_err(|_| SealError::InvalidMlKem {
            reason: "encapsulation key decode".into(),
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
    Zeroizing::new(h.finalize().into())
}

fn x_public_from_slice(bytes: &[u8]) -> Result<XPublic, SealError> {
    let arr: [u8; X25519_LEN] = bytes.try_into().map_err(|_| SealError::WrongLength {
        what: "x25519 point",
        expected: X25519_LEN,
        actual: bytes.len(),
    })?;
    Ok(XPublic::from(arr))
}
