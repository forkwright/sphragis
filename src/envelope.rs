//! Content-key envelope: HKDF-SHA256 expansion + ChaCha20-Poly1305 sealing.
//!
//! The X-Wing shared secret is expanded under a versioned domain tag into a
//! 32-byte wrapping key, which seals the content key with ChaCha20-Poly1305. The
//! recipient id and version are bound as AEAD associated data.
//!
//! Digest-state hygiene: sha2 0.11's `zeroize` feature wipes the HMAC-keyed
//! Sha256 cores and block buffers on drop (mirroring the sha3 0.11 property in
//! `hybrid`), so the shared-secret-derived state inside the HKDF stack does not
//! outlive the derivation.
//!
//! INVARIANT: this module is the primitive side of the envelope seam
//! (sphragis#23) — `derive_wrap_key` is reachable only under `hazmat`.
//! [`crate::seal::seal_for`]/[`crate::seal::unseal`] call the crate-private
//! path unconditionally; a normal consumer never derives a wrap key directly.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use snafu::ResultExt;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AeadOpenSnafu, AeadSealSnafu, HkdfExpandSnafu, SealError};

/// AEAD nonce length (ChaCha20-Poly1305).
pub(crate) const NONCE_LEN: usize = 12;
/// AEAD authentication-tag length (Poly1305).
pub(crate) const TAG_LEN: usize = 16;
/// Wrapping-key length derived from HKDF.
pub(crate) const WRAP_KEY_LEN: usize = 32;

/// `HKDF-SHA256(salt = 32 zero bytes, ikm = shared_secret, info = domain)`.
/// A null (zero-filled) salt is used per the PQXDH/SP 800-56C convention for a
/// uniformly-random IKM.
fn derive_wrap_key_impl(
    shared_secret: &[u8],
    domain: &[u8],
) -> Result<Zeroizing<[u8; WRAP_KEY_LEN]>, SealError> {
    let salt = [0u8; 32];
    // WHY: extract-then-wipe rather than `Hkdf::new` — `new()` discards its
    // PRK copy un-zeroized; the keyed state inside `hk` drop-zeroizes via the
    // sha2 0.11 `zeroize` feature.
    let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(&salt), shared_secret);
    prk.zeroize();
    let mut okm = Zeroizing::new([0u8; WRAP_KEY_LEN]);
    hk.expand(domain, okm.as_mut_slice())
        .context(HkdfExpandSnafu)?;
    Ok(okm)
}

/// Derives the 32-byte wrapping key from a hybrid shared secret.
///
/// Internal: [`seal_for`](crate::seal::seal_for)/[`unseal`](crate::seal::unseal)
/// are the stable entry points a normal consumer calls instead.
///
/// # Errors
///
/// Returns [`SealError::HkdfExpand`] if expansion fails (cannot occur for a
/// 32-byte output, but surfaced rather than panicking).
#[cfg(not(feature = "hazmat"))]
pub(crate) fn derive_wrap_key(
    shared_secret: &[u8],
    domain: &[u8],
) -> Result<Zeroizing<[u8; WRAP_KEY_LEN]>, SealError> {
    derive_wrap_key_impl(shared_secret, domain)
}

/// Derives the 32-byte wrapping key from a hybrid shared secret.
///
/// HAZMAT: primitive-level HKDF access, reachable only with the `hazmat`
/// feature, for RFC 5869 known-answer testing only — no stability promise.
/// A normal consumer calls
/// [`seal_for`](crate::seal::seal_for)/[`unseal`](crate::seal::unseal)
/// instead, which derive the wrap key internally.
///
/// # Errors
///
/// Returns [`SealError::HkdfExpand`] if expansion fails (cannot occur for a
/// 32-byte output, but surfaced rather than panicking).
// kanon:ignore RUST/pub-visibility -- hazmat-only primitive surface (sphragis#23): the RFC 5869 KAT gate consumes it externally, feature-gated off the normal public API
#[cfg(feature = "hazmat")]
pub fn derive_wrap_key(
    shared_secret: &[u8],
    domain: &[u8],
) -> Result<Zeroizing<[u8; WRAP_KEY_LEN]>, SealError> {
    derive_wrap_key_impl(shared_secret, domain)
}

/// Seals `content_key` under `wrap_key`, binding `aad`. Returns
/// `ciphertext || tag`.
///
/// # Errors
///
/// Returns [`SealError::AeadSeal`] if the AEAD operation fails.
pub(crate) fn seal(
    wrap_key: &[u8; WRAP_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    content_key: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SealError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(wrap_key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: content_key,
                aad,
            },
        )
        .context(AeadSealSnafu)
}

/// Opens a sealed content key produced by [`seal`].
///
/// # Errors
///
/// Returns [`SealError::AeadOpen`] on a wrong key, wrong recipient, tampered
/// ciphertext, or wrong associated data.
pub(crate) fn open(
    wrap_key: &[u8; WRAP_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    sealed: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(wrap_key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
        .map(Zeroizing::new)
        .context(AeadOpenSnafu)
}
