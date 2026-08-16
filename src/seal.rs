//! Multi-recipient content-key sealing.
//!
//! Wraps one content key separately for each recipient device. This module
//! only distributes keys — it has no memory of who has ever recovered one,
//! so re-sealing for a smaller recipient set removes a recipient from the
//! *next* wrap set without touching what a recipient who already unsealed
//! the key still holds. That is not revocation (sphragis#14); the typed
//! protocol that actually is lives in [`crate::rotate`].

use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, ensure};
use zeroize::Zeroizing;

use crate::envelope::{NONCE_LEN, TAG_LEN, derive_wrap_key, open, seal};
use crate::error::{
    EntropySnafu, EnvelopeTooLargeSnafu, SealError, SerializationSnafu, TrailingDataSnafu,
    UnsupportedVersionSnafu, WrongLengthSnafu,
};
use crate::hybrid::{CIPHERTEXT_LEN, DecapsulationKey, EncapsulationKey, HybridKem};
use crate::{SEAL_VERSION_V1, WRAP_DOMAIN_V1};

/// Content-key length (the symmetric key the consuming store uses for payloads).
pub const CONTENT_KEY_LEN: usize = 32; // kanon:ignore RUST/pub-visibility -- re-exported in lib.rs

/// Upper bound on the byte length of any RFC 8949 CBOR "argument": the
/// initial byte, plus at most the 8 extension bytes additional-info 27 (a
/// 64-bit-wide argument) demands. This bounds the header of ANY value or
/// length a CBOR item can declare, so summing it once per header slot below
/// gives a provable upper bound on the wire size without needing to
/// reproduce the encoder's own minimal-encoding choice per field.
const CBOR_MAX_HEADER_LEN: usize = 1 + 8;

/// Wire field count on [`WrappedContentKey`] (one CBOR map pair per field).
const FIELD_COUNT: usize = 5;

/// Sum of the UTF-8 byte length of every field name, which is also its CBOR
/// map key under ciborium's default struct-as-map encoding (no
/// `#[serde(rename)]` is used anywhere on the struct). WHY: the struct's
/// field names ARE the wire keys, so this is a literal copy that must stay
/// in sync by hand if a field is ever renamed —
/// `max_envelope_size_covers_worst_case_encoding` (in tests, below) fails
/// closed rather than silently under-bounding if it drifts.
const KEY_BYTES_TOTAL: usize = "version".len()
    + "recipient_id".len()
    + "kem_ciphertext".len()
    + "aead_nonce".len()
    + "sealed_key".len();

/// Sum of the raw payload bytes every field's value carries beyond its own
/// header: `version` is a bare integer with no payload beyond its header;
/// `recipient_id` and `aead_nonce` are fixed-size byte strings; `kem_ciphertext`
/// and `sealed_key` are the KEM/AEAD wire-length constants.
const VALUE_BYTES_TOTAL: usize = 32 + CIPHERTEXT_LEN + NONCE_LEN + (CONTENT_KEY_LEN + TAG_LEN);

/// Upper bound on the CBOR-encoded size of a v1 [`WrappedContentKey`],
/// derived from the wire-format field lengths (RFC 8949 §3) rather than
/// hardcoded: one map header, plus a key header and a value header per
/// field, plus every field's own bytes. [`WrappedContentKey::from_cbor`]
/// rejects any input larger than this *before* deserializing, so a
/// declared-but-absent length inside a small input cannot drive allocation
/// past what a genuine encoder could ever produce.
const MAX_ENVELOPE_SIZE: usize =
    CBOR_MAX_HEADER_LEN * (1 + 2 * FIELD_COUNT) + KEY_BYTES_TOTAL + VALUE_BYTES_TOTAL;

/// A recipient identifier: BLAKE3 of the recipient's X-Wing encapsulation key.
///
/// Stable, public, and collision-resistant; used to select the right
/// [`WrappedContentKey`] for a device and bound as AEAD associated data.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientId(#[serde(with = "serde_bytes")] pub [u8; 32]);

impl RecipientId {
    /// Computes the id for an encapsulation key.
    ///
    /// WHY: thin on purpose — BLAKE3-hashing the encapsulation key's wire
    /// bytes is the entire identity computation; a deeper interface here
    /// would rename this one call, not add behavior.
    #[must_use]
    pub fn of(ek: &EncapsulationKey) -> Self {
        Self(blake3::hash(&ek.to_bytes()).into())
    }
}

impl core::fmt::Debug for RecipientId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RecipientId({})", blake3::Hash::from(self.0).to_hex())
    }
}

/// A content key wrapped for exactly one recipient device.
///
/// Wire form (CBOR). `version` gates the construction; decoders reject unknown
/// versions. The recipient id and version are bound as AEAD associated data, so
/// a wrap for one device cannot be replayed against another.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedContentKey {
    /// Construction version (1 = X-Wing + HKDF-SHA256 + ChaCha20-Poly1305).
    pub version: u8,
    /// Which device this wrap is for.
    pub recipient_id: RecipientId,
    /// X-Wing ciphertext (`ML-KEM ct || X25519 ct`). Length `CIPHERTEXT_LEN`.
    // WHY serde(with = "serde_bytes") on this field and the two below:
    // without it, serde deserializes a `Vec<u8>` as a generic CBOR sequence,
    // pre-allocating off the attacker-declared element count before reading
    // any elements (capped at 1 MiB by serde's own `size_hint::cautious`,
    // still a per-field amplification a few header bytes can trigger). The
    // `serde_bytes` byte-string path grows the buffer only as bytes are
    // actually read from the input, so allocation tracks real input size —
    // on top of, not instead of, the whole-envelope cap in `from_cbor`.
    #[serde(with = "serde_bytes")]
    pub kem_ciphertext: Vec<u8>,
    /// ChaCha20-Poly1305 nonce.
    #[serde(with = "serde_bytes")]
    pub aead_nonce: [u8; NONCE_LEN],
    /// Sealed content key: `ciphertext || tag` (48 bytes for a 32-byte key).
    #[serde(with = "serde_bytes")]
    pub sealed_key: Vec<u8>,
}

impl core::fmt::Debug for WrappedContentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WrappedContentKey")
            .field("version", &self.version)
            .field("recipient_id", &self.recipient_id)
            .finish_non_exhaustive()
    }
}

impl WrappedContentKey {
    /// Encodes to CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Serialization`] on encoding failure.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SealError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| {
            SerializationSnafu {
                reason: e.to_string(),
            }
            .build()
        })?;
        Ok(buf)
    }

    /// Decodes from CBOR and validates the v1 wire shape.
    ///
    /// Three checks bound the parse boundary before any field is trusted:
    /// the input is rejected outright above a maximum size derived from the
    /// wire-format field lengths (not a guess); the byte-blob
    /// fields decode through `serde_bytes` so their allocation tracks bytes
    /// actually read rather than an attacker-declared length; and the
    /// decoded value must consume every supplied byte — trailing data after
    /// one complete envelope is rejected rather than silently accepted,
    /// since letting two distinct byte strings decode to the same envelope
    /// is a malleability surface, not a convenience.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::EnvelopeTooLarge`] if `bytes` exceeds the
    /// derived maximum size of a v1 envelope, [`SealError::Serialization`]
    /// on decoding failure (including an unknown or duplicate CBOR map key,
    /// since the struct denies both), [`SealError::TrailingData`] if bytes
    /// remain after one complete envelope, [`SealError::UnsupportedVersion`]
    /// for an unknown version byte, or [`SealError::WrongLength`] if a
    /// variable-length field does not match the v1 construction.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, SealError> {
        ensure!(
            bytes.len() <= MAX_ENVELOPE_SIZE,
            EnvelopeTooLargeSnafu {
                size: bytes.len(),
                max: MAX_ENVELOPE_SIZE,
            }
        );

        // WHY: `&mut &[u8]` (rather than `bytes` directly) so the slice
        // advances past exactly the bytes ciborium consumed decoding the one
        // top-level value — `ciborium::from_reader` returns without an EOF
        // check of its own, so this is what makes the trailing-data check
        // below meaningful rather than a no-op.
        let mut remaining = bytes;
        let wck: Self = ciborium::from_reader(&mut remaining).map_err(|e| {
            SerializationSnafu {
                reason: e.to_string(),
            }
            .build()
        })?;
        ensure!(
            remaining.is_empty(),
            TrailingDataSnafu {
                trailing: remaining.len(),
            }
        );

        wck.validate()?;
        Ok(wck)
    }

    // WHY: content validation for fields the CBOR layer accepts structurally
    // but the v1 construction still constrains — the version tag, and the
    // two byte-blob fields whose `Vec<u8>` type does not itself pin an exact
    // length (unlike the fixed-size `recipient_id`/`aead_nonce` arrays).
    // Allocation-bounding and frame-exactness are handled earlier, in
    // `from_cbor`, before this ever runs.
    fn validate(&self) -> Result<(), SealError> {
        ensure!(
            self.version == SEAL_VERSION_V1,
            UnsupportedVersionSnafu {
                version: self.version,
            }
        );
        ensure!(
            self.kem_ciphertext.len() == CIPHERTEXT_LEN,
            WrongLengthSnafu {
                what: "kem ciphertext",
                expected: CIPHERTEXT_LEN,
                actual: self.kem_ciphertext.len(),
            }
        );
        ensure!(
            self.sealed_key.len() == CONTENT_KEY_LEN + TAG_LEN,
            WrongLengthSnafu {
                what: "sealed content key",
                expected: CONTENT_KEY_LEN + TAG_LEN,
                actual: self.sealed_key.len(),
            }
        );
        Ok(())
    }

    /// Associated data bound into the AEAD: `version || recipient_id`.
    // INVARIANT: the irrefutable array destructure splits the fixed-size
    // buffer at compile time - no runtime bounds check can fail.
    const fn aad(&self) -> [u8; 1 + 32] {
        let mut aad = [0u8; 1 + 32];
        let [version_byte, recipient_bytes @ ..] = &mut aad; // kanon:ignore RUST/indexing-slicing -- irrefutable pattern, not an index: destructures the fixed [u8; 33] at compile time
        *version_byte = self.version;
        *recipient_bytes = self.recipient_id.0;
        aad
    }
}

/// Generates a fresh recipient keypair.
///
/// Returns an [`EncapsulationKey`] (public — publish it so others can seal
/// to this device) and a [`DecapsulationKey`] (secret — persist it via
/// [`DecapsulationKey::to_seed`]).
///
/// This is the versioned Sphragis operation for device-key creation. It is
/// the only supported way to obtain a keypair for [`seal_for`]/[`unseal`]:
/// the underlying hybrid-KEM primitive (`HybridKem`) is not part of the
/// normal public API (sphragis#23) — see `DECISION.md` for the
/// envelope-vs-primitive boundary and the upstream-adapter seam this exists
/// to keep stable across a future primitive-provider swap.
///
/// WHY: thin on purpose — this is exactly `HybridKem::generate` renamed
/// to the envelope-profile vocabulary; the indirection is the entire
/// point (sphragis#23's stable-name boundary over a primitive that may be
/// swapped for an upstream crate later), not a missing behavior.
///
/// # Errors
///
/// Returns [`SealError::Entropy`] if the OS entropy source fails.
// kanon:ignore RUST/pub-visibility -- re-exported in lib.rs
pub fn generate_recipient_keypair() -> Result<(DecapsulationKey, EncapsulationKey), SealError> {
    HybridKem::generate()
}

/// Seals a content key for each recipient device.
///
/// Returns one [`WrappedContentKey`] per recipient; all unseal to the same
/// `content_key`. The order of the output matches `recipients`.
///
/// WHY: thin on purpose — fixes the RNG to `OsRng`, mirroring
/// `HybridKem::generate`'s own OS-vs-injectable split;
/// `seal_for_with_rng`'s doc comment carries the injectable-entropy
/// rationale for the one caller (tests) that needs a
/// deterministically-failing source.
///
/// # Errors
///
/// Returns a [`SealError`] if entropy generation, encapsulation, HKDF, or the
/// AEAD seal fails for any recipient.
// kanon:ignore RUST/pub-visibility -- re-exported in lib.rs
pub fn seal_for(
    content_key: &[u8; CONTENT_KEY_LEN],
    recipients: &[EncapsulationKey],
) -> Result<Vec<WrappedContentKey>, SealError> {
    seal_for_with_rng(content_key, recipients, &mut OsRng)
}

// kanon:ignore RUST/pub-visibility -- re-exported in lib.rs (forkwright/kanon#2382)
/// Seals a content key for each recipient device using the given CSPRNG.
///
/// WHY: isolates both entropy draws (KEM encapsulation + AEAD nonce) per
/// recipient behind one injectable seam, so a partial-batch RNG failure
/// returns no partial wrap set (the early `?` drops `out` before
/// returning). Time: O(n), Space: O(n) — n = `recipients.len()`.
///
/// # Errors
///
/// Returns a [`SealError`] if entropy, encapsulation, HKDF, or AEAD fails.
pub fn seal_for_with_rng<R: RngCore + CryptoRng>(
    content_key: &[u8; CONTENT_KEY_LEN],
    recipients: &[EncapsulationKey],
    rng: &mut R,
) -> Result<Vec<WrappedContentKey>, SealError> {
    let mut out = Vec::with_capacity(recipients.len());
    for ek in recipients {
        let recipient_id = RecipientId::of(ek);
        let (kem_ciphertext, ss) = ek.encapsulate_with_rng(rng)?;

        let wrap_key = derive_wrap_key(ss.as_slice(), WRAP_DOMAIN_V1)?;

        let mut nonce = [0u8; NONCE_LEN];
        rng.try_fill_bytes(&mut nonce).context(EntropySnafu)?;

        let mut wck = WrappedContentKey {
            version: SEAL_VERSION_V1,
            recipient_id,
            kem_ciphertext,
            aead_nonce: nonce,
            sealed_key: Vec::new(),
        };
        wck.sealed_key = seal(&wrap_key, &nonce, content_key, &wck.aad())?;
        out.push(wck);
    }
    Ok(out)
}

/// Unseals a wrapped content key with this device's decapsulation key.
///
/// # Errors
///
/// Returns [`SealError::UnsupportedVersion`] for an unknown version,
/// [`SealError::AeadOpen`] for the wrong recipient / tampered ciphertext, or a
/// KEM error for a corrupted ciphertext.
// kanon:ignore RUST/pub-visibility -- re-exported in lib.rs
pub fn unseal(
    dk: &DecapsulationKey,
    wck: &WrappedContentKey,
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    if wck.version != SEAL_VERSION_V1 {
        return UnsupportedVersionSnafu {
            version: wck.version,
        }
        .fail();
    }
    let ss = dk.decapsulate(&wck.kem_ciphertext)?;
    let wrap_key = derive_wrap_key(ss.as_slice(), WRAP_DOMAIN_V1)?;
    open(&wrap_key, &wck.aead_nonce, &wck.sealed_key, &wck.aad())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "unit test: a failed unwrap on our own encoder's output IS the test failure"
)]
mod tests {
    use super::{
        CIPHERTEXT_LEN, CONTENT_KEY_LEN, MAX_ENVELOPE_SIZE, NONCE_LEN, RecipientId, TAG_LEN,
        WrappedContentKey,
    };

    /// [`MAX_ENVELOPE_SIZE`] is derived (RFC 8949 §3 header-size arithmetic),
    /// not measured — this is the proof that the derivation actually bounds
    /// what the crate's own encoder produces. A worst-case-shaped v1
    /// envelope (every byte-blob field at its real wire length; `version`
    /// at 0xFF, the one field whose CBOR header size still varies with its
    /// value) must encode at or under the bound, or `from_cbor` would reject
    /// genuine output from `to_cbor`.
    #[test]
    fn max_envelope_size_covers_worst_case_encoding() {
        let worst_case = WrappedContentKey {
            version: 0xFF,
            recipient_id: RecipientId([0xFF; 32]),
            kem_ciphertext: vec![0xFF; CIPHERTEXT_LEN],
            aead_nonce: [0xFF; NONCE_LEN],
            sealed_key: vec![0xFF; CONTENT_KEY_LEN + TAG_LEN],
        };
        let encoded = worst_case.to_cbor().unwrap();
        assert!(
            encoded.len() <= MAX_ENVELOPE_SIZE,
            "worst-case v1 envelope encoded to {} bytes, exceeding the derived {MAX_ENVELOPE_SIZE}-byte bound",
            encoded.len()
        );
    }
}
