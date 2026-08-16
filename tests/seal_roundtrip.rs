//! Envelope-API acceptance gate for `sphragis` (preview-pq): proves the
//! `seal_for`/`unseal`/`WrappedContentKey` surface behaves correctly, as
//! distinct from `tests/known_answer_vectors.rs`'s external-standard
//! conformance (RUST/file-too-long split, forkwright/sphragis#37 — moved
//! verbatim with the API each test exercises, no test logic changed).
//!
//! Covers:
//! - Round-trip, multi-recipient, and recipient-omission behavior (the
//!   omission tests carry an explicit note that they are NOT revocation —
//!   see `tests/rotation.rs` for the actual adversarial revocation proof,
//!   sphragis#14).
//! - Negative tests: wrong recipient, wrong version, tampered ciphertext/key,
//!   AAD binding.
//! - Wire-format parse boundaries: oversized/lying-length/duplicate/unknown
//!   CBOR fields, trailing-data rejection.
//! - Key export (seed round-trip), wire round-trip, `Debug` redaction, and
//!   randomness-freshness across independent calls.

#![cfg(feature = "preview-pq")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "KAT harness: inputs are fixed known-answer vectors; a failed unwrap or out-of-bounds index IS the test failure"
)]

use sphragis::hybrid::{
    CIPHERTEXT_LEN, DecapsulationKey, ENCAPSULATION_KEY_LEN, EncapsulationKey, HybridKem,
};
use sphragis::seal::{CONTENT_KEY_LEN, RecipientId, WrappedContentKey, seal_for, unseal};
use sphragis::{SEAL_VERSION_V1, SealError};

// ---------------------------------------------------------------------------
// End-to-end sealing: round-trip, multi-recipient, revocation, negatives.
// ---------------------------------------------------------------------------

fn fresh() -> (DecapsulationKey, EncapsulationKey) {
    HybridKem::generate().unwrap()
}

/// A content key seals and unseals through a single recipient.
#[test]
fn seal_unseal_round_trip() {
    let (dk, ek) = fresh();
    let content_key = [0xACu8; CONTENT_KEY_LEN];

    let wrapped = seal_for(&content_key, &[ek]).unwrap();
    assert_eq!(wrapped.len(), 1);

    let recovered = unseal(&dk, &wrapped[0]).unwrap();
    assert_eq!(recovered.as_slice(), &content_key);
}

/// One content key wraps for several devices; each recovers the same key.
#[test]
fn multi_recipient_all_recover_same_key() {
    let (dk1, ek1) = fresh();
    let (dk2, ek2) = fresh();
    let (dk3, ek3) = fresh();
    let content_key = [0x11u8; CONTENT_KEY_LEN];

    let wrapped = seal_for(&content_key, &[ek1, ek2, ek3]).unwrap();
    assert_eq!(wrapped.len(), 3);

    assert_eq!(unseal(&dk1, &wrapped[0]).unwrap().as_slice(), &content_key);
    assert_eq!(unseal(&dk2, &wrapped[1]).unwrap().as_slice(), &content_key);
    assert_eq!(unseal(&dk3, &wrapped[2]).unwrap().as_slice(), &content_key);
}

/// Recipient omission: re-sealing for a smaller set excludes the omitted
/// device from the new wrap set. This is NOT revocation (sphragis#14) — it
/// proves only that device 2 has no wrap addressed to it here, not that
/// device 2 has lost the ability to decrypt anything. A device that never
/// held a content key in the first place was never going to keep it
/// either, so this test does not model a revoked device at all; see
/// `tests/rotation.rs::rotation_actually_revokes_a_device_that_held_the_old_key`
/// for the adversarial property a real revocation must satisfy.
#[test]
fn seal_for_omits_unlisted_recipient() {
    let (dk1, ek1) = fresh();
    let (dk2, ek2) = fresh();
    let content_key = [0x22u8; CONTENT_KEY_LEN];

    // Seal for device 1 only; device 2 is simply not in the recipient list.
    let wrapped = seal_for(&content_key, &[ek1]).unwrap();
    assert_eq!(wrapped.len(), 1);
    assert_eq!(unseal(&dk1, &wrapped[0]).unwrap().as_slice(), &content_key);

    // Device 2 has no wrap addressed to it.
    let _ = (dk2, ek2);
}

/// A wrap for one device cannot be opened by another (wrong recipient).
#[test]
fn wrong_recipient_fails() {
    let (_dk1, ek1) = fresh();
    let (dk2, _ek2) = fresh();
    let content_key = [0x33u8; CONTENT_KEY_LEN];

    let wrapped = seal_for(&content_key, &[ek1]).unwrap();
    assert!(
        unseal(&dk2, &wrapped[0]).is_err(),
        "a different device must not unseal another device's wrap"
    );
}

/// An unknown version is rejected, not reinterpreted.
#[test]
fn unsupported_version_rejected() {
    let (dk, ek) = fresh();
    let content_key = [0x44u8; CONTENT_KEY_LEN];
    let mut wrapped = seal_for(&content_key, &[ek]).unwrap()[0].clone();
    wrapped.version = SEAL_VERSION_V1 + 7;
    assert!(unseal(&dk, &wrapped).is_err(), "unknown version must fail");
}

/// A corrupted sealed key fails the AEAD tag check.
#[test]
fn tampered_sealed_key_fails() {
    let (dk, ek) = fresh();
    let content_key = [0x55u8; CONTENT_KEY_LEN];
    let mut wrapped = seal_for(&content_key, &[ek]).unwrap()[0].clone();
    let last = wrapped.sealed_key.len() - 1;
    wrapped.sealed_key[last] ^= 0xFF;
    assert!(
        unseal(&dk, &wrapped).is_err(),
        "tampered sealed key must fail the AEAD tag"
    );
}

/// A corrupted KEM ciphertext yields a different shared secret and fails open.
#[test]
fn corrupted_kem_ciphertext_fails() {
    let (dk, ek) = fresh();
    let content_key = [0x66u8; CONTENT_KEY_LEN];
    let mut wrapped = seal_for(&content_key, &[ek]).unwrap()[0].clone();
    wrapped.kem_ciphertext[0] ^= 0xFF;
    assert!(
        unseal(&dk, &wrapped).is_err(),
        "corrupted KEM ciphertext must not recover the content key"
    );
}

/// The wrapped key round-trips through CBOR.
#[test]
fn cbor_round_trip() {
    let (dk, ek) = fresh();
    let content_key = [0x77u8; CONTENT_KEY_LEN];
    let wrapped = seal_for(&content_key, &[ek]).unwrap();

    let bytes = wrapped[0].to_cbor().unwrap();
    let decoded = WrappedContentKey::from_cbor(&bytes).unwrap();
    assert_eq!(unseal(&dk, &decoded).unwrap().as_slice(), &content_key);
}

// ---------------------------------------------------------------------------
// Key export, wire serialization, randomness freshness, parse boundaries.
// ---------------------------------------------------------------------------

/// The seed export/persistence path: `to_seed` -> `from_seed` rebuilds a key
/// that derives the same public key and unseals wraps addressed to the original.
#[test]
fn to_seed_from_seed_round_trip() {
    let (dk, ek) = fresh();
    let content_key = [0x88u8; CONTENT_KEY_LEN];
    let wrapped = seal_for(&content_key, core::slice::from_ref(&ek)).unwrap();

    let restored = DecapsulationKey::from_seed(*dk.to_seed());
    assert_eq!(
        restored.encapsulation_key().to_bytes(),
        ek.to_bytes(),
        "a key rebuilt from the exported seed must derive the same public key"
    );
    assert_eq!(
        unseal(&restored, &wrapped[0]).unwrap().as_slice(),
        &content_key,
        "a key rebuilt from the exported seed must unseal existing wraps"
    );
}

/// The encapsulation key round-trips through its wire form and stays usable.
#[test]
fn encapsulation_key_wire_round_trip() {
    let (dk, ek) = fresh();
    let bytes = ek.to_bytes();
    assert_eq!(bytes.len(), ENCAPSULATION_KEY_LEN);

    let decoded = EncapsulationKey::from_bytes(&bytes).unwrap();
    assert_eq!(
        decoded.to_bytes(),
        bytes,
        "wire form must survive a decode/encode round trip byte-for-byte"
    );

    let (ct, ss_send) = decoded.encapsulate().unwrap();
    let ss_recv = dk.decapsulate(&ct).unwrap();
    assert_eq!(
        ss_send.as_slice(),
        ss_recv.as_slice(),
        "a deserialized encapsulation key must interoperate with the original dk"
    );
}

/// Wrong-length encapsulation-key and ciphertext inputs are rejected, and
/// the rejection carries the failing call site's location (sphragis#26).
// WHY matched on `&short_ek_result` rather than unwrapped/moved:
// `EncapsulationKey` is intentionally not `Debug` (it holds key-derived
// material), so `.unwrap_err()` does not compile here — same reasoning as
// `tests/entropy_failure.rs`'s `generate_with_rng_returns_entropy_error_not_panic`.
#[test]
#[expect(
    clippy::panic,
    reason = "test harness: an unmatched error variant IS the test failure, surfaced via panic! \
              the same way assert!/assert_eq! do internally (mirrors tests/entropy_failure.rs)"
)]
fn wrong_length_ek_and_ct_rejected() {
    let (dk, ek) = fresh();

    let ek_bytes = ek.to_bytes();
    let short_ek_result = EncapsulationKey::from_bytes(&ek_bytes[..ek_bytes.len() - 1]);
    assert!(EncapsulationKey::from_bytes(&[]).is_err());
    let mut long = ek.to_bytes();
    long.push(0);
    assert!(EncapsulationKey::from_bytes(&long).is_err());

    let (ct, _ss) = ek.encapsulate().unwrap();
    assert!(dk.decapsulate(&ct[..ct.len() - 1]).is_err());
    assert!(dk.decapsulate(&[]).is_err());
    assert!(dk.decapsulate(&[0u8; CIPHERTEXT_LEN - 1]).is_err());

    let Err(SealError::WrongLength { location, .. }) = &short_ek_result else {
        panic!("expected SealError::WrongLength");
    };
    assert!(
        location.file.ends_with("hybrid.rs"),
        "the implicit location must name the failing call site, got {}",
        location.file
    );
}

/// A `SharedSecret`'s `Debug` output redacts the secret: it must never
/// print the raw bytes, whether from a stray `tracing::debug!(?ss)`, a
/// leftover `dbg!(ss)`, or an error-context capture (sphragis#25).
#[test]
fn shared_secret_debug_is_redacted() {
    let (_dk, ek) = fresh();
    let (_ct, ss) = ek.encapsulate().unwrap();

    let formatted = format!("{ss:?}");
    let raw_hex = hex::encode(ss.as_slice());

    assert!(
        formatted.contains("REDACTED"),
        "SharedSecret's Debug output must carry a redaction marker, got {formatted:?}"
    );
    assert!(
        !formatted.contains(&raw_hex),
        "SharedSecret's Debug output must not contain the secret bytes, got {formatted:?}"
    );
}

/// Independent encapsulations to one key draw fresh randomness: no ciphertext
/// or shared-secret reuse.
#[test]
fn encapsulate_draws_fresh_randomness() {
    let (_dk, ek) = fresh();
    let (ct1, ss1) = ek.encapsulate().unwrap();
    let (ct2, ss2) = ek.encapsulate().unwrap();
    assert_ne!(ct1, ct2, "two encapsulations must not share a ciphertext");
    assert_ne!(
        ss1.as_slice(),
        ss2.as_slice(),
        "two encapsulations must not share a secret"
    );
}

/// Independent `seal_for` calls draw fresh nonces and KEM ciphertexts.
#[test]
fn seal_for_draws_fresh_randomness() {
    let (_dk, ek) = fresh();
    let content_key = [0x99u8; CONTENT_KEY_LEN];
    let first = seal_for(&content_key, core::slice::from_ref(&ek)).unwrap();
    let second = seal_for(&content_key, &[ek]).unwrap();
    let (a, b) = (&first[0], &second[0]);
    assert_ne!(a.aead_nonce, b.aead_nonce, "nonces must never repeat");
    assert_ne!(
        a.kem_ciphertext, b.kem_ciphertext,
        "KEM ciphertexts must never repeat"
    );
    assert_ne!(a.sealed_key, b.sealed_key, "sealed keys must never repeat");
}

/// The empty recipient list seals to an empty set — a structural property
/// of `seal_for`, not "full revocation": an empty wrap set says nothing
/// about whether a previously-provisioned recipient still holds a content
/// key from before this call (sphragis#14).
#[test]
fn seal_for_empty_recipients_is_empty() {
    let content_key = [0xAAu8; CONTENT_KEY_LEN];
    let wrapped = seal_for(&content_key, &[]).unwrap();
    assert!(
        wrapped.is_empty(),
        "an empty recipient list must produce zero wraps, not an error"
    );
}

/// The recipient id is bound as AEAD associated data: altering only the id —
/// KEM ciphertext, nonce, and keys untouched — must fail the open.
#[test]
fn recipient_id_aad_binding_isolated() {
    let (dk, ek) = fresh();
    let content_key = [0xBBu8; CONTENT_KEY_LEN];
    let mut wrapped = seal_for(&content_key, &[ek]).unwrap()[0].clone();
    wrapped.recipient_id = RecipientId([0x5Au8; 32]);
    assert!(
        unseal(&dk, &wrapped).is_err(),
        "a wrap replayed under a different recipient id must fail the AEAD open"
    );
}

/// `from_cbor` rejects an unbounded / oversized KEM ciphertext before it can
/// reach the KEM — and now, before it can even reach deserialization: a
/// 1 MiB `kem_ciphertext` blows the whole-envelope size cap, so the input is
/// turned away outright rather than allocated and then found wrong-length.
#[test]
fn from_cbor_rejects_oversized_kem_ciphertext() {
    let (_dk, ek) = fresh();
    let content_key = [0xCCu8; CONTENT_KEY_LEN];
    let mut wrapped = seal_for(&content_key, &[ek]).unwrap()[0].clone();
    wrapped.kem_ciphertext = vec![0u8; 1 << 20];
    let bytes = wrapped.to_cbor().unwrap();
    assert!(
        matches!(
            WrappedContentKey::from_cbor(&bytes),
            Err(SealError::EnvelopeTooLarge { .. })
        ),
        "an oversized envelope must be rejected by the size cap before deserializing"
    );
}

/// `from_cbor` rejects a wrong-length sealed key at the parse boundary.
#[test]
fn from_cbor_rejects_wrong_length_sealed_key() {
    let (_dk, ek) = fresh();
    let content_key = [0xDDu8; CONTENT_KEY_LEN];
    let mut wrapped = seal_for(&content_key, &[ek]).unwrap()[0].clone();
    wrapped.sealed_key.truncate(wrapped.sealed_key.len() - 1);
    let bytes = wrapped.to_cbor().unwrap();
    assert!(
        matches!(
            WrappedContentKey::from_cbor(&bytes),
            Err(SealError::WrongLength { .. })
        ),
        "a decoded sealed_key must be exactly content-key + tag length"
    );
}

/// `from_cbor` rejects an unknown version at the parse boundary.
#[test]
fn from_cbor_rejects_unknown_version() {
    let (_dk, ek) = fresh();
    let content_key = [0xEEu8; CONTENT_KEY_LEN];
    let mut wrapped = seal_for(&content_key, &[ek]).unwrap()[0].clone();
    wrapped.version = SEAL_VERSION_V1 + 1;
    let bytes = wrapped.to_cbor().unwrap();
    assert!(
        matches!(
            WrappedContentKey::from_cbor(&bytes),
            Err(SealError::UnsupportedVersion { .. })
        ),
        "an unknown version must be rejected at decode, not reinterpreted"
    );
}

/// `from_cbor` must require full consumption of the input after exactly one
/// top-level object. `ciborium::from_reader` returns as soon as it has
/// decoded one value and performs no EOF check of its own, so bytes
/// appended after a complete, valid envelope must not be silently accepted
/// — two distinct byte strings decoding to the same envelope is a
/// malleability surface for anything that treats the sealed bytes as
/// canonical (framing, signatures, hashes, concatenated records).
#[test]
fn from_cbor_rejects_trailing_bytes() {
    let (_dk, ek) = fresh();
    let content_key = [0x15u8; CONTENT_KEY_LEN];
    let mut bytes = seal_for(&content_key, &[ek]).unwrap()[0].to_cbor().unwrap();
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(
        matches!(
            WrappedContentKey::from_cbor(&bytes),
            Err(SealError::TrailingData { .. })
        ),
        "four trailing bytes after a complete, valid envelope must be rejected, not silently accepted"
    );
}

/// Appending a single extra byte — of any value — to a complete, valid
/// envelope must always be rejected. Proptest coverage of the malleability
/// property `from_cbor_rejects_trailing_bytes` demonstrates for one fixed
/// byte sequence.
#[test]
fn from_cbor_rejects_any_appended_byte() {
    let (_dk, ek) = fresh();
    let content_key = [0x16u8; CONTENT_KEY_LEN];
    let valid = seal_for(&content_key, &[ek]).unwrap()[0].to_cbor().unwrap();
    proptest::proptest!(|(extra in 0u8..=255u8)| {
        let mut tampered = valid.clone();
        tampered.push(extra);
        proptest::prop_assert!(
            WrappedContentKey::from_cbor(&tampered).is_err(),
            "appending byte {extra:#04x} to a complete, valid envelope must be rejected"
        );
    });
}

/// Locates the `kem_ciphertext` map key inside a real `to_cbor()` output and
/// returns everything up to and including that key's own bytes, so a test
/// can splice in a hand-crafted (malformed) value for exactly that field.
/// Field order is struct declaration order (ciborium encodes a struct as a
/// CBOR map in field order — verified against `ciborium` 0.2.2
/// `src/ser/mod.rs`'s `SerializeStruct::serialize_field`), so this key
/// always follows `version` and `recipient_id` in a genuine encoding.
fn split_before_kem_ciphertext_value(valid: &[u8]) -> Vec<u8> {
    let mut key_marker = vec![0x6e_u8]; // text string, additional-info 14 ("kem_ciphertext".len())
    key_marker.extend_from_slice(b"kem_ciphertext");
    let key_pos = valid
        .windows(key_marker.len())
        .position(|w| w == key_marker.as_slice())
        .unwrap();
    valid[..key_pos + key_marker.len()].to_vec()
}

/// `from_cbor` must not honour a CBOR byte-string header that declares a
/// length far larger than the bytes actually supplied. Pre-fix, `Vec<u8>`
/// decoded through serde's generic sequence path, pre-allocating off the
/// declared count (capped at 1 MiB by serde's own `size_hint::cautious`,
/// per the crate's existing 1 MiB oversized-ciphertext test); the
/// `serde_bytes` byte-string path this fix adds grows its buffer only as
/// bytes are actually read from the input (`ciborium` 0.2.2
/// `deserialize_byte_buf`, `src/de/mod.rs:384-403`), so a length that lies
/// is bounded by what is actually present, not by what it claims.
#[test]
fn from_cbor_rejects_lying_byte_string_length() {
    let (_dk, ek) = fresh();
    let content_key = [0x17u8; CONTENT_KEY_LEN];
    let valid = seal_for(&content_key, &[ek]).unwrap()[0].to_cbor().unwrap();
    let mut malformed = split_before_kem_ciphertext_value(&valid);
    // Byte string (major type 2), additional-info 26: 4-byte length follows.
    malformed.push(0x5A);
    malformed.extend_from_slice(&1_000_000_u32.to_be_bytes());
    malformed.extend_from_slice(&[0x01, 0x02, 0x03]); // far short of the declared length
    assert!(
        WrappedContentKey::from_cbor(&malformed).is_err(),
        "a byte-string header declaring 1,000,000 bytes with 3 actually present must be rejected, not hang or over-allocate"
    );
}

/// `from_cbor` must handle an indefinite-length byte string (RFC 8949
/// §3.2.3) the same way: a chunk header that lies about its own length,
/// with the input ending before that many bytes exist, must be rejected
/// without over-reading.
#[test]
fn from_cbor_rejects_indefinite_length_chunk_lying_about_size() {
    let (_dk, ek) = fresh();
    let content_key = [0x18u8; CONTENT_KEY_LEN];
    let valid = seal_for(&content_key, &[ek]).unwrap()[0].to_cbor().unwrap();
    let mut malformed = split_before_kem_ciphertext_value(&valid);
    malformed.push(0x5F); // byte string (major type 2), additional-info 31: indefinite length
    malformed.push(0x5A); // first chunk: byte string, 4-byte length follows
    malformed.extend_from_slice(&1_000_000_u32.to_be_bytes());
    // No chunk bytes, no break (0xff): the input ends here.
    assert!(
        WrappedContentKey::from_cbor(&malformed).is_err(),
        "an indefinite-length chunk declaring 1,000,000 bytes with none present must be rejected, not hang or over-allocate"
    );
}

/// `from_cbor` must reject a duplicate CBOR map key rather than letting the
/// second occurrence silently win — an undetected duplicate is the same
/// class of ambiguity as trailing data: two different byte sequences would
/// carry the same apparent meaning.
#[test]
fn from_cbor_rejects_duplicate_field() {
    let (_dk, ek) = fresh();
    let content_key = [0x19u8; CONTENT_KEY_LEN];
    let mut malformed = seal_for(&content_key, &[ek]).unwrap()[0].to_cbor().unwrap();
    malformed[0] = 0xA6; // map header: 6 pairs (was 5)
    let version_pair = malformed[1..10].to_vec(); // "version" key (8 bytes) + its u8 value (1 byte)
    malformed.splice(10..10, version_pair);

    assert!(
        matches!(
            WrappedContentKey::from_cbor(&malformed),
            Err(SealError::Serialization { .. })
        ),
        "a `version` key appearing twice must be rejected, not resolved by last-value-wins"
    );
}

/// `from_cbor` must reject an unrecognized CBOR map key rather than
/// silently ignoring it — an unknown field is an unauthenticated place to
/// smuggle data that different consumers of the same bytes could disagree
/// about.
#[test]
fn from_cbor_rejects_unknown_field() {
    let (_dk, ek) = fresh();
    let content_key = [0x1Au8; CONTENT_KEY_LEN];
    let mut malformed = seal_for(&content_key, &[ek]).unwrap()[0].to_cbor().unwrap();
    malformed[0] = 0xA6; // map header: 6 pairs (was 5)
    malformed.push(0x64); // text string, additional-info 4 ("evil".len())
    malformed.extend_from_slice(b"evil");
    malformed.push(0x00); // value: unsigned 0

    assert!(
        matches!(
            WrappedContentKey::from_cbor(&malformed),
            Err(SealError::Serialization { .. })
        ),
        "an unrecognized `evil` key on an otherwise-complete envelope must be rejected, not ignored"
    );
}
