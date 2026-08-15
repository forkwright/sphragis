//! Known-answer-test acceptance gate for `sphragis` (preview-pq).
//!
//! Proves the construction matches the published standards:
//! - X-Wing draft KAT (full hybrid encaps→decaps→shared secret).
//! - RFC 5869 HKDF-SHA256.
//! - RFC 7748 X25519.
//! - Round-trip + negative tests (wrong recipient, wrong version, tamper,
//!   wrong-length inputs, parse-boundary rejection, AAD binding, seed and
//!   wire-form export, randomness freshness).
//!
//! ChaCha20-Poly1305 (RFC 8439) and ML-KEM-768 (FIPS-203 ACVP) primitive vectors
//! are covered upstream in the `ml-kem` crate respectively; this gate validates
//! the *hybrid composition* and *envelope*.

#![cfg(feature = "preview-pq")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "KAT harness: inputs are fixed known-answer vectors; a failed unwrap or out-of-bounds index IS the test failure"
)]

use hex_literal::hex;

use sphragis::envelope::derive_wrap_key;
use sphragis::hybrid::{
    DecapsulationKey, EncapsulationKey, HybridKem, CIPHERTEXT_LEN, ENCAPSULATION_KEY_LEN,
};
use sphragis::seal::{seal_for, unseal, RecipientId, WrappedContentKey, CONTENT_KEY_LEN};
use sphragis::{SealError, SEAL_VERSION_V1};

// ---------------------------------------------------------------------------
// X-Wing draft known-answer vector (RustCrypto x-wing test-vectors.json, [0]).
// draft-connolly-cfrg-xwing-kem. seed -> keypair; eseed -> deterministic encaps.
// ---------------------------------------------------------------------------

/// X-Wing KAT: deterministic encapsulation reproduces the published shared
/// secret, and decapsulation recovers it.
#[test]
fn xwing_draft_kat_vector_0() {
    let seed = hex!("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    let eseed = hex!(
        "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2"
        "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2"
    );
    let expected_ss = hex!("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384");

    let dk = DecapsulationKey::from_seed(seed);
    assert_eq!(
        *dk.to_seed(),
        seed,
        "to_seed must export exactly the seed the key was built from"
    );
    let ek = dk.encapsulation_key();

    let (ct, ss_send) = ek.encapsulate_deterministic(&eseed).unwrap();
    assert_eq!(
        ss_send.as_slice(),
        &expected_ss,
        "X-Wing deterministic encaps must reproduce the draft KAT shared secret"
    );

    let ss_recv = dk.decapsulate(&ct).unwrap();
    assert_eq!(
        ss_recv.as_slice(),
        &expected_ss,
        "X-Wing decaps must recover the draft KAT shared secret"
    );
}

// ---------------------------------------------------------------------------
// RFC 5869 HKDF-SHA256 — Test Case 1.
// ---------------------------------------------------------------------------

/// RFC 5869 Appendix A.1 (HKDF-SHA256, Test Case 1) against the `hkdf` crate.
#[test]
fn hkdf_sha256_rfc5869_case_1() {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex!("000102030405060708090a0b0c");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm = hex!(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    );

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm).unwrap();
    assert_eq!(
        okm.as_slice(),
        &expected_okm,
        "HKDF-SHA256 must match RFC 5869 Test Case 1"
    );
}

/// The envelope wrap-key derivation is deterministic and domain-separated.
#[test]
fn derive_wrap_key_is_deterministic_and_domain_separated() {
    let ss = [0x42u8; 32];
    let a = derive_wrap_key(&ss, b"sphragis-ck-wrap-v1").unwrap();
    let b = derive_wrap_key(&ss, b"sphragis-ck-wrap-v1").unwrap();
    let c = derive_wrap_key(&ss, b"sphragis-ck-wrap-v2").unwrap();
    assert_eq!(a.as_slice(), b.as_slice(), "same inputs -> same key");
    assert_ne!(
        a.as_slice(),
        c.as_slice(),
        "different domain tag -> different key"
    );
}

// ---------------------------------------------------------------------------
// RFC 7748 Section 5.2 — X25519 known-answer vector (first vector).
// ---------------------------------------------------------------------------

/// RFC 7748 Section 5.2 X25519 first test vector.
#[test]
fn x25519_rfc7748_vector_1() {
    use x25519_dalek::{PublicKey, StaticSecret};

    let scalar = hex!("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u_coord = hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let expected = hex!("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    let sk = StaticSecret::from(scalar);
    let peer = PublicKey::from(u_coord);
    let shared = sk.diffie_hellman(&peer);
    assert_eq!(
        shared.as_bytes(),
        &expected,
        "X25519 must match RFC 7748 Section 5.2 vector 1"
    );
}

// ---------------------------------------------------------------------------
// End-to-end sealing: round-trip, multi-recipient, revocation, negatives.
// ---------------------------------------------------------------------------

fn fresh() -> (DecapsulationKey, EncapsulationKey) {
    HybridKem::generate()
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

/// Revocation: re-sealing for the remaining recipients excludes the revoked one.
#[test]
fn revocation_excludes_device() {
    let (dk1, ek1) = fresh();
    let (dk2, ek2) = fresh();
    let content_key = [0x22u8; CONTENT_KEY_LEN];

    // Revoke device 2: re-seal for device 1 only.
    let rewrapped = seal_for(&content_key, &[ek1]).unwrap();
    assert_eq!(rewrapped.len(), 1);
    assert_eq!(
        unseal(&dk1, &rewrapped[0]).unwrap().as_slice(),
        &content_key
    );

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

/// Wrong-length encapsulation-key and ciphertext inputs are rejected.
#[test]
fn wrong_length_ek_and_ct_rejected() {
    let (dk, ek) = fresh();

    let ek_bytes = ek.to_bytes();
    assert!(EncapsulationKey::from_bytes(&ek_bytes[..ek_bytes.len() - 1]).is_err());
    assert!(EncapsulationKey::from_bytes(&[]).is_err());
    let mut long = ek.to_bytes();
    long.push(0);
    assert!(EncapsulationKey::from_bytes(&long).is_err());

    let (ct, _ss) = ek.encapsulate().unwrap();
    assert!(dk.decapsulate(&ct[..ct.len() - 1]).is_err());
    assert!(dk.decapsulate(&[]).is_err());
    assert!(dk.decapsulate(&[0u8; CIPHERTEXT_LEN - 1]).is_err());
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

/// The empty recipient list (full revocation) seals to an empty set.
#[test]
fn seal_for_empty_recipients_is_empty() {
    let content_key = [0xAAu8; CONTENT_KEY_LEN];
    let wrapped = seal_for(&content_key, &[]).unwrap();
    assert!(
        wrapped.is_empty(),
        "revoking every recipient must produce zero wraps, not an error"
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
    let valid = seal_for(&content_key, &[ek]).unwrap()[0].to_cbor().unwrap();

    let mut malformed = valid.clone();
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
    let valid = seal_for(&content_key, &[ek]).unwrap()[0].to_cbor().unwrap();

    let mut malformed = valid.clone();
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
