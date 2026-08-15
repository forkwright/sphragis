//! Normal-consumer acceptance for the envelope profile (sphragis#23).
//!
//! Exercises only the stable public surface — `generate_recipient_keypair`,
//! `seal_for`, `unseal` — with `preview-pq` alone, `hazmat` OFF. This is the
//! proof that narrowing the public API (hiding `HybridKem`, `SharedSecret`,
//! `derive_wrap_key`, and direct encaps/decaps behind `hazmat`) did not also
//! narrow what a normal consumer can *do*: every operation the profile
//! promises still works without naming a single primitive-level item.

#![cfg(feature = "preview-pq")]

use sphragis::{generate_recipient_keypair, seal_for, unseal, CONTENT_KEY_LEN};

/// A normal consumer generates a keypair, seals a content key for it, and
/// unseals it back — using only the versioned envelope operations.
#[expect(
    clippy::unwrap_used,
    reason = "integration test: a failed unwrap on our own API's output IS the test failure"
)]
#[test]
fn generate_seal_unseal_round_trip_without_hazmat() {
    let (dk, ek) = generate_recipient_keypair();
    let content_key = [0x42u8; CONTENT_KEY_LEN];

    let wrapped = seal_for(&content_key, &[ek]).unwrap();
    assert_eq!(wrapped.len(), 1);

    let recovered = unseal(&dk, wrapped.first().unwrap()).unwrap();
    assert_eq!(recovered.as_slice(), &content_key);
}

/// Two calls to `generate_recipient_keypair` produce independent devices:
/// device 2's key does not unseal a wrap addressed to device 1.
#[expect(
    clippy::unwrap_used,
    reason = "integration test: a failed unwrap on our own API's output IS the test failure"
)]
#[test]
fn independently_generated_keypairs_do_not_cross_unseal() {
    let (_dk1, ek1) = generate_recipient_keypair();
    let (dk2, _ek2) = generate_recipient_keypair();
    let content_key = [0x24u8; CONTENT_KEY_LEN];

    let wrapped = seal_for(&content_key, &[ek1]).unwrap();
    assert!(
        unseal(&dk2, wrapped.first().unwrap()).is_err(),
        "an independently generated device must not unseal another device's wrap"
    );
}
