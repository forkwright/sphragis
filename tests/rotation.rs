//! Adversarial proof of key rotation (sphragis#14): a device that already
//! recovered the old content key remains able to read old-key ciphertext,
//! and loses read access specifically because rotation moves to a
//! cryptographically independent key, not because it is missing from a
//! wrap list.
//!
//! Exercises only the stable profile surface (`preview-pq`, no `hazmat`) —
//! the rotation API sits on the same narrowed surface as `seal_for`/
//! `unseal` (sphragis#23).

#![cfg(feature = "preview-pq")]
#![expect(
    clippy::unwrap_used,
    reason = "integration test: a failed unwrap on our own API's or our own AEAD call's output IS the test failure"
)]

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use sphragis::{
    CONTENT_KEY_LEN, EpochId, PendingRotation, generate_content_key, generate_recipient_keypair,
    seal_for, unseal,
};

/// Stands in for whatever AEAD a consuming store uses to protect its own
/// payload bytes under a sphragis-distributed content key. Sphragis never
/// performs this operation itself — see `src/rotate.rs`'s module doc.
fn store_encrypt(
    content_key: &[u8; CONTENT_KEY_LEN],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(<&Key>::from(content_key));
    cipher
        .encrypt(
            <&Nonce>::from(nonce),
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
        .unwrap()
}

/// The store-side counterpart of [`store_encrypt`]. Returns `None` on any
/// AEAD failure (wrong key, wrong nonce, tampered ciphertext) rather than
/// naming the underlying error type, which this test has no need to
/// inspect.
fn store_decrypt(
    content_key: &[u8; CONTENT_KEY_LEN],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(<&Key>::from(content_key));
    cipher
        .decrypt(
            <&Nonce>::from(nonce),
            Payload {
                msg: ciphertext,
                aad: b"",
            },
        )
        .ok()
}

/// The adversarial property forkwright/sphragis#14 exists to establish: a
/// device that already recovered the OLD content key (device 2) —
///
/// - remains able to decrypt data that was already encrypted under the old
///   key (nothing in this crate, or in rotation, can retract that), AND
/// - is unable to decrypt data encrypted under the NEW content key once
///   rotation has completed, because the new key is cryptographically
///   independent of the old one and device 2 was never issued a wrap for
///   it.
///
/// A test that only checks device 2 is absent from the new wrap set proves
/// the weaker, already-true `seal_for_omits_unlisted_recipient` property
/// (`tests/known_answer_vectors.rs`); this test proves the actual security
/// property instead.
#[test]
fn rotation_actually_revokes_a_device_that_held_the_old_key() {
    let (dk1, ek1) = generate_recipient_keypair().unwrap();
    let (dk2, ek2) = generate_recipient_keypair().unwrap();

    // --- Before rotation: both devices are legitimately provisioned. ---
    let old_content_key = generate_content_key().unwrap();
    let old_wraps = seal_for(&old_content_key, &[ek1.clone(), ek2]).unwrap();

    // Device 2 actually recovers the old content key -- this is the step
    // the issue's evidence found missing from the prior "revocation" test.
    let device2_old_key: [u8; CONTENT_KEY_LEN] = unseal(&dk2, old_wraps.get(1).unwrap())
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();

    let old_payload_nonce = [0x01u8; 12];
    let old_payload = store_encrypt(&old_content_key, &old_payload_nonce, b"pre-rotation secret");

    // Device 2 remains able to read data encrypted under the key it holds --
    // rotation has not happened yet, and never touches this ciphertext.
    assert_eq!(
        store_decrypt(&device2_old_key, &old_payload_nonce, &old_payload).unwrap(),
        b"pre-rotation secret",
        "device 2 must still be able to read data it already had the key for"
    );

    // --- Rotate: device 2 is revoked, device 1 is retained. ---
    let new_content_key = generate_content_key().unwrap();
    let pending = PendingRotation::begin(EpochId(1), &new_content_key, &old_content_key).unwrap();
    let published = pending.publish_wraps_for(&[ek1]).unwrap();

    // The weaker, already-true property (recipient omission): device 2 has
    // no wrap in the new epoch. By itself this proves nothing about whether
    // device 2 can still read data -- the load-bearing assertion is below,
    // after the epoch is actually committed.
    assert_eq!(
        published.wraps().len(),
        1,
        "only the retained recipient (device 1) receives a new-epoch wrap"
    );
    let device1_new_wrap = published.wraps().first().unwrap().clone();

    let committed = published.commit();
    let complete = committed.retire_old_key(old_content_key);
    assert_eq!(complete.epoch, EpochId(1));

    // --- After rotation: the load-bearing assertion. ---
    let new_payload_nonce = [0x02u8; 12];
    let new_payload = store_encrypt(
        &new_content_key,
        &new_payload_nonce,
        b"post-rotation secret",
    );

    // THE adversarial assertion: device 2, still holding the OLD content
    // key it legitimately recovered, cannot decrypt data protected under
    // the completed NEW epoch. This is what "revoked" has to mean.
    assert!(
        store_decrypt(&device2_old_key, &new_payload_nonce, &new_payload).is_none(),
        "a device holding only the OLD content key must not be able to read \
         data protected under a completed new epoch"
    );

    // Device 1 (retained) continues to work: it gets a new-epoch wrap and
    // can read the new payload.
    let device1_new_key: [u8; CONTENT_KEY_LEN] = unseal(&dk1, &device1_new_wrap)
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
    assert_eq!(
        store_decrypt(&device1_new_key, &new_payload_nonce, &new_payload).unwrap(),
        b"post-rotation secret",
        "the retained device must be able to read data protected under the new epoch"
    );
}

/// `PendingRotation::begin` refuses a rotation that would not actually
/// change anything: new key == old key.
#[test]
fn begin_rejects_unchanged_content_key() {
    let content_key = generate_content_key().unwrap();
    let result = PendingRotation::begin(EpochId(7), &content_key, &content_key);
    assert!(
        result.is_err(),
        "rotating into the same content key must be rejected, not silently accepted"
    );
}

/// A rotation with a genuinely fresh key is accepted, and the completed
/// protocol reports the epoch it was begun with.
#[test]
fn full_protocol_reaches_rotation_complete() {
    let (_dk1, ek1) = generate_recipient_keypair().unwrap();
    let old_content_key = generate_content_key().unwrap();
    let new_content_key = generate_content_key().unwrap();

    let pending = PendingRotation::begin(EpochId(42), &new_content_key, &old_content_key).unwrap();
    let published = pending.publish_wraps_for(&[ek1]).unwrap();
    assert_eq!(published.epoch(), EpochId(42));
    let committed = published.commit();
    assert_eq!(committed.epoch(), EpochId(42));
    let complete = committed.retire_old_key(old_content_key);
    assert_eq!(complete.epoch, EpochId(42));
}
