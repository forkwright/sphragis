//! Known-answer-test acceptance gate for `sphragis` (preview-pq): proves the
//! construction matches externally published cryptographic standards.
//!
//! Every KAT here is bound to `crypto-provenance.toml`: which standard
//! revision it proves, where the vector came from, and (for the vendored
//! ones) a hash `tests/provenance_lock.rs` checks against the file on disk.
//! Proves the construction matches the published standards:
//! - X-Wing draft KAT: full hybrid keypair, ciphertext, and shared secret
//!   (both directions), not shared-secret-only. Lives beside the
//!   implementation, in `src/hybrid.rs`'s own `#[cfg(test)] mod tests` — not
//!   here. It drives deterministic encapsulation, which is a private method
//!   on `EncapsulationKey`; this file compiles as a separate crate and
//!   cannot name it (forkwright/sphragis#17).
//! - FIPS-203 ML-KEM-768 ACVP: keygen (seed -> ek), encapsulation
//!   (ek, m -> ct, k), and decapsulation (dk, ct -> k) — executed locally,
//!   not delegated to the `ml-kem` crate's own test suite (a consumer
//!   `cargo test` never runs a dependency's tests).
//! - RFC 8439 ChaCha20-Poly1305 (full AEAD: key, nonce, AAD, plaintext,
//!   ciphertext, tag) — executed locally against the same `chacha20poly1305`
//!   crate version `sphragis::envelope` seals with.
//! - RFC 5869 HKDF-SHA256.
//! - RFC 7748 X25519.
//!
//! `tests/seal_roundtrip.rs` is the sibling acceptance gate for the envelope
//! API itself (round-trip, multi-recipient, negatives, wire/parse
//! boundaries): this split (RUST/file-too-long, forkwright/sphragis#37)
//! keeps external-standard conformance and sphragis's own API behavior in
//! separate files, each provable independently of the other.

#![cfg(feature = "preview-pq")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "KAT harness: inputs are fixed known-answer vectors; a failed unwrap or out-of-bounds index IS the test failure"
)]

use hex_literal::hex;

use sphragis::envelope::derive_wrap_key;

/// Reads a vendored vector fixture (`tests/vectors/<name>`) as JSON.
///
/// `crypto-provenance.toml` records this file's provenance and hash;
/// `tests/provenance_lock.rs` checks the hash. Reading it here rather than
/// re-typing its fields as a parallel set of hex literals means the executed
/// assertion and the hash-locked file can never silently desync.
fn vector_json(name: &str) -> serde_json::Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn hex_field(v: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(v[field].as_str().unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// X-Wing draft known-answer vector (crypto-provenance.toml: xwing-kat-0).
// draft-connolly-cfrg-xwing-kem. seed -> keypair; eseed -> deterministic
// encaps. Lives beside the implementation, in `src/hybrid.rs`'s own
// `#[cfg(test)] mod tests` — deterministic encapsulation is a private method
// on `EncapsulationKey`; this file compiles as a separate crate and cannot
// name it (forkwright/sphragis#17).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// FIPS-203 ML-KEM-768 known-answer vectors (crypto-provenance.toml:
// mlkem768-keygen-acvp, mlkem768-encapdecap-acvp). Executed locally: this is
// the specific gap #18 found — ML-KEM correctness was previously delegated to
// the `ml-kem` crate's own test suite, which `cargo test` in this repo never
// runs. NIST ACVP-Server, ML-KEM-768 parameter set.
// ---------------------------------------------------------------------------

/// FIPS-203 keygen: an ACVP `(d, z)` seed reproduces the published
/// encapsulation key. Exercises the same `Seed`/`from_seed` path
/// `hybrid::expand` uses for the X-Wing ML-KEM component.
#[test]
fn mlkem768_fips203_keygen_from_seed_acvp() {
    use ml_kem::array::Array;
    use ml_kem::kem::KeyExport;
    use ml_kem::{MlKem768, Seed};

    let doc = vector_json("mlkem-fips203-keygen-acvp.json");
    let group = doc["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["parameterSet"].as_str() == Some("ML-KEM-768"))
        .unwrap();
    let tc = group["tests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tcId"].as_u64() == Some(26))
        .unwrap();

    let d = hex_field(tc, "d");
    let z = hex_field(tc, "z");
    let expected_ek = hex_field(tc, "ek");

    let mut seed_bytes = d;
    seed_bytes.extend_from_slice(&z);
    let seed: Seed = Array::try_from(seed_bytes.as_slice()).unwrap();

    let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed);
    assert_eq!(
        dk.encapsulation_key().to_bytes().as_slice(),
        expected_ek.as_slice(),
        "ML-KEM-768 FIPS-203 keygen from (d, z) must reproduce the ACVP encapsulation key"
    );
}

/// FIPS-203 encapsulation: a published encapsulation key plus the ACVP
/// randomness `m` reproduces the exact ciphertext and shared secret.
#[test]
fn mlkem768_fips203_encapsulate_deterministic_acvp() {
    use ml_kem::array::Array;
    use ml_kem::kem::Key;
    use ml_kem::{EncapsulationKey as MlKemEncapsulationKey, MlKem768};

    let case = mlkem768_aft_case();

    let key: Key<MlKemEncapsulationKey<MlKem768>> = Array::try_from(case.ek.as_slice()).unwrap();
    let ek = MlKemEncapsulationKey::<MlKem768>::new(&key).unwrap();
    let m: ml_kem::B32 = Array::try_from(case.m.as_slice()).unwrap();

    let (ct, ss) = ek.encapsulate_deterministic(&m);
    assert_eq!(
        ct.as_slice(),
        case.c.as_slice(),
        "ML-KEM-768 FIPS-203 encapsulation must reproduce the ACVP ciphertext"
    );
    assert_eq!(
        ss.as_slice(),
        case.k.as_slice(),
        "ML-KEM-768 FIPS-203 encapsulation must reproduce the ACVP shared secret"
    );
}

/// FIPS-203 decapsulation: the published expanded decapsulation key recovers
/// the ACVP shared secret from the ACVP ciphertext.
#[expect(
    deprecated,
    reason = "the ACVP vector publishes dk in the FIPS-203 expanded wire format; ml-kem's non-deprecated encoding is seed-only (from_seed / to_seed), so decoding a real NIST-published dk requires the legacy expanded-key path — used strictly to validate against the standard, matching the pattern the ml-kem crate's own wycheproof.rs test uses for the same reason"
)]
#[test]
fn mlkem768_fips203_decapsulate_acvp() {
    use ml_kem::array::Array;
    use ml_kem::kem::Decapsulate;
    use ml_kem::{Ciphertext, ExpandedDecapsulationKey, MlKem768};

    let case = mlkem768_aft_case();

    let expanded: ExpandedDecapsulationKey<MlKem768> = Array::try_from(case.dk.as_slice()).unwrap();
    let dk = ml_kem::DecapsulationKey::<MlKem768>::from_expanded(&expanded).unwrap();
    let ct: Ciphertext<MlKem768> = Array::try_from(case.c.as_slice()).unwrap();

    let ss = dk.decapsulate(&ct);
    assert_eq!(
        ss.as_slice(),
        case.k.as_slice(),
        "ML-KEM-768 FIPS-203 decapsulation must reproduce the ACVP shared secret"
    );
}

/// One ML-KEM-768 AFT (encapsulation) test case, self-contained: `ek`/`dk` are
/// the same keypair, `m` the encapsulation randomness, `c`/`k` the expected
/// ciphertext and shared secret.
struct MlKem768AftCase {
    ek: Vec<u8>,
    dk: Vec<u8>,
    m: Vec<u8>,
    c: Vec<u8>,
    k: Vec<u8>,
}

/// Reads the ML-KEM-768 AFT test case (tcId 26). Shared by the encapsulation
/// and decapsulation ACVP tests so both exercise the identical NIST-published
/// keypair and ciphertext.
fn mlkem768_aft_case() -> MlKem768AftCase {
    let doc = vector_json("mlkem-fips203-encapdecap-acvp.json");
    let group = doc["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["parameterSet"].as_str() == Some("ML-KEM-768") && g["testType"] == "AFT")
        .unwrap();
    let tc = group["tests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tcId"].as_u64() == Some(26))
        .unwrap();
    MlKem768AftCase {
        ek: hex_field(tc, "ek"),
        dk: hex_field(tc, "dk"),
        m: hex_field(tc, "m"),
        c: hex_field(tc, "c"),
        k: hex_field(tc, "k"),
    }
}

// ---------------------------------------------------------------------------
// RFC 8439 ChaCha20-Poly1305 — Section 2.8.2 example/test vector
// (crypto-provenance.toml: chacha20poly1305-rfc8439-2.8.2). Executed locally
// against the same `chacha20poly1305` crate `sphragis::envelope` seals with —
// the other half of the gap #18 found (ChaCha vectors were previously
// delegated upstream, unexercised by this repo's own `cargo test`).
// ---------------------------------------------------------------------------

/// RFC 8439 Section 2.8.2 worked example: full AEAD seal reproduces the
/// published ciphertext and tag; open recovers the plaintext and rejects a
/// tampered tag.
#[test]
fn chacha20poly1305_rfc8439_2_8_2() {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let key = hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    // 32-bit fixed-common part (07000000) || 64-bit IV (4041424344454647).
    let nonce = hex!("070000004041424344454647");
    let aad = hex!("50515253c0c1c2c3c4c5c6c7");
    let plaintext = hex!(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c61"
        "7373206f66202739393a204966204920636f756c64206f6666657220796f75"
        "206f6e6c79206f6e652074697020666f7220746865206675747572652c2073"
        "756e73637265656e20776f756c642062652069742e"
    );
    // WHY: each hex! fragment must independently have an even hex-digit count
    // (hex-literal parses per-fragment, not the virtual concatenation) — split
    // at the ciphertext/tag boundary plus even 76-char chunks, not by feel.
    let expected_ciphertext_and_tag = hex!(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9"
        "671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee3"
        "28091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        "1ae10b594f09e26a7e902ecbd0600691"
    );

    let cipher = ChaCha20Poly1305::new(<&Key>::from(&key));
    let sealed = cipher
        .encrypt(
            <&Nonce>::from(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(
        sealed, expected_ciphertext_and_tag,
        "ChaCha20-Poly1305 must reproduce the RFC 8439 §2.8.2 ciphertext || tag"
    );

    let opened = cipher
        .decrypt(
            <&Nonce>::from(&nonce),
            Payload {
                msg: &sealed,
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(
        opened, plaintext,
        "ChaCha20-Poly1305 open must recover the RFC 8439 §2.8.2 plaintext"
    );

    let mut tampered = sealed;
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    assert!(
        cipher
            .decrypt(
                <&Nonce>::from(&nonce),
                Payload {
                    msg: &tampered,
                    aad: &aad
                }
            )
            .is_err(),
        "a tampered RFC 8439 §2.8.2 tag must fail to open"
    );
}

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
