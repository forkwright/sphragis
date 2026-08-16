//! Enforces `crypto-provenance.toml` against reality.
//!
//! A provenance claim that nothing checks is a sentence, not a lock. This
//! test makes two specific claims fail loudly instead of drifting silently:
//! a dependency version moving out from under a verified vector
//! (`cargo update` changing what `Cargo.lock` resolves), and a vendored
//! vector file changing without its recorded hash changing with it. Standard
//! <-> vector referential integrity is checked too, so a dangling or
//! orphaned entry cannot sit in the lock unnoticed.

#![cfg(feature = "preview-pq")]
#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "manifest/lock-file harness: the input is this repo's own crypto-provenance.toml, Cargo.lock, and vendored vector files; a failed lookup IS the test failure"
)]

use std::collections::HashSet;
use std::fs;

use sha2::{Digest, Sha256};

fn provenance() -> toml::Value {
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/crypto-provenance.toml"
    ))
    .expect("crypto-provenance.toml is readable");
    toml::from_str(&raw).expect("crypto-provenance.toml parses as TOML")
}

fn cargo_lock() -> toml::Value {
    let raw = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"))
        .expect("Cargo.lock is readable");
    toml::from_str(&raw).expect("Cargo.lock parses as TOML")
}

/// The version Cargo actually resolved for `crate_name`, per `Cargo.lock`.
///
/// # Panics
///
/// Panics (test failure) if the crate has no `[[package]]` entry, or if more
/// than one resolved version is present (this repo's dependency graph has
/// never needed two majors of a locked crypto crate; if it ever does, this
/// lock's `locked_version` field needs a real disambiguation scheme, not a
/// silent pick).
fn resolved_version(lock: &toml::Value, crate_name: &str) -> String {
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("Cargo.lock has a [[package]] array");
    let versions: Vec<&str> = packages
        .iter()
        .filter(|p| p.get("name").and_then(toml::Value::as_str) == Some(crate_name))
        .filter_map(|p| p.get("version").and_then(toml::Value::as_str))
        .collect();
    match versions.as_slice() {
        [v] => (*v).to_owned(),
        [] => panic!("Cargo.lock has no resolved version for crate `{crate_name}`"),
        many => panic!(
            "Cargo.lock resolves {n} versions for crate `{crate_name}` ({many:?}); \
             crypto-provenance.toml's locked_version cannot disambiguate — this needs a \
             deliberate per-version-instance lock entry before the check can proceed",
            n = many.len()
        ),
    }
}

/// Every `[[dependency]]` in the lock must match the version `Cargo.lock`
/// actually resolves. This is the review-policy trigger #1 made executable:
/// a `cargo update` that moves a locked crypto crate fails here, not silently.
#[test]
fn dependency_versions_match_cargo_lock() {
    let prov = provenance();
    let lock = cargo_lock();
    let deps = prov
        .get("dependency")
        .and_then(toml::Value::as_array)
        .expect("crypto-provenance.toml has [[dependency]] entries");
    assert!(!deps.is_empty(), "dependency lock must not be empty");

    for dep in deps {
        let crate_name = dep
            .get("crate")
            .and_then(toml::Value::as_str)
            .expect("[[dependency]] has a `crate` field");
        let locked = dep
            .get("locked_version")
            .and_then(toml::Value::as_str)
            .expect("[[dependency]] has a `locked_version` field");
        let actual = resolved_version(&lock, crate_name);
        assert_eq!(
            actual, locked,
            "crate `{crate_name}` resolves to {actual} in Cargo.lock but \
             crypto-provenance.toml pins {locked}: re-verify every vector this crate's \
             version participates in against the standard it claims to match, byte-for-byte, \
             then update locked_version — do not update the lock without re-deriving"
        );
    }
}

/// Every vendored vector file's on-disk hash must equal its recorded
/// `source_sha256`. Catches an accidental or malicious edit to a vendored
/// fixture independent of a `cargo update` — the file itself is the vector.
#[test]
fn vendored_vector_files_match_recorded_hash() {
    let prov = provenance();
    let vectors = prov
        .get("vector")
        .and_then(toml::Value::as_array)
        .expect("crypto-provenance.toml has [[vector]] entries");

    let mut checked = 0;
    for vector in vectors {
        let Some(vendored_file) = vector.get("vendored_file").and_then(toml::Value::as_str) else {
            continue; // inline (RFC) vectors: source_sha256 is an audit reference, not a local file
        };
        let expected = vector
            .get("source_sha256")
            .and_then(toml::Value::as_str)
            .expect("a vendored vector has a source_sha256");
        let id = vector
            .get("id")
            .and_then(toml::Value::as_str)
            .expect("a vector has an id");

        let bytes = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/").to_owned() + vendored_file)
            .unwrap_or_else(|e| panic!("vendored vector `{id}` at {vendored_file}: {e}"));
        let actual = hex::encode(Sha256::digest(&bytes).as_slice());
        assert_eq!(
            actual, expected,
            "vendored vector `{id}` at {vendored_file} hashes to {actual}, \
             crypto-provenance.toml records {expected} — the file drifted from what the lock \
             claims to have hashed; re-vendor from `vendored_from`/`origin_url` and update \
             source_sha256, do not hand-edit the mismatch away"
        );
        checked += 1;
    }
    assert!(
        checked >= 3,
        "expected at least the three vendored vectors (x-wing, ML-KEM keygen, ML-KEM encapdecap) to be present and checked, got {checked}"
    );
}

/// Every `[[vector]].standard` must reference a declared `[[standard]].id`,
/// and every standard must have at least one vector proving it — no dangling
/// or orphaned lock entries.
#[test]
fn vector_standard_references_are_complete() {
    let prov = provenance();
    let standards = prov
        .get("standard")
        .and_then(toml::Value::as_array)
        .expect("crypto-provenance.toml has [[standard]] entries");
    let vectors = prov
        .get("vector")
        .and_then(toml::Value::as_array)
        .expect("crypto-provenance.toml has [[vector]] entries");

    let standard_ids: HashSet<&str> = standards
        .iter()
        .filter_map(|s| s.get("id").and_then(toml::Value::as_str))
        .collect();
    assert_eq!(
        standard_ids.len(),
        standards.len(),
        "duplicate [[standard]] id in crypto-provenance.toml"
    );

    let mut proven: HashSet<&str> = HashSet::new();
    for vector in vectors {
        let vector_id = vector
            .get("id")
            .and_then(toml::Value::as_str)
            .expect("a vector has an id");
        let standard_ref = vector
            .get("standard")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("vector `{vector_id}` has no `standard` reference"));
        assert!(
            standard_ids.contains(standard_ref),
            "vector `{vector_id}` references undeclared standard `{standard_ref}`"
        );
        proven.insert(standard_ref);
    }

    for id in &standard_ids {
        assert!(
            proven.contains(id),
            "standard `{id}` is declared but no [[vector]] proves it — either add a vector or remove the standard"
        );
    }
}
