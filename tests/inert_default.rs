//! Packaging invariant: unaudited crypto never ships in the default path.
//!
//! Every module and export in this crate sits behind `preview-pq`; the default
//! build is deliberately inert. These tests lock that contract at the manifest
//! layer, where it is defined — an accidental `default = ["preview-pq"]` or a
//! crypto dependency losing `optional = true` fails here. They are also the
//! only tests that exist without `--features preview-pq`, so a default-features
//! test run exercises the invariant rather than finding an empty suite.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "manifest-invariant harness: the input is the crate's own Cargo.toml; a failed lookup IS the test failure"
)]

use std::fs;

const CRYPTO_DEPS: [&str; 7] = [
    "ml-kem",
    "x25519-dalek",
    "sha3",
    "sha2",
    "hkdf",
    "chacha20poly1305",
    "rand_core",
];

fn manifest() -> toml::Value {
    let raw = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("Cargo.toml is readable");
    toml::from_str(&raw).expect("Cargo.toml parses as TOML")
}

#[test]
fn default_feature_set_is_empty() {
    let doc = manifest();
    let default = doc
        .get("features")
        .and_then(|f| f.get("default"))
        .and_then(toml::Value::as_array)
        .expect("[features] default is an array");
    assert!(
        default.is_empty(),
        "default feature set must stay empty (unaudited crypto is opt-in only), got {default:?}"
    );
}

#[test]
fn every_crypto_dependency_is_optional() {
    let doc = manifest();
    let deps = doc
        .get("dependencies")
        .expect("[dependencies] table exists");
    for name in CRYPTO_DEPS {
        let optional = deps
            .get(name)
            .unwrap_or_else(|| panic!("dependency `{name}` present in manifest"))
            .get("optional")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        assert!(
            optional,
            "crypto dependency `{name}` must be `optional = true`"
        );
    }
}

#[test]
fn preview_pq_gates_every_crypto_dependency() {
    let doc = manifest();
    let gate = doc
        .get("features")
        .and_then(|f| f.get("preview-pq"))
        .and_then(toml::Value::as_array)
        .expect("[features] preview-pq is an array");
    let gated: Vec<String> = gate
        .iter()
        .filter_map(toml::Value::as_str)
        .filter_map(|entry| entry.strip_prefix("dep:"))
        .map(str::to_owned)
        .collect();
    for name in CRYPTO_DEPS {
        assert!(
            gated.iter().any(|g| g == name),
            "crypto dependency `{name}` must be activated via `dep:{name}` in preview-pq"
        );
    }
}
