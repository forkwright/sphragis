//! Fitness checks for the security-critical feature coverage in the required gate.

use std::error::Error;
use std::fs;

#[test]
fn required_gate_locks_every_review_feature_profile() -> Result<(), Box<dyn Error>> {
    let workflow = fs::read_to_string(".github/workflows/gate-attestation.yml")?;

    // WHY(sphragis#43): compare complete settings, not individual command
    // fragments, so deleting any profile from a stage fails this fitness test.
    for required in [
        r#"check_cmd: "cargo check --all-targets && cargo check --all-targets --features preview-pq && cargo check --all-targets --features preview-pq,hazmat""#,
        r#"clippy_cmd: "cargo clippy --all-targets -- -D warnings && cargo clippy --all-targets --features preview-pq -- -D warnings && cargo clippy --all-targets --features preview-pq,hazmat -- -D warnings""#,
        r#"nextest_cmd: "cargo nextest run && cargo nextest run --features preview-pq && cargo nextest run --features preview-pq,hazmat""#,
        r#"doctest_cmd: "cargo test --doc && cargo test --doc --features preview-pq && cargo test --doc --features preview-pq,hazmat""#,
        "docs_only_exemption: false",
    ] {
        assert!(
            workflow.lines().any(|line| line.trim() == required),
            "required public gate setting changed or disappeared: {required}"
        );
    }

    Ok(())
}
