//! Entropy-failure handling (#16): OS-RNG exhaustion must return
//! `SealError::Entropy`, never panic.
//!
//! `rand_core` 0.6's `OsRng::fill_bytes` panics on OS-RNG failure
//! (`rand_core-0.6.4/src/os.rs`); this crate's `_with_rng` seams use
//! `try_fill_bytes` exclusively, so a caller-injected RNG proves every
//! entropy-consuming call site — key generation, encapsulation, and the AEAD
//! nonce draw inside `seal_for` — returns a typed error instead. The OS RNG
//! itself cannot be made to fail on command, so injection is the only way to
//! observe this path at all.

#![cfg(feature = "preview-pq")]
#![expect(
    clippy::unwrap_used,
    reason = "test harness: a failed unwrap on setup data IS the test failure"
)]
#![expect(
    clippy::expect_used,
    reason = "CountdownRng::fill_bytes deliberately panics via expect() — it mirrors OsRng's real \
              panicking behavior on failure, so a production call site that regressed onto \
              fill_bytes (instead of try_fill_bytes) fails loudly here instead of silently"
)]
#![expect(
    clippy::panic,
    reason = "test harness: an unmatched error variant or unmet assertion IS the test failure, \
              surfaced via panic! the same way assert!/assert_eq! do internally"
)]

use rand_core::{CryptoRng, Error as RngError, RngCore};

use sphragis::SealError;
use sphragis::hybrid::HybridKem;
use sphragis::seal::seal_for_with_rng;

/// A CSPRNG stand-in that succeeds a fixed number of `try_fill_bytes` calls
/// before failing every call after. Fill bytes are deterministic (an
/// incrementing counter), never real entropy — fine for proving control flow,
/// never for real key material.
///
/// WHY: the injectable seam this test exists to prove. Without a way to hand
/// the KEM/seal paths an RNG that fails on demand, the entropy-failure branch
/// has no test — a failure mode nobody has watched fail is an unverified
/// claim wearing a verdict's clothes.
struct CountdownRng {
    remaining: u32,
    counter: u8,
}

impl CountdownRng {
    /// An RNG whose next `n` fill calls succeed; every call after fails.
    const fn succeeds(n: u32) -> Self {
        Self {
            remaining: n,
            counter: 0,
        }
    }
}

impl RngCore for CountdownRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("CountdownRng: production code must use try_fill_bytes, not fill_bytes");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        let Some(remaining) = self.remaining.checked_sub(1) else {
            return Err(RngError::new(std::io::Error::other(
                "mock entropy source exhausted",
            )));
        };
        self.remaining = remaining;
        for b in dest {
            self.counter = self.counter.wrapping_add(1);
            *b = self.counter;
        }
        Ok(())
    }
}

impl CryptoRng for CountdownRng {}

/// `HybridKem::generate_with_rng` returns [`SealError::Entropy`], with a
/// captured call-site location, when the RNG fails — not a panic.
// WHY: matched on `&result` (never printed, never moved) rather than
// `result` — `EncapsulationKey` is intentionally not `Debug` (it holds
// key-derived material), so a moved-and-printed `Result` here would not
// compile.
#[test]
fn generate_with_rng_returns_entropy_error_not_panic() {
    let mut rng = CountdownRng::succeeds(0);
    let result = HybridKem::generate_with_rng(&mut rng);

    let Err(SealError::Entropy { source, location }) = &result else {
        panic!("expected SealError::Entropy");
    };
    assert!(
        format!("{source}").contains("exhausted"),
        "the underlying RNG failure text must be reachable, got {source}"
    );
    assert!(
        location.file().ends_with("hybrid.rs"),
        "the implicit location must name the failing call site, got {}",
        location.file()
    );
}

/// `HybridKem::generate_with_rng` still succeeds when the RNG does — the seam
/// does not disturb the happy path.
#[test]
fn generate_with_rng_succeeds_with_working_rng() {
    let mut rng = CountdownRng::succeeds(1);
    assert!(HybridKem::generate_with_rng(&mut rng).is_ok());
}

/// `EncapsulationKey::encapsulate_with_rng` returns [`SealError::Entropy`]
/// when the RNG fails — not a panic.
#[test]
fn encapsulate_with_rng_returns_entropy_error_not_panic() {
    let (_dk, ek) = HybridKem::generate_with_rng(&mut CountdownRng::succeeds(1)).unwrap();

    let mut rng = CountdownRng::succeeds(0);
    let result = ek.encapsulate_with_rng(&mut rng);
    assert!(
        matches!(&result, Err(SealError::Entropy { .. })),
        "expected SealError::Entropy, got {result:?}"
    );
}

/// `seal_for_with_rng` propagates an entropy failure from the encapsulation
/// draw (the first randomness consumed per recipient) as
/// [`SealError::Entropy`].
#[test]
fn seal_for_with_rng_returns_entropy_error_when_encapsulation_entropy_fails() {
    let (_dk, ek) = HybridKem::generate_with_rng(&mut CountdownRng::succeeds(1)).unwrap();
    let content_key = [0x42u8; 32];

    let mut rng = CountdownRng::succeeds(0);
    let result = seal_for_with_rng(&content_key, &[ek], &mut rng);
    assert!(
        matches!(&result, Err(SealError::Entropy { .. })),
        "expected SealError::Entropy from the encapsulation draw, got {result:?}"
    );
}

/// `seal_for_with_rng` propagates an entropy failure from the AEAD nonce draw
/// (the second randomness consumed per recipient, after a successful
/// encapsulation) as [`SealError::Entropy`].
#[test]
fn seal_for_with_rng_returns_entropy_error_when_nonce_entropy_fails() {
    let (_dk, ek) = HybridKem::generate_with_rng(&mut CountdownRng::succeeds(1)).unwrap();
    let content_key = [0x43u8; 32];

    // One successful draw (encapsulation's 64-byte fill), then exhausted
    // before the nonce's 12-byte fill.
    let mut rng = CountdownRng::succeeds(1);
    let result = seal_for_with_rng(&content_key, &[ek], &mut rng);
    let Err(SealError::Entropy { location, .. }) = &result else {
        panic!("expected SealError::Entropy from the nonce draw, got {result:?}");
    };
    assert!(
        location.file().ends_with("seal.rs"),
        "the nonce draw's entropy failure must be located in seal.rs, got {}",
        location.file()
    );
}

/// A mid-batch entropy failure in `seal_for_with_rng` emits no partial wrap
/// set: the only two reachable outcomes are a full `Ok(Vec<..>)` covering
/// every recipient or an `Err(SealError::Entropy)` covering none — there is
/// no third state carrying a partially-wrapped batch, because the function
/// returns exactly one `Result` and the fallible draw for recipient 2 is
/// reached only after recipient 1's `WrappedContentKey` has already been
/// pushed into a `Vec` that is dropped, not returned, on the `?` early exit.
#[test]
fn seal_for_with_rng_emits_no_partial_wraps_across_recipients() {
    let (_dk1, ek1) = HybridKem::generate_with_rng(&mut CountdownRng::succeeds(1)).unwrap();
    let (_dk2, ek2) = HybridKem::generate_with_rng(&mut CountdownRng::succeeds(1)).unwrap();
    let content_key = [0x44u8; 32];

    // Exactly enough successful draws for recipient 1's full pipeline
    // (encapsulation + nonce = 2 draws), then exhausted on recipient 2's
    // encapsulation draw.
    let mut rng = CountdownRng::succeeds(2);
    let result = seal_for_with_rng(&content_key, &[ek1, ek2], &mut rng);

    let Err(SealError::Entropy { .. }) = &result else {
        panic!(
            "a mid-batch entropy failure must surface as SealError::Entropy with no wraps, got {result:?}"
        );
    };
}
