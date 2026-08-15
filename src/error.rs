//! Error types for hybrid sealing.

use snafu::Snafu;

/// Errors produced by sealing, unsealing, and key handling.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum SealError {
    /// A key or ciphertext byte slice had the wrong length.
    #[snafu(display("wrong length for {what}: expected {expected}, got {actual}"))]
    WrongLength {
        /// What was being decoded (e.g. "encapsulation key").
        what: &'static str,
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
        /// Source location of the failing check.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// An ML-KEM key or ciphertext failed structural validation.
    #[snafu(display("invalid ML-KEM material: {reason}"))]
    InvalidMlKem {
        /// Failure detail.
        reason: String,
        /// Source location of the failing check.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The entropy source failed to supply randomness for key generation,
    /// encapsulation, or nonce sampling.
    // WHY: `OsRng::fill_bytes` panics on OS-RNG failure (rand_core 0.6
    // `os.rs`); every call site uses the fallible `try_fill_bytes` and
    // surfaces its error here instead, so a transient host entropy failure
    // is a typed, recoverable `Result`, never a process abort.
    #[snafu(display("entropy source failed: {source}"))]
    Entropy {
        /// The underlying RNG failure.
        source: rand_core::Error,
        /// Source location of the failed entropy call.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// HKDF expansion failed (invalid output length request).
    #[snafu(display("HKDF expand failed"))]
    HkdfExpand {
        /// Source location of the failing call.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// AEAD sealing of the content key failed.
    #[snafu(display("content-key AEAD seal failed"))]
    AeadSeal {
        /// Source location of the failing call.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// AEAD opening failed: wrong recipient, tampered ciphertext, or wrong key.
    #[snafu(display("content-key AEAD open failed"))]
    AeadOpen {
        /// Source location of the failing call.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The wrapped content key declared a version this build cannot decode.
    #[snafu(display("unsupported seal version: {version}"))]
    UnsupportedVersion {
        /// The version byte found on the wire.
        version: u8,
        /// Source location of the failing check.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// CBOR (de)serialization of a wrapped content key failed.
    #[snafu(display("wrapped-key serialization failed: {reason}"))]
    Serialization {
        /// Failure detail.
        reason: String,
        /// Source location of the failing call.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// CBOR input exceeded the maximum possible size of a genuine v1
    /// envelope, rejected before any deserialization was attempted.
    #[snafu(display("CBOR input is {size} bytes, exceeding the {max}-byte v1 envelope maximum"))]
    EnvelopeTooLarge {
        /// The size of the rejected input, in bytes.
        size: usize,
        /// The maximum size a genuine v1 envelope can encode to.
        max: usize,
        /// Source location of the failing check.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// CBOR input contained a complete envelope followed by additional
    /// bytes. The parse boundary must be exact: trailing data would let two
    /// distinct byte strings decode to the same envelope.
    #[snafu(display("{trailing} trailing byte(s) followed a complete wrapped content key"))]
    TrailingData {
        /// How many bytes followed the decoded envelope.
        trailing: usize,
        /// Source location of the failing check.
        #[snafu(implicit)]
        location: snafu::Location,
    },
}
