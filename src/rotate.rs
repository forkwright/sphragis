//! Key rotation: the typed protocol for actually revoking a device.
//!
//! [`crate::seal::seal_for`] distributes a content key to a recipient set —
//! it has no memory of who has ever recovered that key, so re-running it
//! over a smaller set is recipient-key distribution, not revocation: a
//! recipient who already unsealed the key keeps it regardless of whether a
//! later `seal_for` call addresses them again. This module names and types
//! the operation that actually changes what a removed recipient can read:
//! generate a new content key, publish wraps of it for the retained
//! recipients only, switch to it, and retire the old key.
//!
//! # Protocol stages
//!
//! 1. **New key** — [`generate_content_key`] (or any caller-chosen key,
//!    independent of the one it replaces).
//! 2. **Publish new wraps** — [`PendingRotation::begin`], then
//!    [`PendingRotation::publish_wraps_for`].
//! 3. **Switch the epoch** — [`PublishedWraps::commit`].
//! 4. **Retire the old key** — [`CommittedEpoch::retire_old_key`].
//!
//! The typestate chain (`PendingRotation` -> `PublishedWraps` ->
//! `CommittedEpoch` -> [`RotationComplete`]) makes the ordering a compile
//! error to violate: there is no way to retire the old key before
//! committing the new epoch, and no way to commit an epoch whose wraps were
//! never published.
//!
//! # What this crate re-encrypts (nothing)
//!
//! Sphragis wraps *content keys*; it has never touched the payload data
//! those keys protect, and this module does not change that. Concretely:
//!
//! - **Already-written ciphertext under the old key stays readable by
//!   anyone who holds that key** — including a recipient this rotation just
//!   excluded, if they ever unsealed it before now. Rotation cannot retract
//!   a secret from memory it does not control. It protects data written
//!   *after* the switch, not data written before it.
//! - If the consumer wants old data protected too, they must re-encrypt or
//!   version it under the new content key themselves, against their own
//!   store — this crate has no payload to act on and no opinion on how
//!   theirs is structured. Whether to do that at all is a policy decision
//!   left entirely to the consumer; sphragis's contribution ends at
//!   correctly rotating key material.
//! - "Atomically switch the epoch" (stage 3) is the consumer's own store
//!   transaction, not something sphragis performs — see
//!   [`PublishedWraps::commit`] for exactly what guarantee this crate can
//!   and cannot provide there.
//!
//! forkwright/sphragis#14: this module exists because describing recipient
//! omission as revocation is a security-contract failure at the boundary
//! this crate defines. `tests/rotation.rs` is the adversarial proof: a
//! removed device that already held the old key remains able to read
//! whatever it already decrypted under it, and fails to read data protected
//! under a completed new epoch.

use rand_core::{CryptoRng, OsRng, RngCore};
use snafu::{ResultExt, ensure};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{ContentKeyUnchangedSnafu, EntropySnafu, SealError};
use crate::hybrid::EncapsulationKey;
use crate::seal::{CONTENT_KEY_LEN, WrappedContentKey, seal_for_with_rng};

/// An opaque identifier for a content-key epoch.
///
/// WHY: sphragis holds no persistent state of its own, so it cannot
/// allocate or validate epoch ordering — that bookkeeping belongs to the
/// consumer's own store, however it already tracks "which wrap set is
/// current" (a sequence number, a timestamp, a UUID). `EpochId` exists so
/// the rotation typestate chain carries the consumer's own identifier
/// through every stage instead of discarding it, letting the caller match a
/// completed rotation back to the record they started it for. Sphragis
/// never inspects or orders the wrapped value itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EpochId(pub u64);

/// Generates a fresh content key using the OS CSPRNG — the "new key" stage
/// of a rotation.
///
/// Content keys are otherwise entirely caller-managed: `seal_for`/`unseal`
/// take and return them as bytes, and sphragis never chose them before now.
///
/// WHY: a dedicated generator instead of inlining `OsRng` at each call
/// site — rotation specifically needs a key **provably independent** of
/// the one it replaces, and hand-rolling "32 secure random bytes" per call
/// site is exactly the kind of question a caller should not have to
/// answer for themselves.
///
/// # Errors
///
/// Returns [`SealError::Entropy`] if the OS entropy source fails.
// kanon:ignore RUST/pub-visibility -- re-exported in lib.rs (forkwright/kanon#2382: standalone
// published-crate exemption not yet implemented upstream)
pub fn generate_content_key() -> Result<Zeroizing<[u8; CONTENT_KEY_LEN]>, SealError> {
    generate_content_key_with_rng(&mut OsRng)
}

/// Generates a fresh content key using the given CSPRNG. See
/// [`generate_content_key`].
///
/// # Errors
///
/// Returns [`SealError::Entropy`] if `rng` fails to supply randomness.
// kanon:ignore RUST/pub-visibility -- re-exported in lib.rs (forkwright/kanon#2382: standalone
// published-crate exemption not yet implemented upstream)
pub fn generate_content_key_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<Zeroizing<[u8; CONTENT_KEY_LEN]>, SealError> {
    let mut key = Zeroizing::new([0u8; CONTENT_KEY_LEN]);
    rng.try_fill_bytes(key.as_mut_slice())
        .context(EntropySnafu)?;
    Ok(key)
}

/// Stage 1 of key rotation: the new epoch's content key is chosen, and
/// proven distinct from the epoch it replaces.
///
/// WHY the lifetime: `seal_for` itself takes `content_key` by reference
/// rather than by value, so rotation mirrors that and never makes an
/// internal copy of the plaintext key beyond what the caller already
/// owns — one fewer place a 32-byte secret sits in memory before the
/// caller is ready to erase it.
///
/// See the module documentation's boundary section for what rotating a key
/// does and does not protect.
// kanon:ignore RUST/pub-visibility -- re-exported in lib.rs (forkwright/kanon#2382: standalone
// published-crate exemption not yet implemented upstream)
#[must_use]
pub struct PendingRotation<'k> {
    new_epoch: EpochId,
    new_content_key: &'k [u8; CONTENT_KEY_LEN],
}

impl core::fmt::Debug for PendingRotation<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingRotation")
            .field("new_epoch", &self.new_epoch)
            .finish_non_exhaustive()
    }
}

impl<'k> PendingRotation<'k> {
    /// Begins rotating into `new_epoch` with `new_content_key`.
    ///
    /// `old_content_key` is borrowed only long enough to prove the new key
    /// actually differs from the one it replaces. WHY that check exists:
    /// rotation is supposed to change what secret a removed recipient
    /// needs; a caller who accidentally rotates into the *same* key would
    /// produce a full set of new wraps that decapsulate to a value a
    /// revoked recipient can already decrypt — defeating rotation while
    /// looking, from the wrap set alone, exactly like a real one. The
    /// comparison runs in constant time (`subtle::ConstantTimeEq`) because
    /// both operands are secret key material: a variable-time `==` would
    /// leak where the two keys agree through timing.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::ContentKeyUnchanged`] if `new_content_key` and
    /// `old_content_key` are equal.
    pub fn begin(
        new_epoch: EpochId,
        new_content_key: &'k [u8; CONTENT_KEY_LEN],
        old_content_key: &[u8; CONTENT_KEY_LEN],
    ) -> Result<Self, SealError> {
        let unchanged: bool = new_content_key
            .as_slice()
            .ct_eq(old_content_key.as_slice())
            .into();
        ensure!(!unchanged, ContentKeyUnchangedSnafu);
        Ok(Self {
            new_epoch,
            new_content_key,
        })
    }

    /// Stage 2: publishes wraps of the new content key for the retained
    /// recipient set, using the OS CSPRNG.
    ///
    /// A recipient omitted from `retained_recipients` receives no wrap for
    /// this epoch. WHY that is the weaker property, not revocation on its
    /// own: an omitted recipient who already held a prior epoch's content
    /// key is unaffected by the omission itself. What stops them from
    /// reading data protected under *this* epoch is that they have no path
    /// to the new content key, not that their name is missing from a list.
    ///
    /// # Errors
    ///
    /// Returns a [`SealError`] under the same conditions as
    /// [`seal_for`](crate::seal::seal_for).
    pub fn publish_wraps_for(
        self,
        retained_recipients: &[EncapsulationKey],
    ) -> Result<PublishedWraps, SealError> {
        self.publish_wraps_for_with_rng(retained_recipients, &mut OsRng)
    }

    /// Stage 2 using the given CSPRNG. See
    /// [`publish_wraps_for`](Self::publish_wraps_for).
    ///
    /// # Errors
    ///
    /// Returns a [`SealError`] under the same conditions as
    /// [`seal_for_with_rng`](crate::seal::seal_for_with_rng).
    pub fn publish_wraps_for_with_rng<R: RngCore + CryptoRng>(
        self,
        retained_recipients: &[EncapsulationKey],
        rng: &mut R,
    ) -> Result<PublishedWraps, SealError> {
        let wraps = seal_for_with_rng(self.new_content_key, retained_recipients, rng)?;
        Ok(PublishedWraps {
            epoch: self.new_epoch,
            wraps,
        })
    }
}

/// Stage 3 of key rotation: the new epoch's wraps exist, addressed to the
/// retained recipients, but nothing has acted on them yet.
#[derive(Debug)]
#[must_use]
pub struct PublishedWraps {
    epoch: EpochId,
    wraps: Vec<WrappedContentKey>,
}

impl PublishedWraps {
    /// The epoch these wraps belong to.
    #[must_use]
    pub const fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// The published wraps, one per retained recipient, in the order
    /// `publish_wraps_for` was called with.
    #[must_use]
    pub fn wraps(&self) -> &[WrappedContentKey] {
        &self.wraps
    }

    /// Consumes `self`, returning the published wraps by value.
    #[must_use]
    pub fn into_wraps(self) -> Vec<WrappedContentKey> {
        self.wraps
    }

    /// Stage 4: acknowledges the new epoch is now live.
    ///
    /// WHY this does not itself do anything durable: sphragis holds no
    /// state of its own, so it cannot make the consumer's own store update
    /// atomic — only the consumer's transaction can do that (e.g. writing
    /// `wraps()` as the new live wrap set in the same transaction that
    /// advances a "current epoch" pointer). What this method provides
    /// instead is an ordering guarantee sphragis genuinely can keep: the
    /// type system will not let [`CommittedEpoch::retire_old_key`] run
    /// until this has been called, so the old epoch's key cannot be
    /// destroyed before the caller has at least acknowledged the new one is
    /// durably in place. Call this only after `wraps()` has actually been
    /// persisted as `epoch()`'s live wrap set.
    pub fn commit(self) -> CommittedEpoch {
        CommittedEpoch { epoch: self.epoch }
    }
}

/// Stage 4 result: the new epoch is committed. Only from here can the old
/// epoch's key be retired.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct CommittedEpoch {
    epoch: EpochId,
}

impl CommittedEpoch {
    /// The epoch that is now authoritative.
    #[must_use]
    pub const fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// Stage 5: retires the previous epoch's content key.
    ///
    /// Takes `old_content_key` by value and drops it — [`Zeroizing`] wipes
    /// the backing bytes when it does. This is the only step of the
    /// protocol that touches the old key at all, and it only ever erases
    /// the orchestrating caller's own copy.
    ///
    /// # What this does NOT do
    ///
    /// It cannot reach into a revoked device's memory, disk, or backups.
    /// Any device that unsealed the old content key before this rotation
    /// ran keeps it, and keeps the ability to decrypt anything already
    /// encrypted under it, forever — this method erases sphragis's
    /// caller's own copy, nothing more. See the module documentation's
    /// boundary section.
    pub fn retire_old_key(
        self,
        old_content_key: Zeroizing<[u8; CONTENT_KEY_LEN]>,
    ) -> RotationComplete {
        drop(old_content_key);
        RotationComplete { epoch: self.epoch }
    }
}

/// The full 5-stage protocol has run: a new key was generated, wraps were
/// published for the retained recipients, the new epoch was committed, and
/// the old epoch's key (this caller's copy) was retired.
///
/// Does not by itself prove any *other* holder of the old key has lost
/// access — see the module documentation's boundary section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationComplete {
    /// The epoch that is now authoritative.
    pub epoch: EpochId,
}
