#![no_std]
#![forbid(unsafe_code)]

//! Narrow platform-neutral Ports for external effects.

extern crate alloc;

use alloc::vec::Vec;
use icc_error::PlatformError;
use icc_types::{MonotonicMs, ObjectId, SecretHandle, SecurityStateKey, WallTimeMs};

pub trait Clock {
    fn wall_time_ms(&self) -> Result<WallTimeMs, PlatformError>;
    fn monotonic_ms(&self) -> Result<MonotonicMs, PlatformError>;
}

pub trait SecureRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), PlatformError>;
}

pub trait ObjectStore {
    fn get(&self, id: ObjectId) -> Result<Option<Vec<u8>>, PlatformError>;
    fn put(&mut self, id: ObjectId, value: &[u8]) -> Result<(), PlatformError>;
    fn delete(&mut self, id: ObjectId) -> Result<(), PlatformError>;
}

/// Trusted, authority-owned Vault snapshot store. This is distinct from
/// SecurityStateStore and KeyStateStore. The namespace and committed revision
/// must be durable and immune to rollback, while epoch reservations must never
/// be reused, even after a failed commit or crash. A commit publishes the whole
/// sealed snapshot and trusted revision atomically. An exclusive, non-stealable
/// lease prevents stale concurrent writers; all other methods require it.
/// A generic file or the simple ObjectStore above does not meet this contract.
pub trait VaultStateStore {
    fn acquire_exclusive(&mut self) -> Result<(), PlatformError>;
    fn release_exclusive(&mut self);
    fn namespace(&self) -> Result<[u8; 16], PlatformError>;
    fn load(&self) -> Result<Option<(u64, Vec<u8>)>, PlatformError>;
    fn reserve_epoch(&mut self, expected_committed: u64) -> Result<u64, PlatformError>;
    fn commit(
        &mut self,
        expected_committed: u64,
        reserved_epoch: u64,
        sealed: &[u8],
    ) -> Result<(), PlatformError>;
}

/// Internal cryptographic service boundary. Implementations must authenticate
/// namespace, revision, format and *all* object data and metadata, and keep
/// sealing keys out of the Domain Core and application interfaces.
pub trait VaultSeal {
    fn seal(
        &self,
        namespace: [u8; 16],
        epoch: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, PlatformError>;
    fn open(
        &self,
        namespace: [u8; 16],
        epoch: u64,
        sealed: &[u8],
    ) -> Result<Vec<u8>, PlatformError>;
}

/// Independently provisioned capability security state. The trusted store
/// guarantees a durable, non-rollbackable committed epoch, non-reused epoch
/// reservations, atomic sealed-snapshot commits and a non-stealable exclusive
/// lease held across *every* authorization and operation. A missing snapshot
/// after provisioning is corruption. The test implementation only models this.
pub trait CapabilityStateStore {
    fn acquire_exclusive(&mut self) -> Result<(), PlatformError>;
    fn release_exclusive(&mut self);
    fn namespace(&self) -> Result<[u8; 16], PlatformError>;
    fn load(&self) -> Result<Option<(u64, Vec<u8>)>, PlatformError>;
    fn reserve_epoch(&mut self, expected_committed: u64) -> Result<u64, PlatformError>;
    fn commit(
        &mut self,
        expected_committed: u64,
        reserved_epoch: u64,
        sealed: &[u8],
    ) -> Result<(), PlatformError>;
}

/// Internal cryptographic boundary. The sealer must authenticate format,
/// namespace, revision and the entire snapshot under a capability-specific
/// key and nonce domain, never the Vault or KeyStore domain.
pub trait CapabilitySeal {
    fn seal(&self, namespace: [u8; 16], epoch: u64, plaintext: &[u8])
        -> Result<Vec<u8>, PlatformError>;
    fn open(&self, namespace: [u8; 16], epoch: u64, sealed: &[u8])
        -> Result<Vec<u8>, PlatformError>;
}

/// Trusted authority clock. Unlike a boot-relative clock, values share a
/// stable epoch across restarts and never move backward or wrap. On loss of
/// this guarantee the adapter must fail closed, including for no-expiry grants.
pub trait CapabilityClock {
    fn trusted_time_ms(&self) -> Result<MonotonicMs, PlatformError>;
}

pub trait SecurityStateStore {
    fn get(&self, key: SecurityStateKey) -> Result<Option<Vec<u8>>, PlatformError>;
    fn put(&mut self, key: SecurityStateKey, value: &[u8]) -> Result<(), PlatformError>;
}

/// Authority-side, crash-safe storage for an authenticated KeyStore snapshot.
///
/// Unlike the generic SecurityStateStore, this Port must keep a trusted,
/// non-rollbackable committed epoch and a durable, strictly increasing epoch
/// reservation counter, even if commit fails or the process crashes. A
/// missing snapshot may be returned only for a never-provisioned namespace;
/// restoring an older snapshot, deleting provisioned state, or swapping the
/// namespace must fail closed. A successful commit must atomically publish the
/// complete blob AND advance the trusted committed epoch, after durable sync.
/// A live KeyStore must first acquire an exclusive, non-stealable lease for
/// its namespace and hold it across every sign, verification, and mutation.
/// The lease is released when the adapter is dropped or explicitly relinquished
/// for a handoff. No other adapter for that namespace may successfully acquire
/// a lease while it is held; an expired/stealable TTL is NOT sufficient because
/// a stale instance would retain an in-memory signing seed. All methods below
/// other than acquisition must fail without the lease. Implementations must
/// release it on drop, including after errors. The test adapter models this
/// contract; a normal file or process-local mutex alone cannot meet it.
pub trait KeyStateStore {
    fn acquire_exclusive(&mut self) -> Result<(), PlatformError>;
    fn release_exclusive(&mut self);
    fn namespace(&self) -> Result<[u8; 16], PlatformError>;
    fn load(&self) -> Result<Option<(u64, Vec<u8>)>, PlatformError>;
    fn reserve_epoch(&mut self, expected_committed: u64) -> Result<u64, PlatformError>;
    fn commit(
        &mut self,
        expected_committed: u64,
        reserved_epoch: u64,
        sealed: &[u8],
    ) -> Result<(), PlatformError>;
}

pub trait SecretStore {
    fn generate_secret(&mut self, bytes: u16) -> Result<SecretHandle, PlatformError>;
    fn destroy_secret(&mut self, handle: SecretHandle) -> Result<(), PlatformError>;
}
