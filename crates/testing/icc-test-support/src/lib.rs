#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use icc_error::PlatformError;
use icc_platform_api::{
    Clock, KeyStateStore, ObjectStore, SecretStore, SecureRandom, SecurityStateStore,
};
use icc_types::{MonotonicMs, ObjectId, SecretHandle, SecurityStateKey, WallTimeMs};

#[derive(Debug)]
pub struct FakeClock {
    wall: WallTimeMs,
    monotonic: MonotonicMs,
}

impl FakeClock {
    pub const fn new(wall: WallTimeMs, monotonic: MonotonicMs) -> Self {
        Self { wall, monotonic }
    }

    pub fn set_wall(&mut self, value: WallTimeMs) {
        self.wall = value;
    }

    pub fn set_monotonic(&mut self, value: MonotonicMs) {
        self.monotonic = value;
    }
}

impl Clock for FakeClock {
    fn wall_time_ms(&self) -> Result<WallTimeMs, PlatformError> {
        Ok(self.wall)
    }

    fn monotonic_ms(&self) -> Result<MonotonicMs, PlatformError> {
        Ok(self.monotonic)
    }
}

#[derive(Debug)]
pub struct DeterministicRandom {
    next: u8,
}

impl DeterministicRandom {
    pub const fn new(seed: u8) -> Self {
        Self { next: seed }
    }
}

impl SecureRandom for DeterministicRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), PlatformError> {
        for byte in output {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct InMemoryObjectStore {
    values: BTreeMap<ObjectId, Vec<u8>>,
}

impl ObjectStore for InMemoryObjectStore {
    fn get(&self, id: ObjectId) -> Result<Option<Vec<u8>>, PlatformError> {
        Ok(self.values.get(&id).cloned())
    }

    fn put(&mut self, id: ObjectId, value: &[u8]) -> Result<(), PlatformError> {
        self.values.insert(id, value.to_vec());
        Ok(())
    }

    fn delete(&mut self, id: ObjectId) -> Result<(), PlatformError> {
        self.values.remove(&id);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct InMemorySecurityStateStore {
    values: BTreeMap<SecurityStateKey, Vec<u8>>,
}

impl SecurityStateStore for InMemorySecurityStateStore {
    fn get(&self, key: SecurityStateKey) -> Result<Option<Vec<u8>>, PlatformError> {
        Ok(self.values.get(&key).cloned())
    }

    fn put(&mut self, key: SecurityStateKey, value: &[u8]) -> Result<(), PlatformError> {
        self.values.insert(key, value.to_vec());
        Ok(())
    }
}

/// Fault-injectable trusted Port MODEL. Not a durable Linux implementation.
/// Keep the adapter across software KeyStore instances to simulate a restart.
pub struct InMemoryKeyStateStore {
    namespace: [u8; 16],
    snapshot: Option<(u64, Vec<u8>)>,
    trusted_committed: u64,
    reserved_high_water: u64,
    fail_next_reservation: bool,
    fail_before_commit: bool,
    fail_after_commit: bool,
}

impl InMemoryKeyStateStore {
    pub const fn new(namespace: [u8; 16]) -> Self {
        Self {
            namespace,
            snapshot: None,
            trusted_committed: 0,
            reserved_high_water: 0,
            fail_next_reservation: false,
            fail_before_commit: false,
            fail_after_commit: false,
        }
    }

    pub fn fail_next_reservation(&mut self) {
        self.fail_next_reservation = true;
    }

    pub fn fail_before_commit(&mut self) {
        self.fail_before_commit = true;
    }

    pub fn fail_after_commit(&mut self) {
        self.fail_after_commit = true;
    }

    pub fn snapshot_for_test(&self) -> Option<(u64, Vec<u8>)> {
        self.snapshot.clone()
    }

    pub fn replace_snapshot_for_test(&mut self, snapshot: Option<(u64, Vec<u8>)>) {
        self.snapshot = snapshot;
    }
}

impl KeyStateStore for InMemoryKeyStateStore {
    fn namespace(&self) -> Result<[u8; 16], PlatformError> {
        Ok(self.namespace)
    }

    fn load(&self) -> Result<Option<(u64, Vec<u8>)>, PlatformError> {
        match &self.snapshot {
            Some((epoch, bytes)) if *epoch == self.trusted_committed => {
                Ok(Some((*epoch, bytes.clone())))
            }
            None if self.trusted_committed == 0 => Ok(None),
            _ => Err(PlatformError::Corrupt),
        }
    }

    fn reserve_epoch(&mut self, expected_committed: u64) -> Result<u64, PlatformError> {
        if self.fail_next_reservation {
            self.fail_next_reservation = false;
            return Err(PlatformError::Unavailable);
        }
        if expected_committed != self.trusted_committed {
            return Err(PlatformError::Corrupt);
        }
        self.reserved_high_water = self
            .reserved_high_water
            .checked_add(1)
            .ok_or(PlatformError::OutOfSpace)?;
        Ok(self.reserved_high_water)
    }

    fn commit(
        &mut self,
        expected_committed: u64,
        reserved_epoch: u64,
        sealed: &[u8],
    ) -> Result<(), PlatformError> {
        if self.fail_before_commit {
            self.fail_before_commit = false;
            return Err(PlatformError::Unavailable);
        }
        if expected_committed != self.trusted_committed
            || reserved_epoch <= expected_committed
            || reserved_epoch != self.reserved_high_water
        {
            return Err(PlatformError::Corrupt);
        }
        self.snapshot = Some((reserved_epoch, sealed.to_vec()));
        self.trusted_committed = reserved_epoch;
        if self.fail_after_commit {
            self.fail_after_commit = false;
            return Err(PlatformError::Unavailable);
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct FakeSecretStore {
    next: u64,
    live: BTreeMap<u64, u16>,
}

impl SecretStore for FakeSecretStore {
    fn generate_secret(&mut self, bytes: u16) -> Result<SecretHandle, PlatformError> {
        if bytes == 0 {
            return Err(PlatformError::InvalidInput);
        }
        self.next = self.next.checked_add(1).ok_or(PlatformError::Internal)?;
        self.live.insert(self.next, bytes);
        Ok(SecretHandle::from_raw_for_adapter(self.next))
    }

    fn destroy_secret(&mut self, handle: SecretHandle) -> Result<(), PlatformError> {
        if self.live.remove(&handle.raw_for_adapter()).is_some() {
            Ok(())
        } else {
            Err(PlatformError::NotFound)
        }
    }
}
