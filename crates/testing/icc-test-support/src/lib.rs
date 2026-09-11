#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use icc_error::PlatformError;
use icc_platform_api::{Clock, ObjectStore, SecretStore, SecureRandom, SecurityStateStore};
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
