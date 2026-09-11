#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

//! Narrow platform-neutral Ports for external effects.

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

pub trait SecurityStateStore {
    fn get(&self, key: SecurityStateKey) -> Result<Option<Vec<u8>>, PlatformError>;
    fn put(&mut self, key: SecurityStateKey, value: &[u8]) -> Result<(), PlatformError>;
}

pub trait SecretStore {
    fn generate_secret(&mut self, bytes: u16) -> Result<SecretHandle, PlatformError>;
    fn destroy_secret(&mut self, handle: SecretHandle) -> Result<(), PlatformError>;
}
