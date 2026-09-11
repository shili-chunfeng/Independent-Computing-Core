#![forbid(unsafe_code)]

//! Linux implementations of narrow platform Ports.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use icc_error::PlatformError;
use icc_platform_api::{Clock, SecureRandom};
use icc_types::{MonotonicMs, WallTimeMs};

#[derive(Debug)]
pub struct LinuxClock {
    start: Instant,
}

impl LinuxClock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for LinuxClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for LinuxClock {
    fn wall_time_ms(&self) -> Result<WallTimeMs, PlatformError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PlatformError::ClockUnavailable)?;
        let millis = u64::try_from(duration.as_millis()).map_err(|_| PlatformError::ClockUnavailable)?;
        Ok(WallTimeMs::new(millis))
    }

    fn monotonic_ms(&self) -> Result<MonotonicMs, PlatformError> {
        let millis = u64::try_from(self.start.elapsed().as_millis())
            .map_err(|_| PlatformError::ClockUnavailable)?;
        Ok(MonotonicMs::new(millis))
    }
}

#[derive(Debug, Default)]
pub struct LinuxSecureRandom;

impl SecureRandom for LinuxSecureRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), PlatformError> {
        getrandom::fill(output).map_err(|_| PlatformError::EntropyUnavailable)
    }
}
