#![no_std]
#![forbid(unsafe_code)]

//! Stable, platform-neutral error categories.

use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    Unavailable,
    PermissionDenied,
    Corrupt,
    OutOfSpace,
    InvalidInput,
    EntropyUnavailable,
    ClockUnavailable,
    NotFound,
    AlreadyExists,
    Internal,
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainError {
    Denied,
    Expired,
    Revoked,
    InvalidScope,
    InvalidState,
    InvalidInput,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
