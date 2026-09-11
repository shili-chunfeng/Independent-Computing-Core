#![no_std]
#![forbid(unsafe_code)]

//! Minimal identity-domain skeleton.
//!
//! Phase 1 only provisions an opaque local identity identifier. Cryptographic
//! identity keys are deliberately deferred to the dedicated Crypto/Identity phases.

use icc_error::PlatformError;
use icc_platform_api::SecureRandom;
use icc_types::{Generation, IdentityId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityRecord {
    pub id: IdentityId,
    pub generation: Generation,
}

pub fn provision_local_identity_id<R: SecureRandom>(
    random: &mut R,
) -> Result<IdentityRecord, PlatformError> {
    let mut bytes = [0_u8; 16];
    random.fill(&mut bytes)?;

    Ok(IdentityRecord {
        id: IdentityId::from_bytes(bytes),
        generation: Generation::ZERO,
    })
}
