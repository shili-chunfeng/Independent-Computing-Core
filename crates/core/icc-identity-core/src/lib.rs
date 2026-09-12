#![no_std]
#![forbid(unsafe_code)]

//! Portable identity authority state machine.
//!
//! Phase 3 keeps the root identity inside authority-owned state, gives each App
//! an independent pseudonym and verification key, and requires exact signed
//! transcripts for security-sensitive transitions. This crate owns no private
//! key bytes, persistence format, runtime caller identity, or operating-system
//! effect.
//!
//! App-facing identity views deliberately have no root identity accessor:
//!
//! ```compile_fail
//! fn leak_root(view: &icc_identity_core::AppIdentityView) {
//!     let _ = view.root_identity_id();
//! }
//! ```
//!
//! The state machine itself also provides no public root-domain accessor:
//!
//! ```compile_fail
//! fn leak_root(core: &icc_identity_core::IdentityCore) {
//!     let _ = core.root_domain_id();
//! }
//! ```

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt;

use icc_crypto_api::{CryptoProviderV1, Ed25519PublicKey, Ed25519Signature};
use icc_error::PlatformError;
use icc_platform_api::SecureRandom;
use icc_types::{
    AppId, AppPseudonymId, DeviceId, EnrollmentId, Generation, IdentityDomainId, IdentityKeyId,
    RecoveryAttemptId, RecoveryAuthorityId,
};

pub const MAX_DEVICE_RECORDS: usize = 32;
pub const MAX_PENDING_ENROLLMENTS: usize = 16;
pub const MAX_APP_IDENTITIES: usize = 128;
pub const MIN_RECOVERY_AUTHORITIES: usize = 2;
pub const MAX_RECOVERY_AUTHORITIES: usize = 8;
pub const RANDOM_ID_ATTEMPTS: usize = 8;

const STATE_SCHEMA_VERSION: u16 = 1;
const AUTHORIZATION_PREFIX: &[u8] = b"ICC/identity-core/authorization/v1\0";

const ACTION_DEVICE_ENROLLMENT: u8 = 1;
const ACTION_DEVICE_ROTATION: u8 = 2;
const ACTION_DEVICE_REVOCATION: u8 = 3;
const ACTION_APP_ROTATION: u8 = 4;
const ACTION_APP_REVOCATION: u8 = 5;
const ACTION_RECOVERY_APPROVAL: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IdentityKeyPurpose {
    RootAuthorization = 1,
    RecoveryAuthorization = 2,
    DeviceAuthentication = 3,
    AppAuthentication = 4,
    Communication = 5,
    Financial = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityKeyBinding {
    id: IdentityKeyId,
    purpose: IdentityKeyPurpose,
    public_key: Ed25519PublicKey,
}

impl IdentityKeyBinding {
    pub const fn new(
        id: IdentityKeyId,
        purpose: IdentityKeyPurpose,
        public_key: Ed25519PublicKey,
    ) -> Self {
        Self {
            id,
            purpose,
            public_key,
        }
    }

    pub const fn id(&self) -> IdentityKeyId {
        self.id
    }

    pub const fn purpose(&self) -> IdentityKeyPurpose {
        self.purpose
    }

    pub const fn public_key(&self) -> Ed25519PublicKey {
        self.public_key
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryAuthority {
    id: RecoveryAuthorityId,
    binding: IdentityKeyBinding,
}

impl RecoveryAuthority {
    pub fn new(
        id: RecoveryAuthorityId,
        binding: IdentityKeyBinding,
    ) -> Result<Self, IdentityError> {
        require_nonzero(id.as_bytes())?;
        validate_binding(&binding, IdentityKeyPurpose::RecoveryAuthorization)?;
        Ok(Self { id, binding })
    }

    pub const fn id(&self) -> RecoveryAuthorityId {
        self.id
    }

    pub const fn binding(&self) -> IdentityKeyBinding {
        self.binding
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPolicy {
    threshold: u8,
    authorities: Vec<RecoveryAuthority>,
}

impl RecoveryPolicy {
    pub fn new(
        threshold: u8,
        mut authorities: Vec<RecoveryAuthority>,
    ) -> Result<Self, IdentityError> {
        if authorities.len() < MIN_RECOVERY_AUTHORITIES
            || authorities.len() > MAX_RECOVERY_AUTHORITIES
            || usize::from(threshold) < MIN_RECOVERY_AUTHORITIES
            || usize::from(threshold) > authorities.len()
        {
            return Err(IdentityError::InvalidRecoveryPolicy);
        }

        authorities.sort_by_key(RecoveryAuthority::id);
        for (index, authority) in authorities.iter().enumerate() {
            require_nonzero(authority.id.as_bytes())?;
            validate_binding(
                &authority.binding,
                IdentityKeyPurpose::RecoveryAuthorization,
            )?;
            for other in &authorities[..index] {
                if authority.id == other.id || bindings_overlap(&authority.binding, &other.binding)
                {
                    return Err(IdentityError::DuplicateBinding);
                }
            }
        }

        Ok(Self {
            threshold,
            authorities,
        })
    }

    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn authorities(&self) -> &[RecoveryAuthority] {
        &self.authorities
    }

    fn authority(&self, id: RecoveryAuthorityId) -> Option<&RecoveryAuthority> {
        self.authorities
            .binary_search_by_key(&id, RecoveryAuthority::id)
            .ok()
            .map(|index| &self.authorities[index])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DeviceStatus {
    Active = 1,
    Revoked = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceView {
    id: DeviceId,
    binding: IdentityKeyBinding,
    generation: Generation,
    status: DeviceStatus,
}

impl DeviceView {
    pub const fn id(&self) -> DeviceId {
        self.id
    }

    pub const fn binding(&self) -> IdentityKeyBinding {
        self.binding
    }

    pub const fn generation(&self) -> Generation {
        self.generation
    }

    pub const fn status(&self) -> DeviceStatus {
        self.status
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingDeviceEnrollmentView {
    enrollment_id: EnrollmentId,
    device_id: DeviceId,
    binding: IdentityKeyBinding,
}

impl PendingDeviceEnrollmentView {
    pub const fn enrollment_id(&self) -> EnrollmentId {
        self.enrollment_id
    }

    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub const fn binding(&self) -> IdentityKeyBinding {
        self.binding
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AppIdentityStatus {
    Active = 1,
    Suspended = 2,
    Revoked = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppIdentityView {
    pseudonym: AppPseudonymId,
    public_key: Ed25519PublicKey,
    generation: Generation,
}

impl AppIdentityView {
    pub const fn pseudonym(&self) -> AppPseudonymId {
        self.pseudonym
    }

    pub const fn public_key(&self) -> Ed25519PublicKey {
        self.public_key
    }

    pub const fn generation(&self) -> Generation {
        self.generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationTranscript(Vec<u8>);

impl AuthorizationTranscript {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryChallenge {
    attempt_id: RecoveryAttemptId,
    new_device_id: DeviceId,
}

impl RecoveryChallenge {
    pub const fn attempt_id(&self) -> RecoveryAttemptId {
        self.attempt_id
    }

    pub const fn new_device_id(&self) -> DeviceId {
        self.new_device_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryProgress {
    approvals: u8,
    threshold: u8,
}

impl RecoveryProgress {
    pub const fn approvals(&self) -> u8 {
        self.approvals
    }

    pub const fn threshold(&self) -> u8 {
        self.threshold
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryOutcome {
    root_generation: Generation,
    recovery_epoch: u64,
    new_device_id: DeviceId,
}

impl RecoveryOutcome {
    pub const fn root_generation(&self) -> Generation {
        self.root_generation
    }

    pub const fn recovery_epoch(&self) -> u64 {
        self.recovery_epoch
    }

    pub const fn new_device_id(&self) -> DeviceId {
        self.new_device_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    InvalidInput,
    InvalidKeyPurpose,
    InvalidRecoveryPolicy,
    DuplicateBinding,
    AlreadyExists,
    NotFound,
    InvalidState,
    CapacityExceeded,
    GenerationOverflow,
    RandomFailure(PlatformError),
    RandomIdentifierExhausted,
    ProofInvalid,
    Unauthorized,
    Revoked,
    Suspended,
    RecoveryThresholdNotMet,
    DuplicateApproval,
    CorruptState,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Clone, Copy)]
struct DeviceRecord {
    binding: IdentityKeyBinding,
    generation: Generation,
    status: DeviceStatus,
}

#[derive(Clone, Copy)]
struct PendingEnrollment {
    device_id: DeviceId,
    binding: IdentityKeyBinding,
}

#[derive(Clone, Copy)]
struct AppIdentityRecord {
    pseudonym: AppPseudonymId,
    binding: IdentityKeyBinding,
    generation: Generation,
    status: AppIdentityStatus,
}

struct RecoveryAttempt {
    id: RecoveryAttemptId,
    new_root: IdentityKeyBinding,
    next_root_generation: Generation,
    new_device_id: DeviceId,
    new_device: IdentityKeyBinding,
    target_policy: RecoveryPolicy,
    next_recovery_epoch: u64,
    approvals: BTreeSet<RecoveryAuthorityId>,
}

/// Movable domain state, intentionally without serialization or public fields.
pub struct IdentityState {
    schema_version: u16,
    domain_id: IdentityDomainId,
    root: IdentityKeyBinding,
    root_generation: Generation,
    recovery_epoch: u64,
    recovery_policy: RecoveryPolicy,
    devices: BTreeMap<DeviceId, DeviceRecord>,
    pending_enrollments: BTreeMap<EnrollmentId, PendingEnrollment>,
    apps: BTreeMap<AppId, AppIdentityRecord>,
    recovery_attempt: Option<RecoveryAttempt>,
}

/// Authority-side identity state machine. Do not expose this object to Apps.
pub struct IdentityCore {
    state: IdentityState,
}

impl IdentityCore {
    pub fn bootstrap<R: SecureRandom>(
        random: &mut R,
        root: IdentityKeyBinding,
        initial_device: IdentityKeyBinding,
        recovery_policy: RecoveryPolicy,
    ) -> Result<Self, IdentityError> {
        validate_binding(&root, IdentityKeyPurpose::RootAuthorization)?;
        validate_binding(&initial_device, IdentityKeyPurpose::DeviceAuthentication)?;
        if bindings_overlap(&root, &initial_device) {
            return Err(IdentityError::DuplicateBinding);
        }
        validate_policy(&recovery_policy)?;
        if recovery_policy.authorities.iter().any(|authority| {
            bindings_overlap(&authority.binding, &root)
                || bindings_overlap(&authority.binding, &initial_device)
        }) {
            return Err(IdentityError::DuplicateBinding);
        }

        let domain_id = IdentityDomainId::from_bytes(random_nonzero_id(random, |_| false)?);
        let initial_device_id = DeviceId::from_bytes(random_nonzero_id(random, |_| false)?);
        let mut devices = BTreeMap::new();
        devices.insert(
            initial_device_id,
            DeviceRecord {
                binding: initial_device,
                generation: Generation::new(1),
                status: DeviceStatus::Active,
            },
        );

        let core = Self {
            state: IdentityState {
                schema_version: STATE_SCHEMA_VERSION,
                domain_id,
                root,
                root_generation: Generation::new(1),
                recovery_epoch: 0,
                recovery_policy,
                devices,
                pending_enrollments: BTreeMap::new(),
                apps: BTreeMap::new(),
                recovery_attempt: None,
            },
        };
        core.validate_state()?;
        Ok(core)
    }

    pub fn restore(state: IdentityState) -> Result<Self, IdentityError> {
        let core = Self { state };
        core.validate_state()?;
        Ok(core)
    }

    pub fn into_state(self) -> IdentityState {
        self.state
    }

    pub fn recovery_policy(&self) -> &RecoveryPolicy {
        &self.state.recovery_policy
    }

    pub fn active_devices(&self) -> Vec<DeviceView> {
        self.state
            .devices
            .iter()
            .filter_map(|(id, record)| {
                (record.status == DeviceStatus::Active).then_some(device_view(*id, *record))
            })
            .collect()
    }

    pub fn device_view(&self, id: DeviceId) -> Result<DeviceView, IdentityError> {
        self.state
            .devices
            .get(&id)
            .copied()
            .map(|record| device_view(id, record))
            .ok_or(IdentityError::NotFound)
    }

    pub fn begin_device_enrollment<R: SecureRandom>(
        &mut self,
        random: &mut R,
        binding: IdentityKeyBinding,
    ) -> Result<PendingDeviceEnrollmentView, IdentityError> {
        validate_binding(&binding, IdentityKeyPurpose::DeviceAuthentication)?;
        self.require_binding_unused(&binding)?;
        if self.state.pending_enrollments.len() >= MAX_PENDING_ENROLLMENTS
            || self.state.devices.len() + self.state.pending_enrollments.len()
                >= MAX_DEVICE_RECORDS - 1
        {
            return Err(IdentityError::CapacityExceeded);
        }

        let enrollment_id = EnrollmentId::from_bytes(random_nonzero_id(random, |candidate| {
            self.state
                .pending_enrollments
                .contains_key(&EnrollmentId::from_bytes(*candidate))
        })?);
        let device_id = DeviceId::from_bytes(random_nonzero_id(random, |candidate| {
            let candidate = DeviceId::from_bytes(*candidate);
            self.state.devices.contains_key(&candidate)
                || self
                    .state
                    .pending_enrollments
                    .values()
                    .any(|pending| pending.device_id == candidate)
                || self
                    .state
                    .recovery_attempt
                    .as_ref()
                    .is_some_and(|attempt| attempt.new_device_id == candidate)
        })?);

        self.state
            .pending_enrollments
            .insert(enrollment_id, PendingEnrollment { device_id, binding });
        Ok(PendingDeviceEnrollmentView {
            enrollment_id,
            device_id,
            binding,
        })
    }

    pub fn device_enrollment_transcript(
        &self,
        enrollment_id: EnrollmentId,
        approver_device_id: DeviceId,
    ) -> Result<AuthorizationTranscript, IdentityError> {
        let pending = self
            .state
            .pending_enrollments
            .get(&enrollment_id)
            .copied()
            .ok_or(IdentityError::NotFound)?;
        let approver = self.active_device(approver_device_id)?;

        let mut builder = self.transcript(ACTION_DEVICE_ENROLLMENT);
        builder.bytes(enrollment_id.as_bytes());
        builder.bytes(pending.device_id.as_bytes());
        builder.binding(&pending.binding);
        builder.bytes(approver_device_id.as_bytes());
        builder.u64(approver.generation.get());
        builder.binding(&approver.binding);
        Ok(builder.finish())
    }

    pub fn approve_device_enrollment<P: CryptoProviderV1>(
        &mut self,
        enrollment_id: EnrollmentId,
        approver_device_id: DeviceId,
        signature: &Ed25519Signature,
        provider: &P,
    ) -> Result<DeviceView, IdentityError> {
        let transcript = self.device_enrollment_transcript(enrollment_id, approver_device_id)?;
        let approver = self.active_device(approver_device_id)?;
        verify(provider, &approver.binding, &transcript, signature)?;

        let pending = self
            .state
            .pending_enrollments
            .remove(&enrollment_id)
            .ok_or(IdentityError::InvalidState)?;
        let record = DeviceRecord {
            binding: pending.binding,
            generation: Generation::new(1),
            status: DeviceStatus::Active,
        };
        self.state.devices.insert(pending.device_id, record);
        Ok(device_view(pending.device_id, record))
    }

    pub fn device_rotation_transcript(
        &self,
        device_id: DeviceId,
        new_binding: IdentityKeyBinding,
    ) -> Result<AuthorizationTranscript, IdentityError> {
        validate_binding(&new_binding, IdentityKeyPurpose::DeviceAuthentication)?;
        self.require_binding_unused(&new_binding)?;
        let current = self.active_device(device_id)?;
        let next_generation = next_generation(current.generation)?;

        let mut builder = self.transcript(ACTION_DEVICE_ROTATION);
        builder.bytes(device_id.as_bytes());
        builder.u64(current.generation.get());
        builder.binding(&current.binding);
        builder.u64(next_generation.get());
        builder.binding(&new_binding);
        Ok(builder.finish())
    }

    pub fn rotate_device_key<P: CryptoProviderV1>(
        &mut self,
        device_id: DeviceId,
        new_binding: IdentityKeyBinding,
        signature: &Ed25519Signature,
        provider: &P,
    ) -> Result<DeviceView, IdentityError> {
        let transcript = self.device_rotation_transcript(device_id, new_binding)?;
        let current = self.active_device(device_id)?;
        let next_generation = next_generation(current.generation)?;
        verify(provider, &current.binding, &transcript, signature)?;

        let record = self
            .state
            .devices
            .get_mut(&device_id)
            .ok_or(IdentityError::InvalidState)?;
        record.binding = new_binding;
        record.generation = next_generation;
        Ok(device_view(device_id, *record))
    }

    pub fn device_revocation_transcript(
        &self,
        approver_device_id: DeviceId,
        target_device_id: DeviceId,
    ) -> Result<AuthorizationTranscript, IdentityError> {
        if approver_device_id == target_device_id {
            return Err(IdentityError::Unauthorized);
        }
        let approver = self.active_device(approver_device_id)?;
        let target = self.active_device(target_device_id)?;

        let mut builder = self.transcript(ACTION_DEVICE_REVOCATION);
        builder.bytes(approver_device_id.as_bytes());
        builder.u64(approver.generation.get());
        builder.binding(&approver.binding);
        builder.bytes(target_device_id.as_bytes());
        builder.u64(target.generation.get());
        builder.binding(&target.binding);
        Ok(builder.finish())
    }

    pub fn revoke_device<P: CryptoProviderV1>(
        &mut self,
        approver_device_id: DeviceId,
        target_device_id: DeviceId,
        signature: &Ed25519Signature,
        provider: &P,
    ) -> Result<DeviceView, IdentityError> {
        let transcript = self.device_revocation_transcript(approver_device_id, target_device_id)?;
        let approver = self.active_device(approver_device_id)?;
        verify(provider, &approver.binding, &transcript, signature)?;

        let target = self
            .state
            .devices
            .get_mut(&target_device_id)
            .ok_or(IdentityError::InvalidState)?;
        target.status = DeviceStatus::Revoked;
        Ok(device_view(target_device_id, *target))
    }

    pub fn create_app_identity<R: SecureRandom>(
        &mut self,
        random: &mut R,
        app_id: AppId,
        binding: IdentityKeyBinding,
    ) -> Result<AppIdentityView, IdentityError> {
        require_nonzero(app_id.as_bytes())?;
        validate_binding(&binding, IdentityKeyPurpose::AppAuthentication)?;
        self.require_binding_unused(&binding)?;
        if self.state.apps.contains_key(&app_id) {
            return Err(IdentityError::AlreadyExists);
        }
        if self.state.apps.len() >= MAX_APP_IDENTITIES {
            return Err(IdentityError::CapacityExceeded);
        }

        let pseudonym = AppPseudonymId::from_bytes(random_nonzero_id(random, |candidate| {
            let candidate = AppPseudonymId::from_bytes(*candidate);
            self.state
                .apps
                .values()
                .any(|record| record.pseudonym == candidate)
        })?);
        let record = AppIdentityRecord {
            pseudonym,
            binding,
            generation: Generation::new(1),
            status: AppIdentityStatus::Active,
        };
        self.state.apps.insert(app_id, record);
        Ok(app_view(record))
    }

    pub fn app_identity_view(&self, app_id: AppId) -> Result<AppIdentityView, IdentityError> {
        let record = self
            .state
            .apps
            .get(&app_id)
            .copied()
            .ok_or(IdentityError::NotFound)?;
        match record.status {
            AppIdentityStatus::Active => Ok(app_view(record)),
            AppIdentityStatus::Suspended => Err(IdentityError::Suspended),
            AppIdentityStatus::Revoked => Err(IdentityError::Revoked),
        }
    }

    pub fn app_identity_status(&self, app_id: AppId) -> Result<AppIdentityStatus, IdentityError> {
        self.state
            .apps
            .get(&app_id)
            .map(|record| record.status)
            .ok_or(IdentityError::NotFound)
    }

    pub fn app_rotation_transcript(
        &self,
        approver_device_id: DeviceId,
        app_id: AppId,
        new_binding: IdentityKeyBinding,
    ) -> Result<AuthorizationTranscript, IdentityError> {
        validate_binding(&new_binding, IdentityKeyPurpose::AppAuthentication)?;
        self.require_binding_unused(&new_binding)?;
        let approver = self.active_device(approver_device_id)?;
        let app = self.app_for_transition(app_id)?;
        let next_generation = next_generation(app.generation)?;

        let mut builder = self.transcript(ACTION_APP_ROTATION);
        builder.bytes(approver_device_id.as_bytes());
        builder.u64(approver.generation.get());
        builder.binding(&approver.binding);
        builder.bytes(app_id.as_bytes());
        builder.bytes(app.pseudonym.as_bytes());
        builder.u8(app.status as u8);
        builder.u64(app.generation.get());
        builder.binding(&app.binding);
        builder.u64(next_generation.get());
        builder.binding(&new_binding);
        Ok(builder.finish())
    }

    pub fn rotate_app_identity_key<P: CryptoProviderV1>(
        &mut self,
        approver_device_id: DeviceId,
        app_id: AppId,
        new_binding: IdentityKeyBinding,
        signature: &Ed25519Signature,
        provider: &P,
    ) -> Result<AppIdentityView, IdentityError> {
        let transcript = self.app_rotation_transcript(approver_device_id, app_id, new_binding)?;
        let approver = self.active_device(approver_device_id)?;
        let next_generation = next_generation(self.app_for_transition(app_id)?.generation)?;
        verify(provider, &approver.binding, &transcript, signature)?;

        let app = self
            .state
            .apps
            .get_mut(&app_id)
            .ok_or(IdentityError::InvalidState)?;
        app.binding = new_binding;
        app.generation = next_generation;
        app.status = AppIdentityStatus::Active;
        Ok(app_view(*app))
    }

    pub fn app_revocation_transcript(
        &self,
        approver_device_id: DeviceId,
        app_id: AppId,
    ) -> Result<AuthorizationTranscript, IdentityError> {
        let approver = self.active_device(approver_device_id)?;
        let app = self.app_for_transition(app_id)?;

        let mut builder = self.transcript(ACTION_APP_REVOCATION);
        builder.bytes(approver_device_id.as_bytes());
        builder.u64(approver.generation.get());
        builder.binding(&approver.binding);
        builder.bytes(app_id.as_bytes());
        builder.bytes(app.pseudonym.as_bytes());
        builder.u8(app.status as u8);
        builder.u64(app.generation.get());
        builder.binding(&app.binding);
        Ok(builder.finish())
    }

    pub fn revoke_app_identity<P: CryptoProviderV1>(
        &mut self,
        approver_device_id: DeviceId,
        app_id: AppId,
        signature: &Ed25519Signature,
        provider: &P,
    ) -> Result<(), IdentityError> {
        let transcript = self.app_revocation_transcript(approver_device_id, app_id)?;
        let approver = self.active_device(approver_device_id)?;
        verify(provider, &approver.binding, &transcript, signature)?;

        let app = self
            .state
            .apps
            .get_mut(&app_id)
            .ok_or(IdentityError::InvalidState)?;
        app.status = AppIdentityStatus::Revoked;
        Ok(())
    }

    pub fn begin_recovery<R: SecureRandom>(
        &mut self,
        random: &mut R,
        new_root: IdentityKeyBinding,
        new_device: IdentityKeyBinding,
        target_policy: RecoveryPolicy,
    ) -> Result<RecoveryChallenge, IdentityError> {
        if self.state.recovery_attempt.is_some() {
            return Err(IdentityError::InvalidState);
        }
        validate_binding(&new_root, IdentityKeyPurpose::RootAuthorization)?;
        validate_binding(&new_device, IdentityKeyPurpose::DeviceAuthentication)?;
        self.require_binding_unused(&new_root)?;
        self.require_binding_unused(&new_device)?;
        if bindings_overlap(&new_root, &new_device) {
            return Err(IdentityError::DuplicateBinding);
        }
        self.validate_target_recovery_policy(&target_policy, &new_root, &new_device)?;

        let active_devices = self
            .state
            .devices
            .values()
            .filter(|record| record.status == DeviceStatus::Active)
            .count();
        if active_devices >= MAX_DEVICE_RECORDS {
            return Err(IdentityError::CapacityExceeded);
        }
        let next_root_generation = next_generation(self.state.root_generation)?;
        let next_recovery_epoch = self
            .state
            .recovery_epoch
            .checked_add(1)
            .ok_or(IdentityError::GenerationOverflow)?;

        let attempt_id = RecoveryAttemptId::from_bytes(random_nonzero_id(random, |_| false)?);
        let new_device_id = DeviceId::from_bytes(random_nonzero_id(random, |candidate| {
            let candidate = DeviceId::from_bytes(*candidate);
            self.state.devices.contains_key(&candidate)
                || self
                    .state
                    .pending_enrollments
                    .values()
                    .any(|pending| pending.device_id == candidate)
        })?);
        self.state.recovery_attempt = Some(RecoveryAttempt {
            id: attempt_id,
            new_root,
            next_root_generation,
            new_device_id,
            new_device,
            target_policy,
            next_recovery_epoch,
            approvals: BTreeSet::new(),
        });
        Ok(RecoveryChallenge {
            attempt_id,
            new_device_id,
        })
    }

    pub fn recovery_transcript(
        &self,
        attempt_id: RecoveryAttemptId,
        authority_id: RecoveryAuthorityId,
    ) -> Result<AuthorizationTranscript, IdentityError> {
        let attempt = self.recovery_attempt(attempt_id)?;
        let authority = self
            .state
            .recovery_policy
            .authority(authority_id)
            .ok_or(IdentityError::Unauthorized)?;

        let mut builder = self.transcript(ACTION_RECOVERY_APPROVAL);
        builder.u64(self.state.recovery_epoch);
        builder.bytes(attempt.id.as_bytes());
        builder.bytes(authority.id.as_bytes());
        builder.binding(&authority.binding);
        builder.u64(attempt.next_root_generation.get());
        builder.binding(&attempt.new_root);
        builder.bytes(attempt.new_device_id.as_bytes());
        builder.binding(&attempt.new_device);
        builder.u64(attempt.next_recovery_epoch);
        builder.recovery_policy(&attempt.target_policy);
        Ok(builder.finish())
    }

    pub fn approve_recovery<P: CryptoProviderV1>(
        &mut self,
        attempt_id: RecoveryAttemptId,
        authority_id: RecoveryAuthorityId,
        signature: &Ed25519Signature,
        provider: &P,
    ) -> Result<RecoveryProgress, IdentityError> {
        let attempt = self.recovery_attempt(attempt_id)?;
        if attempt.approvals.contains(&authority_id) {
            return Err(IdentityError::DuplicateApproval);
        }
        let authority = self
            .state
            .recovery_policy
            .authority(authority_id)
            .copied()
            .ok_or(IdentityError::Unauthorized)?;
        let transcript = self.recovery_transcript(attempt_id, authority_id)?;
        verify(provider, &authority.binding, &transcript, signature)?;

        let attempt = self
            .state
            .recovery_attempt
            .as_mut()
            .ok_or(IdentityError::InvalidState)?;
        attempt.approvals.insert(authority_id);
        Ok(RecoveryProgress {
            approvals: attempt.approvals.len() as u8,
            threshold: self.state.recovery_policy.threshold,
        })
    }

    pub fn recovery_progress(
        &self,
        attempt_id: RecoveryAttemptId,
    ) -> Result<RecoveryProgress, IdentityError> {
        let attempt = self.recovery_attempt(attempt_id)?;
        Ok(RecoveryProgress {
            approvals: attempt.approvals.len() as u8,
            threshold: self.state.recovery_policy.threshold,
        })
    }

    pub fn finalize_recovery(
        &mut self,
        attempt_id: RecoveryAttemptId,
    ) -> Result<RecoveryOutcome, IdentityError> {
        let pending = self.recovery_attempt(attempt_id)?;
        if pending.approvals.len() < usize::from(self.state.recovery_policy.threshold) {
            return Err(IdentityError::RecoveryThresholdNotMet);
        }

        let attempt = self
            .state
            .recovery_attempt
            .take()
            .ok_or(IdentityError::InvalidState)?;

        // Already-revoked records are no longer needed to deny authorization:
        // an absent device also fails closed. Retaining devices that were active
        // at this ceremony records their explicit revocation while preserving a
        // bounded slot for future recovery.
        self.state
            .devices
            .retain(|_, record| record.status == DeviceStatus::Active);
        for record in self.state.devices.values_mut() {
            record.status = DeviceStatus::Revoked;
        }
        self.state.devices.insert(
            attempt.new_device_id,
            DeviceRecord {
                binding: attempt.new_device,
                generation: Generation::new(1),
                status: DeviceStatus::Active,
            },
        );
        self.state.pending_enrollments.clear();
        for app in self.state.apps.values_mut() {
            if app.status == AppIdentityStatus::Active {
                app.status = AppIdentityStatus::Suspended;
            }
        }
        self.state.root = attempt.new_root;
        self.state.root_generation = attempt.next_root_generation;
        self.state.recovery_epoch = attempt.next_recovery_epoch;
        self.state.recovery_policy = attempt.target_policy;

        Ok(RecoveryOutcome {
            root_generation: self.state.root_generation,
            recovery_epoch: self.state.recovery_epoch,
            new_device_id: attempt.new_device_id,
        })
    }

    fn active_device(&self, id: DeviceId) -> Result<DeviceRecord, IdentityError> {
        let record = self
            .state
            .devices
            .get(&id)
            .copied()
            .ok_or(IdentityError::NotFound)?;
        match record.status {
            DeviceStatus::Active => Ok(record),
            DeviceStatus::Revoked => Err(IdentityError::Revoked),
        }
    }

    fn app_for_transition(&self, id: AppId) -> Result<AppIdentityRecord, IdentityError> {
        let record = self
            .state
            .apps
            .get(&id)
            .copied()
            .ok_or(IdentityError::NotFound)?;
        if record.status == AppIdentityStatus::Revoked {
            Err(IdentityError::Revoked)
        } else {
            Ok(record)
        }
    }

    fn recovery_attempt(
        &self,
        attempt_id: RecoveryAttemptId,
    ) -> Result<&RecoveryAttempt, IdentityError> {
        let attempt = self
            .state
            .recovery_attempt
            .as_ref()
            .ok_or(IdentityError::NotFound)?;
        if attempt.id != attempt_id {
            return Err(IdentityError::NotFound);
        }
        Ok(attempt)
    }

    fn transcript(&self, action: u8) -> TranscriptBuilder {
        let mut builder = TranscriptBuilder::new(action);
        builder.bytes(self.state.domain_id.as_bytes());
        builder.u64(self.state.root_generation.get());
        builder
    }

    fn require_binding_unused(&self, candidate: &IdentityKeyBinding) -> Result<(), IdentityError> {
        if self.binding_is_in_use(candidate) || self.binding_is_reserved(candidate) {
            Err(IdentityError::DuplicateBinding)
        } else {
            Ok(())
        }
    }

    fn binding_is_reserved(&self, candidate: &IdentityKeyBinding) -> bool {
        self.state
            .recovery_attempt
            .as_ref()
            .is_some_and(|attempt| {
                bindings_overlap(candidate, &attempt.new_root)
                    || bindings_overlap(candidate, &attempt.new_device)
                    || attempt
                        .target_policy
                        .authorities
                        .iter()
                        .any(|authority| bindings_overlap(candidate, &authority.binding))
            })
    }

    fn binding_is_in_use(&self, candidate: &IdentityKeyBinding) -> bool {
        bindings_overlap(candidate, &self.state.root)
            || self
                .state
                .devices
                .values()
                .any(|record| bindings_overlap(candidate, &record.binding))
            || self
                .state
                .pending_enrollments
                .values()
                .any(|record| bindings_overlap(candidate, &record.binding))
            || self
                .state
                .apps
                .values()
                .any(|record| bindings_overlap(candidate, &record.binding))
            || self
                .state
                .recovery_policy
                .authorities
                .iter()
                .any(|authority| bindings_overlap(candidate, &authority.binding))
    }

    fn validate_target_recovery_policy(
        &self,
        policy: &RecoveryPolicy,
        new_root: &IdentityKeyBinding,
        new_device: &IdentityKeyBinding,
    ) -> Result<(), IdentityError> {
        validate_policy(policy)?;
        for authority in &policy.authorities {
            if bindings_overlap(&authority.binding, new_root)
                || bindings_overlap(&authority.binding, new_device)
            {
                return Err(IdentityError::DuplicateBinding);
            }
            if self.binding_is_in_use(&authority.binding) {
                let unchanged_current_authority = self
                    .state
                    .recovery_policy
                    .authority(authority.id)
                    .is_some_and(|current| current.binding == authority.binding);
                if !unchanged_current_authority {
                    return Err(IdentityError::DuplicateBinding);
                }
            }
        }
        Ok(())
    }

    fn validate_state(&self) -> Result<(), IdentityError> {
        let state = &self.state;
        if state.schema_version != STATE_SCHEMA_VERSION
            || state.root_generation.get() == 0
            || state.devices.is_empty()
            || state.devices.len() > MAX_DEVICE_RECORDS
            || state.pending_enrollments.len() > MAX_PENDING_ENROLLMENTS
            || state.apps.len() > MAX_APP_IDENTITIES
        {
            return Err(IdentityError::CorruptState);
        }
        require_nonzero(state.domain_id.as_bytes()).map_err(|_| IdentityError::CorruptState)?;
        validate_binding(&state.root, IdentityKeyPurpose::RootAuthorization)
            .map_err(|_| IdentityError::CorruptState)?;
        validate_policy(&state.recovery_policy).map_err(|_| IdentityError::CorruptState)?;

        let mut key_ids = BTreeSet::new();
        let mut public_keys = Vec::new();
        record_unique_binding(&state.root, &mut key_ids, &mut public_keys)?;

        let mut active_devices = 0_usize;
        for (id, record) in &state.devices {
            require_nonzero(id.as_bytes()).map_err(|_| IdentityError::CorruptState)?;
            if record.generation.get() == 0 {
                return Err(IdentityError::CorruptState);
            }
            validate_binding(&record.binding, IdentityKeyPurpose::DeviceAuthentication)
                .map_err(|_| IdentityError::CorruptState)?;
            record_unique_binding(&record.binding, &mut key_ids, &mut public_keys)?;
            if record.status == DeviceStatus::Active {
                active_devices += 1;
            }
        }
        if active_devices == 0 || active_devices >= MAX_DEVICE_RECORDS {
            return Err(IdentityError::CorruptState);
        }

        let mut pending_device_ids = BTreeSet::new();
        for (enrollment_id, pending) in &state.pending_enrollments {
            require_nonzero(enrollment_id.as_bytes()).map_err(|_| IdentityError::CorruptState)?;
            require_nonzero(pending.device_id.as_bytes())
                .map_err(|_| IdentityError::CorruptState)?;
            if state.devices.contains_key(&pending.device_id)
                || !pending_device_ids.insert(pending.device_id)
            {
                return Err(IdentityError::CorruptState);
            }
            validate_binding(&pending.binding, IdentityKeyPurpose::DeviceAuthentication)
                .map_err(|_| IdentityError::CorruptState)?;
            record_unique_binding(&pending.binding, &mut key_ids, &mut public_keys)?;
        }

        let mut pseudonyms = BTreeSet::new();
        for (app_id, app) in &state.apps {
            require_nonzero(app_id.as_bytes()).map_err(|_| IdentityError::CorruptState)?;
            require_nonzero(app.pseudonym.as_bytes()).map_err(|_| IdentityError::CorruptState)?;
            if app.generation.get() == 0 || !pseudonyms.insert(app.pseudonym) {
                return Err(IdentityError::CorruptState);
            }
            validate_binding(&app.binding, IdentityKeyPurpose::AppAuthentication)
                .map_err(|_| IdentityError::CorruptState)?;
            record_unique_binding(&app.binding, &mut key_ids, &mut public_keys)?;
        }

        for authority in &state.recovery_policy.authorities {
            record_unique_binding(&authority.binding, &mut key_ids, &mut public_keys)?;
        }

        if let Some(attempt) = &state.recovery_attempt {
            require_nonzero(attempt.id.as_bytes()).map_err(|_| IdentityError::CorruptState)?;
            require_nonzero(attempt.new_device_id.as_bytes())
                .map_err(|_| IdentityError::CorruptState)?;
            if attempt.next_root_generation.get()
                != state
                    .root_generation
                    .get()
                    .checked_add(1)
                    .ok_or(IdentityError::CorruptState)?
                || attempt.next_recovery_epoch
                    != state
                        .recovery_epoch
                        .checked_add(1)
                        .ok_or(IdentityError::CorruptState)?
                || state.devices.contains_key(&attempt.new_device_id)
                || pending_device_ids.contains(&attempt.new_device_id)
            {
                return Err(IdentityError::CorruptState);
            }
            validate_binding(&attempt.new_root, IdentityKeyPurpose::RootAuthorization)
                .map_err(|_| IdentityError::CorruptState)?;
            validate_binding(
                &attempt.new_device,
                IdentityKeyPurpose::DeviceAuthentication,
            )
            .map_err(|_| IdentityError::CorruptState)?;
            if self.binding_is_in_use(&attempt.new_root)
                || self.binding_is_in_use(&attempt.new_device)
                || bindings_overlap(&attempt.new_root, &attempt.new_device)
            {
                return Err(IdentityError::CorruptState);
            }
            self.validate_target_recovery_policy(
                &attempt.target_policy,
                &attempt.new_root,
                &attempt.new_device,
            )
            .map_err(|_| IdentityError::CorruptState)?;
            if attempt
                .approvals
                .iter()
                .any(|id| state.recovery_policy.authority(*id).is_none())
            {
                return Err(IdentityError::CorruptState);
            }
        }

        Ok(())
    }
}

fn validate_policy(policy: &RecoveryPolicy) -> Result<(), IdentityError> {
    let reconstructed = RecoveryPolicy::new(policy.threshold, policy.authorities.clone())?;
    if &reconstructed == policy {
        Ok(())
    } else {
        Err(IdentityError::InvalidRecoveryPolicy)
    }
}

fn validate_binding(
    binding: &IdentityKeyBinding,
    expected_purpose: IdentityKeyPurpose,
) -> Result<(), IdentityError> {
    if binding.purpose != expected_purpose {
        return Err(IdentityError::InvalidKeyPurpose);
    }
    require_nonzero(binding.id.as_bytes())?;
    require_nonzero(binding.public_key.as_bytes())?;
    Ok(())
}

fn bindings_overlap(left: &IdentityKeyBinding, right: &IdentityKeyBinding) -> bool {
    left.id == right.id || left.public_key == right.public_key
}

fn record_unique_binding(
    binding: &IdentityKeyBinding,
    ids: &mut BTreeSet<IdentityKeyId>,
    public_keys: &mut Vec<Ed25519PublicKey>,
) -> Result<(), IdentityError> {
    if !ids.insert(binding.id) || public_keys.contains(&binding.public_key) {
        return Err(IdentityError::CorruptState);
    }
    public_keys.push(binding.public_key);
    Ok(())
}

fn require_nonzero<const N: usize>(bytes: &[u8; N]) -> Result<(), IdentityError> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(IdentityError::InvalidInput)
    } else {
        Ok(())
    }
}

fn random_nonzero_id<const N: usize, R: SecureRandom, F: FnMut(&[u8; N]) -> bool>(
    random: &mut R,
    mut collision: F,
) -> Result<[u8; N], IdentityError> {
    for _ in 0..RANDOM_ID_ATTEMPTS {
        let mut bytes = [0_u8; N];
        random
            .fill(&mut bytes)
            .map_err(IdentityError::RandomFailure)?;
        if bytes.iter().any(|byte| *byte != 0) && !collision(&bytes) {
            return Ok(bytes);
        }
    }
    Err(IdentityError::RandomIdentifierExhausted)
}

fn next_generation(current: Generation) -> Result<Generation, IdentityError> {
    current
        .get()
        .checked_add(1)
        .map(Generation::new)
        .ok_or(IdentityError::GenerationOverflow)
}

fn verify<P: CryptoProviderV1>(
    provider: &P,
    binding: &IdentityKeyBinding,
    transcript: &AuthorizationTranscript,
    signature: &Ed25519Signature,
) -> Result<(), IdentityError> {
    provider
        .ed25519_verify(&binding.public_key, transcript.as_bytes(), signature)
        .map_err(|_| IdentityError::ProofInvalid)
}

fn device_view(id: DeviceId, record: DeviceRecord) -> DeviceView {
    DeviceView {
        id,
        binding: record.binding,
        generation: record.generation,
        status: record.status,
    }
}

fn app_view(record: AppIdentityRecord) -> AppIdentityView {
    AppIdentityView {
        pseudonym: record.pseudonym,
        public_key: record.binding.public_key,
        generation: record.generation,
    }
}

struct TranscriptBuilder {
    bytes: Vec<u8>,
}

impl TranscriptBuilder {
    fn new(action: u8) -> Self {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(AUTHORIZATION_PREFIX);
        bytes.push(action);
        Self { bytes }
    }

    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn binding(&mut self, binding: &IdentityKeyBinding) {
        self.bytes(binding.id.as_bytes());
        self.u8(binding.purpose as u8);
        self.bytes(binding.public_key.as_bytes());
    }

    fn recovery_policy(&mut self, policy: &RecoveryPolicy) {
        self.u8(policy.threshold);
        self.u8(policy.authorities.len() as u8);
        for authority in &policy.authorities {
            self.bytes(authority.id.as_bytes());
            self.binding(&authority.binding);
        }
    }

    fn finish(self) -> AuthorizationTranscript {
        AuthorizationTranscript(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRandom(u8);

    impl SecureRandom for FixedRandom {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), PlatformError> {
            output.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    fn test_binding(tag: u8, purpose: IdentityKeyPurpose) -> IdentityKeyBinding {
        IdentityKeyBinding::new(
            IdentityKeyId::from_bytes([tag; 16]),
            purpose,
            Ed25519PublicKey::from_bytes([tag; 32]),
        )
    }

    fn test_policy() -> RecoveryPolicy {
        RecoveryPolicy::new(
            2,
            alloc::vec![
                RecoveryAuthority::new(
                    RecoveryAuthorityId::from_bytes([3; 16]),
                    test_binding(3, IdentityKeyPurpose::RecoveryAuthorization),
                )
                .unwrap(),
                RecoveryAuthority::new(
                    RecoveryAuthorityId::from_bytes([4; 16]),
                    test_binding(4, IdentityKeyPurpose::RecoveryAuthorization),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn checked_generation_rejects_overflow() {
        assert_eq!(
            next_generation(Generation::new(u64::MAX)),
            Err(IdentityError::GenerationOverflow)
        );
    }

    #[test]
    fn restore_rejects_unknown_state_schema() {
        let core = IdentityCore::bootstrap(
            &mut FixedRandom(0x80),
            test_binding(1, IdentityKeyPurpose::RootAuthorization),
            test_binding(2, IdentityKeyPurpose::DeviceAuthentication),
            test_policy(),
        )
        .unwrap();
        let mut state = core.into_state();
        state.schema_version = STATE_SCHEMA_VERSION + 1;

        assert!(matches!(
            IdentityCore::restore(state),
            Err(IdentityError::CorruptState)
        ));
    }
}
