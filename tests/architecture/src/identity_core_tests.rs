use icc_crypto_api::{
    CryptoProviderV1, Ed25519SigningSeed, Ed25519Signature,
};
use icc_crypto_rust::RustCryptoProviderV1;
use icc_error::PlatformError;
use icc_identity_core::{
    AppIdentityStatus, AuthorizationTranscript, DeviceStatus, IdentityCore,
    IdentityError, IdentityKeyBinding, IdentityKeyPurpose, RecoveryAuthority,
    RecoveryPolicy, MAX_APP_IDENTITIES, MAX_PENDING_ENROLLMENTS,
};
use icc_platform_api::SecureRandom;
use icc_types::{
    AppId, IdentityKeyId, RecoveryAuthorityId,
};

const PROVIDER: RustCryptoProviderV1 = RustCryptoProviderV1;

struct BlockRandom {
    next: u8,
}

impl BlockRandom {
    const fn new(next: u8) -> Self {
        Self { next }
    }
}

impl SecureRandom for BlockRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), PlatformError> {
        output.fill(self.next);
        self.next = self.next.wrapping_add(1);
        Ok(())
    }
}

struct FailingRandom;

impl SecureRandom for FailingRandom {
    fn fill(&mut self, _output: &mut [u8]) -> Result<(), PlatformError> {
        Err(PlatformError::EntropyUnavailable)
    }
}

struct ZeroRandom;

impl SecureRandom for ZeroRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), PlatformError> {
        output.fill(0);
        Ok(())
    }
}

fn seed(tag: u8) -> Ed25519SigningSeed {
    Ed25519SigningSeed::from_bytes([tag; 32])
}

fn binding(tag: u8, purpose: IdentityKeyPurpose) -> IdentityKeyBinding {
    binding_with_material(tag, tag, purpose)
}

fn binding_with_material(
    key_id_tag: u8,
    seed_tag: u8,
    purpose: IdentityKeyPurpose,
) -> IdentityKeyBinding {
    IdentityKeyBinding::new(
        IdentityKeyId::from_bytes([key_id_tag; 16]),
        purpose,
        PROVIDER.ed25519_public_from_seed(&seed(seed_tag)),
    )
}

fn authority(tag: u8) -> RecoveryAuthority {
    RecoveryAuthority::new(
        RecoveryAuthorityId::from_bytes([tag; 16]),
        binding(tag, IdentityKeyPurpose::RecoveryAuthorization),
    )
    .expect("test authority must be valid")
}

fn authority_id(tag: u8) -> RecoveryAuthorityId {
    RecoveryAuthorityId::from_bytes([tag; 16])
}

fn standard_policy() -> RecoveryPolicy {
    RecoveryPolicy::new(2, vec![authority(3), authority(4), authority(5)])
        .expect("2-of-3 test policy must be valid")
}

fn bootstrap(random: &mut BlockRandom) -> IdentityCore {
    IdentityCore::bootstrap(
        random,
        binding(1, IdentityKeyPurpose::RootAuthorization),
        binding(2, IdentityKeyPurpose::DeviceAuthentication),
        standard_policy(),
    )
    .expect("test identity must bootstrap")
}

fn sign(tag: u8, transcript: &AuthorizationTranscript) -> Ed25519Signature {
    PROVIDER
        .ed25519_sign(&seed(tag), transcript.as_bytes())
        .expect("test signing must succeed")
}

#[test]
fn bootstrap_rejects_bad_policy_purpose_entropy_and_zero_randomness() {
    assert_eq!(
        RecoveryPolicy::new(1, vec![authority(3), authority(4)]),
        Err(IdentityError::InvalidRecoveryPolicy)
    );
    assert_eq!(
        RecoveryPolicy::new(
            2,
            vec![
                authority(3),
                RecoveryAuthority::new(
                    authority_id(4),
                    binding_with_material(
                        4,
                        3,
                        IdentityKeyPurpose::RecoveryAuthorization,
                    ),
                )
                .unwrap(),
            ],
        ),
        Err(IdentityError::DuplicateBinding)
    );

    let mut random = BlockRandom::new(0x80);
    assert!(matches!(
        IdentityCore::bootstrap(
            &mut random,
            binding(1, IdentityKeyPurpose::AppAuthentication),
            binding(2, IdentityKeyPurpose::DeviceAuthentication),
            standard_policy(),
        ),
        Err(IdentityError::InvalidKeyPurpose)
    ));

    assert!(matches!(
        IdentityCore::bootstrap(
            &mut FailingRandom,
            binding(1, IdentityKeyPurpose::RootAuthorization),
            binding(2, IdentityKeyPurpose::DeviceAuthentication),
            standard_policy(),
        ),
        Err(IdentityError::RandomFailure(
            PlatformError::EntropyUnavailable
        ))
    ));
    assert!(matches!(
        IdentityCore::bootstrap(
            &mut ZeroRandom,
            binding(1, IdentityKeyPurpose::RootAuthorization),
            binding(2, IdentityKeyPurpose::DeviceAuthentication),
            standard_policy(),
        ),
        Err(IdentityError::RandomIdentifierExhausted)
    ));
}

#[test]
fn app_identities_are_pairwise_distinct_and_terminal_revocation_is_enforced() {
    let mut random = BlockRandom::new(0x80);
    let mut core = bootstrap(&mut random);
    let initial_device = core.active_devices()[0].id();
    let app_a = AppId::from_bytes([0xA1; 16]);
    let app_b = AppId::from_bytes([0xB2; 16]);

    let view_a = core
        .create_app_identity(
            &mut random,
            app_a,
            binding(10, IdentityKeyPurpose::AppAuthentication),
        )
        .unwrap();
    let view_b = core
        .create_app_identity(
            &mut random,
            app_b,
            binding(11, IdentityKeyPurpose::AppAuthentication),
        )
        .unwrap();
    assert_ne!(view_a.pseudonym(), view_b.pseudonym());
    assert_ne!(view_a.public_key(), view_b.public_key());
    assert_eq!(core.app_identity_view(app_a), Ok(view_a));

    assert_eq!(
        core.create_app_identity(
            &mut random,
            AppId::from_bytes([0xC3; 16]),
            binding_with_material(12, 10, IdentityKeyPurpose::AppAuthentication),
        ),
        Err(IdentityError::DuplicateBinding)
    );

    let transcript = core
        .app_revocation_transcript(initial_device, app_a)
        .unwrap();
    core.revoke_app_identity(initial_device, app_a, &sign(2, &transcript), &PROVIDER)
        .unwrap();
    assert_eq!(
        core.app_identity_status(app_a),
        Ok(AppIdentityStatus::Revoked)
    );
    assert_eq!(core.app_identity_view(app_a), Err(IdentityError::Revoked));
    assert_eq!(
        core.app_rotation_transcript(
            initial_device,
            app_a,
            binding(12, IdentityKeyPurpose::AppAuthentication),
        ),
        Err(IdentityError::Revoked)
    );
}

#[test]
fn enrollment_requires_a_current_active_device_and_failed_proofs_do_not_mutate() {
    let mut random = BlockRandom::new(0x80);
    let mut core = bootstrap(&mut random);
    let initial_device = core.active_devices()[0].id();
    let pending = core
        .begin_device_enrollment(
            &mut random,
            binding(20, IdentityKeyPurpose::DeviceAuthentication),
        )
        .unwrap();
    let transcript = core
        .device_enrollment_transcript(pending.enrollment_id(), initial_device)
        .unwrap();

    assert_eq!(
        core.approve_device_enrollment(
            pending.enrollment_id(),
            initial_device,
            &sign(99, &transcript),
            &PROVIDER,
        ),
        Err(IdentityError::ProofInvalid)
    );
    assert_eq!(core.active_devices().len(), 1);

    let enrolled = core
        .approve_device_enrollment(
            pending.enrollment_id(),
            initial_device,
            &sign(2, &transcript),
            &PROVIDER,
        )
        .unwrap();
    assert_eq!(enrolled.status(), DeviceStatus::Active);
    assert_eq!(core.active_devices().len(), 2);
    assert_eq!(
        core.approve_device_enrollment(
            pending.enrollment_id(),
            initial_device,
            &sign(2, &transcript),
            &PROVIDER,
        ),
        Err(IdentityError::NotFound)
    );

    let next_pending = core
        .begin_device_enrollment(
            &mut random,
            binding(21, IdentityKeyPurpose::DeviceAuthentication),
        )
        .unwrap();
    let revoked_approver_transcript = core
        .device_enrollment_transcript(next_pending.enrollment_id(), enrolled.id())
        .unwrap();
    let revoked_approver_proof = sign(20, &revoked_approver_transcript);
    let revocation = core
        .device_revocation_transcript(initial_device, enrolled.id())
        .unwrap();
    core.revoke_device(
        initial_device,
        enrolled.id(),
        &sign(2, &revocation),
        &PROVIDER,
    )
    .unwrap();

    assert_eq!(
        core.approve_device_enrollment(
            next_pending.enrollment_id(),
            enrolled.id(),
            &revoked_approver_proof,
            &PROVIDER,
        ),
        Err(IdentityError::Revoked)
    );
    assert_eq!(
        core.device_revocation_transcript(initial_device, initial_device),
        Err(IdentityError::Unauthorized)
    );

    let restored = IdentityCore::restore(core.into_state()).unwrap();
    assert_eq!(
        restored.device_view(enrolled.id()).unwrap().status(),
        DeviceStatus::Revoked
    );
    assert_eq!(restored.active_devices().len(), 1);
}

#[test]
fn device_rotation_rejects_stale_and_cross_action_signatures() {
    let mut random = BlockRandom::new(0x80);
    let mut core = bootstrap(&mut random);
    let device = core.active_devices()[0].id();

    let first_binding = binding(20, IdentityKeyPurpose::DeviceAuthentication);
    let first_transcript = core
        .device_rotation_transcript(device, first_binding)
        .unwrap();
    let first = core
        .rotate_device_key(
            device,
            first_binding,
            &sign(2, &first_transcript),
            &PROVIDER,
        )
        .unwrap();
    assert_eq!(first.generation().get(), 2);

    let stale_binding = binding(21, IdentityKeyPurpose::DeviceAuthentication);
    let stale_transcript = core
        .device_rotation_transcript(device, stale_binding)
        .unwrap();
    let stale_proof = sign(20, &stale_transcript);
    let current_binding = binding(22, IdentityKeyPurpose::DeviceAuthentication);
    let current_transcript = core
        .device_rotation_transcript(device, current_binding)
        .unwrap();
    let current = core
        .rotate_device_key(
            device,
            current_binding,
            &sign(20, &current_transcript),
            &PROVIDER,
        )
        .unwrap();
    assert_eq!(current.generation().get(), 3);
    assert_eq!(
        core.rotate_device_key(device, stale_binding, &stale_proof, &PROVIDER),
        Err(IdentityError::ProofInvalid)
    );
    assert_eq!(core.device_view(device).unwrap().generation().get(), 3);

    let app = AppId::from_bytes([0xA1; 16]);
    core.create_app_identity(
        &mut random,
        app,
        binding(30, IdentityKeyPurpose::AppAuthentication),
    )
    .unwrap();
    let other_action = core.app_revocation_transcript(device, app).unwrap();
    let next_binding = binding(23, IdentityKeyPurpose::DeviceAuthentication);
    assert_eq!(
        core.rotate_device_key(device, next_binding, &sign(22, &other_action), &PROVIDER),
        Err(IdentityError::ProofInvalid)
    );
}

#[test]
fn two_of_three_recovery_rotates_authority_and_contains_old_trust() {
    let mut random = BlockRandom::new(0x80);
    let mut core = bootstrap(&mut random);
    let initial_device = core.active_devices()[0].id();

    let enrollment = core
        .begin_device_enrollment(
            &mut random,
            binding(20, IdentityKeyPurpose::DeviceAuthentication),
        )
        .unwrap();
    let enrollment_transcript = core
        .device_enrollment_transcript(enrollment.enrollment_id(), initial_device)
        .unwrap();
    let second_device = core
        .approve_device_enrollment(
            enrollment.enrollment_id(),
            initial_device,
            &sign(2, &enrollment_transcript),
            &PROVIDER,
        )
        .unwrap()
        .id();

    let app_id = AppId::from_bytes([0xA1; 16]);
    let app_before = core
        .create_app_identity(
            &mut random,
            app_id,
            binding(10, IdentityKeyPurpose::AppAuthentication),
        )
        .unwrap();
    let abandoned_enrollment = core
        .begin_device_enrollment(
            &mut random,
            binding(21, IdentityKeyPurpose::DeviceAuthentication),
        )
        .unwrap();

    let target_policy = core.recovery_policy().clone();
    let challenge = core
        .begin_recovery(
            &mut random,
            binding(50, IdentityKeyPurpose::RootAuthorization),
            binding(51, IdentityKeyPurpose::DeviceAuthentication),
            target_policy,
        )
        .unwrap();
    let first_transcript = core
        .recovery_transcript(challenge.attempt_id(), authority_id(3))
        .unwrap();
    let progress = core
        .approve_recovery(
            challenge.attempt_id(),
            authority_id(3),
            &sign(3, &first_transcript),
            &PROVIDER,
        )
        .unwrap();
    assert_eq!(progress.approvals(), 1);
    assert_eq!(progress.threshold(), 2);
    assert_eq!(
        core.approve_recovery(
            challenge.attempt_id(),
            authority_id(3),
            &sign(3, &first_transcript),
            &PROVIDER,
        ),
        Err(IdentityError::DuplicateApproval)
    );
    assert_eq!(
        core.finalize_recovery(challenge.attempt_id()),
        Err(IdentityError::RecoveryThresholdNotMet)
    );

    let second_transcript = core
        .recovery_transcript(challenge.attempt_id(), authority_id(4))
        .unwrap();
    assert_eq!(
        core.approve_recovery(
            challenge.attempt_id(),
            authority_id(4),
            &sign(5, &second_transcript),
            &PROVIDER,
        ),
        Err(IdentityError::ProofInvalid)
    );
    assert_eq!(
        core.recovery_progress(challenge.attempt_id())
            .unwrap()
            .approvals(),
        1
    );
    core.approve_recovery(
        challenge.attempt_id(),
        authority_id(4),
        &sign(4, &second_transcript),
        &PROVIDER,
    )
    .unwrap();

    let stale_transcript = core
        .recovery_transcript(challenge.attempt_id(), authority_id(5))
        .unwrap();
    let stale_proof = sign(5, &stale_transcript);
    let outcome = core.finalize_recovery(challenge.attempt_id()).unwrap();
    assert_eq!(outcome.root_generation().get(), 2);
    assert_eq!(outcome.recovery_epoch(), 1);
    assert_eq!(outcome.new_device_id(), challenge.new_device_id());
    assert_eq!(core.active_devices().len(), 1);
    assert_eq!(core.active_devices()[0].id(), challenge.new_device_id());
    assert_eq!(
        core.device_view(initial_device).unwrap().status(),
        DeviceStatus::Revoked
    );
    assert_eq!(
        core.device_view(second_device).unwrap().status(),
        DeviceStatus::Revoked
    );
    assert_eq!(
        core.app_identity_status(app_id),
        Ok(AppIdentityStatus::Suspended)
    );
    assert_eq!(
        core.app_identity_view(app_id),
        Err(IdentityError::Suspended)
    );
    assert_eq!(
        core.device_enrollment_transcript(
            abandoned_enrollment.enrollment_id(),
            challenge.new_device_id(),
        ),
        Err(IdentityError::NotFound)
    );
    assert_eq!(
        core.approve_recovery(
            challenge.attempt_id(),
            authority_id(5),
            &stale_proof,
            &PROVIDER,
        ),
        Err(IdentityError::NotFound)
    );

    let mut core = IdentityCore::restore(core.into_state()).unwrap();
    assert_eq!(
        core.device_view(initial_device).unwrap().status(),
        DeviceStatus::Revoked
    );
    assert_eq!(
        core.app_identity_status(app_id),
        Ok(AppIdentityStatus::Suspended)
    );

    let reactivation_binding = binding(11, IdentityKeyPurpose::AppAuthentication);
    let reactivation = core
        .app_rotation_transcript(
            challenge.new_device_id(),
            app_id,
            reactivation_binding,
        )
        .unwrap();
    let app_after = core
        .rotate_app_identity_key(
            challenge.new_device_id(),
            app_id,
            reactivation_binding,
            &sign(51, &reactivation),
            &PROVIDER,
        )
        .unwrap();
    assert_eq!(app_after.pseudonym(), app_before.pseudonym());
    assert_eq!(app_after.generation().get(), 2);

    let next_policy = core.recovery_policy().clone();
    let next_challenge = core
        .begin_recovery(
            &mut random,
            binding(52, IdentityKeyPurpose::RootAuthorization),
            binding(53, IdentityKeyPurpose::DeviceAuthentication),
            next_policy,
        )
        .unwrap();
    assert_eq!(
        core.approve_recovery(
            next_challenge.attempt_id(),
            authority_id(5),
            &stale_proof,
            &PROVIDER,
        ),
        Err(IdentityError::ProofInvalid)
    );
    assert_eq!(
        core.recovery_progress(next_challenge.attempt_id())
            .unwrap()
            .approvals(),
        0
    );
}

#[test]
fn recovery_policy_order_is_canonical_and_transcript_actions_are_separated() {
    let forward = RecoveryPolicy::new(2, vec![authority(3), authority(4), authority(5)]).unwrap();
    let reverse = RecoveryPolicy::new(2, vec![authority(5), authority(4), authority(3)]).unwrap();
    assert_eq!(forward, reverse);
    assert_eq!(forward.authorities()[0].id(), authority_id(3));

    let mut random = BlockRandom::new(0x80);
    let mut core = bootstrap(&mut random);
    let device = core.active_devices()[0].id();
    let rotation = core
        .device_rotation_transcript(
            device,
            binding(20, IdentityKeyPurpose::DeviceAuthentication),
        )
        .unwrap();
    let pending = core
        .begin_device_enrollment(
            &mut random,
            binding(21, IdentityKeyPurpose::DeviceAuthentication),
        )
        .unwrap();
    let enrollment = core
        .device_enrollment_transcript(pending.enrollment_id(), device)
        .unwrap();
    let prefix = b"ICC/identity-core/authorization/v1\0";
    assert!(rotation.as_bytes().starts_with(prefix));
    assert!(enrollment.as_bytes().starts_with(prefix));
    assert_ne!(rotation.as_bytes()[prefix.len()], enrollment.as_bytes()[prefix.len()]);
}

#[test]
fn app_and_pending_enrollment_collections_are_bounded() {
    let mut random = BlockRandom::new(0x80);
    let mut core = bootstrap(&mut random);
    for index in 0..MAX_PENDING_ENROLLMENTS {
        core.begin_device_enrollment(
            &mut random,
            binding(
                20 + u8::try_from(index).unwrap(),
                IdentityKeyPurpose::DeviceAuthentication,
            ),
        )
        .unwrap();
    }
    assert_eq!(
        core.begin_device_enrollment(
            &mut random,
            binding(40, IdentityKeyPurpose::DeviceAuthentication),
        ),
        Err(IdentityError::CapacityExceeded)
    );

    let mut random = BlockRandom::new(0x80);
    let mut core = bootstrap(&mut random);
    for index in 0..MAX_APP_IDENTITIES {
        let tag = 100 + u8::try_from(index).unwrap();
        core.create_app_identity(
            &mut random,
            AppId::from_bytes([u8::try_from(index + 1).unwrap(); 16]),
            binding(tag, IdentityKeyPurpose::AppAuthentication),
        )
        .unwrap();
    }
    assert_eq!(
        core.create_app_identity(
            &mut random,
            AppId::from_bytes([0xF0; 16]),
            binding(230, IdentityKeyPurpose::AppAuthentication),
        ),
        Err(IdentityError::CapacityExceeded)
    );
}
