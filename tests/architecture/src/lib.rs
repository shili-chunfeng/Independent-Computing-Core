#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use icc_capability_core::{AccessRequest, AuthorizationDecision, CapabilityGrant, authorize};
    use icc_identity_core::provision_local_identity_id;
    use icc_rights::Rights;
    use icc_test_support::DeterministicRandom;
    use icc_types::{AppId, Generation, MonotonicMs, ObjectId};

    #[test]
    fn identity_core_accepts_a_test_random_adapter() {
        let mut random = DeterministicRandom::new(7);
        let identity =
            provision_local_identity_id(&mut random).expect("deterministic adapter must succeed");
        assert_eq!(identity.id.as_bytes()[0], 7);
        assert_eq!(identity.id.as_bytes()[15], 22);
    }

    #[test]
    fn capability_authorization_is_platform_independent() {
        let app = AppId::from_bytes([1; 16]);
        let object = ObjectId::from_bytes([2; 16]);
        let grant = CapabilityGrant {
            subject: app,
            resource: object,
            rights: Rights::READ,
            generation: Generation::new(3),
            expires_at: None,
            delegable: false,
        };
        let request = AccessRequest {
            subject: app,
            resource: object,
            required: Rights::READ,
        };

        assert_eq!(
            authorize(&grant, &request, MonotonicMs::new(999), Generation::new(3)),
            AuthorizationDecision::Allow
        );
    }
}
