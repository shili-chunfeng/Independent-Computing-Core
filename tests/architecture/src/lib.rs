#![forbid(unsafe_code)]

#[cfg(test)]
mod identity_core_tests;

#[cfg(test)]
mod tests {
    use icc_capability_core::{AccessRequest, AuthorizationDecision, CapabilityGrant, authorize};
    use icc_rights::Rights;
    use icc_types::{AppId, Generation, MonotonicMs, ObjectId};

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
