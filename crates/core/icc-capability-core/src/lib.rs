#![no_std]
#![forbid(unsafe_code)]

//! Pure capability authorization semantics.

use icc_error::DomainError;
use icc_rights::Rights;
use icc_types::{AppId, Generation, MonotonicMs, ObjectId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityGrant {
    pub subject: AppId,
    pub resource: ObjectId,
    pub rights: Rights,
    pub generation: Generation,
    pub expires_at: Option<MonotonicMs>,
    pub delegable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    pub subject: AppId,
    pub resource: ObjectId,
    pub required: Rights,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    Allow,
    Deny(DomainError),
}

pub fn authorize(
    grant: &CapabilityGrant,
    request: &AccessRequest,
    now: MonotonicMs,
    current_generation: Generation,
) -> AuthorizationDecision {
    if grant.subject != request.subject || grant.resource != request.resource {
        return AuthorizationDecision::Deny(DomainError::Denied);
    }

    if grant.generation != current_generation {
        return AuthorizationDecision::Deny(DomainError::Revoked);
    }

    if let Some(expiry) = grant.expires_at
        && now.get() >= expiry.get()
    {
        return AuthorizationDecision::Deny(DomainError::Expired);
    }

    if !grant.rights.contains(request.required) {
        return AuthorizationDecision::Deny(DomainError::Denied);
    }

    AuthorizationDecision::Allow
}

pub fn attenuate(
    parent: &CapabilityGrant,
    requested_rights: Rights,
    requested_expiry: Option<MonotonicMs>,
) -> Result<CapabilityGrant, DomainError> {
    if !parent.delegable {
        return Err(DomainError::Denied);
    }

    let Some(rights) = parent.rights.attenuate(requested_rights) else {
        return Err(DomainError::InvalidScope);
    };

    let expiry = match (parent.expires_at, requested_expiry) {
        (Some(parent_expiry), Some(child_expiry)) if child_expiry.get() <= parent_expiry.get() => {
            Some(child_expiry)
        }
        (Some(_), None) => return Err(DomainError::InvalidScope),
        (Some(_), Some(_)) => return Err(DomainError::InvalidScope),
        (None, child) => child,
    };

    Ok(CapabilityGrant {
        subject: parent.subject,
        resource: parent.resource,
        rights,
        generation: parent.generation,
        expires_at: expiry,
        delegable: false,
    })
}

#[cfg(test)]
mod tests {
    use super::{AccessRequest, AuthorizationDecision, CapabilityGrant, attenuate, authorize};
    use icc_error::DomainError;
    use icc_rights::Rights;
    use icc_types::{AppId, Generation, MonotonicMs, ObjectId};

    const APP: AppId = AppId::from_bytes([1; 16]);
    const OBJECT: ObjectId = ObjectId::from_bytes([2; 16]);

    fn grant() -> CapabilityGrant {
        CapabilityGrant {
            subject: APP,
            resource: OBJECT,
            rights: Rights::READ.union(Rights::DELEGATE),
            generation: Generation::new(7),
            expires_at: Some(MonotonicMs::new(100)),
            delegable: true,
        }
    }

    #[test]
    fn valid_read_is_allowed() {
        let request = AccessRequest {
            subject: APP,
            resource: OBJECT,
            required: Rights::READ,
        };
        assert_eq!(
            authorize(&grant(), &request, MonotonicMs::new(50), Generation::new(7)),
            AuthorizationDecision::Allow
        );
    }

    #[test]
    fn generation_change_revokes_grant() {
        let request = AccessRequest {
            subject: APP,
            resource: OBJECT,
            required: Rights::READ,
        };
        assert_eq!(
            authorize(&grant(), &request, MonotonicMs::new(50), Generation::new(8)),
            AuthorizationDecision::Deny(DomainError::Revoked)
        );
    }

    #[test]
    fn expired_grant_is_denied() {
        let request = AccessRequest {
            subject: APP,
            resource: OBJECT,
            required: Rights::READ,
        };
        assert_eq!(
            authorize(
                &grant(),
                &request,
                MonotonicMs::new(100),
                Generation::new(7)
            ),
            AuthorizationDecision::Deny(DomainError::Expired)
        );
    }

    #[test]
    fn attenuation_cannot_expand_rights_or_lifetime() {
        assert_eq!(
            attenuate(&grant(), Rights::WRITE, Some(MonotonicMs::new(80))),
            Err(DomainError::InvalidScope)
        );
        assert_eq!(
            attenuate(&grant(), Rights::READ, Some(MonotonicMs::new(101))),
            Err(DomainError::InvalidScope)
        );
    }
}
