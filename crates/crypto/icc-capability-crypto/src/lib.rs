#![no_std]
#![forbid(unsafe_code)]

//! Internal Phase 6 software reference sealer. The injected key must be
//! provisioned by a future authority-owned secret service; this crate does
//! not make the current KeyStore a production capability security-state key provider.

extern crate alloc;

use alloc::vec::Vec;
use icc_crypto_api::{AeadKey32, CryptoProviderV1, Nonce96};
use icc_error::PlatformError;
use icc_platform_api::CapabilitySeal;

const MAGIC: &[u8; 8] = b"ICCCSEC6";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 16 + 8;
const TAG_LEN: usize = 16;
// Also enforced independently by the domain decoder.
const MAX_PLAINTEXT: usize = 16_384;
const KEY_INFO: &[u8] = b"ICC/capability-security-state/snapshot-key/ClassicalV1/v1";

/// A key is confined to the crypto boundary. No App-facing crate may depend
/// on this implementation, and no normal operation returns the key bytes.
pub struct SoftwareCapabilitySealer<P: CryptoProviderV1> {
    provider: P,
    root: AeadKey32,
}

impl<P: CryptoProviderV1> SoftwareCapabilitySealer<P> {
    pub fn new(provider: P, root: AeadKey32) -> Self {
        Self { provider, root }
    }

    fn key_for(&self, namespace: [u8; 16]) -> Result<AeadKey32, PlatformError> {
        let derived = self
            .provider
            .hkdf_sha256_32(&namespace, self.root.expose_secret(), KEY_INFO)
            .map_err(|_| PlatformError::Internal)?;
        Ok(AeadKey32::from_bytes(*derived.expose_secret()))
    }
}

fn header(namespace: [u8; 16], epoch: u64) -> [u8; HEADER_LEN] {
    let mut result = [0; HEADER_LEN];
    result[..8].copy_from_slice(MAGIC);
    result[8..10].copy_from_slice(&VERSION.to_be_bytes());
    result[10..26].copy_from_slice(&namespace);
    result[26..34].copy_from_slice(&epoch.to_be_bytes());
    result
}

fn nonce(epoch: u64) -> Nonce96 {
    let mut bytes = [0; 12];
    bytes[..4].copy_from_slice(b"ICAP");
    bytes[4..].copy_from_slice(&epoch.to_be_bytes());
    Nonce96::from_bytes(bytes)
}

impl<P: CryptoProviderV1> CapabilitySeal for SoftwareCapabilitySealer<P> {
    fn seal(
        &self,
        namespace: [u8; 16],
        epoch: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, PlatformError> {
        if epoch == 0 || namespace == [0; 16] || plaintext.len() > MAX_PLAINTEXT {
            return Err(PlatformError::InvalidInput);
        }
        let hdr = header(namespace, epoch);
        let key = self.key_for(namespace)?;
        let ciphertext = self
            .provider
            .chacha20poly1305_seal(&key, nonce(epoch), &hdr, plaintext)
            .map_err(|_| PlatformError::Internal)?;
        let mut result = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        result.extend_from_slice(&hdr);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn open(
        &self,
        namespace: [u8; 16],
        epoch: u64,
        sealed: &[u8],
    ) -> Result<Vec<u8>, PlatformError> {
        if epoch == 0
            || namespace == [0; 16]
            || sealed.len() < HEADER_LEN + TAG_LEN
            || sealed.len() > HEADER_LEN + TAG_LEN + MAX_PLAINTEXT
        {
            return Err(PlatformError::Corrupt);
        }
        let hdr = header(namespace, epoch);
        if sealed[..HEADER_LEN] != hdr {
            return Err(PlatformError::Corrupt);
        }
        let key = self
            .key_for(namespace)
            .map_err(|_| PlatformError::Corrupt)?;
        self.provider
            .chacha20poly1305_open(&key, nonce(epoch), &hdr, &sealed[HEADER_LEN..])
            .map_err(|_| PlatformError::Corrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icc_capability_core::authority::{AuthorityError, BoundCaller, CapabilityAuthority, Scope};
    use icc_crypto_rust::RustCryptoProviderV1;
    use icc_rights::Rights;
    use icc_test_support::{
        DeterministicRandom, FakeCapabilityClock, InMemoryCapabilityStateStore,
    };
    use icc_types::{AppId, ObjectId, VaultOwnerId};

    fn sealer(key: u8) -> SoftwareCapabilitySealer<RustCryptoProviderV1> {
        SoftwareCapabilitySealer::new(RustCryptoProviderV1, AeadKey32::from_bytes([key; 32]))
    }

    #[test]
    fn authenticated_envelope_context_and_tamper_detection() {
        let plaintext = b"private grant and revocation metadata";
        let sealed = sealer(4).seal([1; 16], 7, plaintext).unwrap();
        assert!(
            !sealed
                .windows(plaintext.len())
                .any(|bytes| bytes == plaintext)
        );
        assert_eq!(sealer(4).open([1; 16], 7, &sealed).unwrap(), plaintext);
        for (namespace, epoch, key) in [([2; 16], 7, 4), ([1; 16], 8, 4), ([1; 16], 7, 5)] {
            assert_eq!(
                sealer(key).open(namespace, epoch, &sealed),
                Err(PlatformError::Corrupt)
            );
        }
        for offset in [0, 8, 10, 26, HEADER_LEN, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[offset] ^= 1;
            assert_eq!(
                sealer(4).open([1; 16], 7, &tampered),
                Err(PlatformError::Corrupt)
            );
        }
        assert_eq!(
            sealer(4).open([1; 16], 7, &sealed[..sealed.len() - 1]),
            Err(PlatformError::Corrupt)
        );
    }

    #[test]
    fn revoked_child_remains_denied_across_authenticated_reopen() {
        let clock = FakeCapabilityClock::new(100);
        let store = InMemoryCapabilityStateStore::new([9; 16]);
        let mut fork = store.fork_for_test();
        let owner = VaultOwnerId::from_bytes([7; 16]);
        let object = ObjectId::from_bytes([3; 16]);
        let a = BoundCaller::from_trusted_runtime(AppId::from_bytes([1; 16]), [10; 16]);
        let b = BoundCaller::from_trusted_runtime(AppId::from_bytes([2; 16]), [11; 16]);
        let mut authority = CapabilityAuthority::initialize(
            store,
            sealer(5),
            DeterministicRandom::new(22),
            clock.clone(),
        )
        .unwrap();
        let (root, handle) = authority
            .grant_root(
                owner,
                a,
                Scope::VaultOwner(owner),
                Rights::READ.union(Rights::DELEGATE),
                Some(400),
            )
            .unwrap();
        let (child, child_handle) = authority
            .delegate(
                a,
                handle,
                b,
                Scope::VaultObject(owner, object),
                Rights::READ,
                Some(200),
            )
            .unwrap();
        let old_snapshot = fork.snapshot_for_test();
        assert_eq!(
            authority.execute(
                b,
                child_handle,
                Scope::VaultObject(owner, object),
                Rights::READ,
                || 42
            ),
            Ok(42)
        );
        authority.revoke(owner, root).unwrap();
        let (_, ciphertext) = fork.snapshot_for_test().unwrap();
        assert!(
            !ciphertext
                .windows(16)
                .any(|window| window == object.as_bytes())
        );
        drop(authority);
        let mut reopened = CapabilityAuthority::open(
            fork.fork_for_test(),
            sealer(5),
            DeterministicRandom::new(44),
            clock.clone(),
        )
        .unwrap();
        assert_eq!(
            reopened.activate(owner, child, b),
            Err(AuthorityError::Revoked)
        );
        drop(reopened);
        fork.replace_snapshot_for_test(old_snapshot);
        assert!(matches!(
            CapabilityAuthority::open(fork, sealer(5), DeterministicRandom::new(44), clock),
            Err(AuthorityError::Storage(PlatformError::Corrupt))
        ));
    }
}
