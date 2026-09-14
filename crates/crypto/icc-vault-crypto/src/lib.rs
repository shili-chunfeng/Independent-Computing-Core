#![no_std]
#![forbid(unsafe_code)]

//! Internal Phase 5 software reference sealer. The injected key must be
//! provisioned by a future authority-owned secret service; this crate does
//! not make the current KeyStore a production Vault key provider.

extern crate alloc;

use alloc::vec::Vec;
use icc_crypto_api::{AeadKey32, CryptoProviderV1, Nonce96};
use icc_error::PlatformError;
use icc_platform_api::VaultSeal;

const MAGIC: &[u8; 8] = b"ICCVLT5\0";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 16 + 8;
const TAG_LEN: usize = 16;
// Also enforced independently by the domain decoder.
const MAX_PLAINTEXT: usize = 1_200_000;
const KEY_INFO: &[u8] = b"ICC/vault/snapshot-key/ClassicalV1/v1";

/// A key is confined to the crypto boundary. No App-facing crate may depend
/// on this implementation, and no normal operation returns the key bytes.
pub struct SoftwareVaultSealer<P: CryptoProviderV1> {
    provider: P,
    root: AeadKey32,
}

impl<P: CryptoProviderV1> SoftwareVaultSealer<P> {
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
    bytes[..4].copy_from_slice(b"IVLT");
    bytes[4..].copy_from_slice(&epoch.to_be_bytes());
    Nonce96::from_bytes(bytes)
}

impl<P: CryptoProviderV1> VaultSeal for SoftwareVaultSealer<P> {
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
        let key = self.key_for(namespace).map_err(|_| PlatformError::Corrupt)?;
        self.provider
            .chacha20poly1305_open(&key, nonce(epoch), &hdr, &sealed[HEADER_LEN..])
            .map_err(|_| PlatformError::Corrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icc_crypto_rust::RustCryptoProviderV1;

    fn sealer(byte: u8) -> SoftwareVaultSealer<RustCryptoProviderV1> {
        SoftwareVaultSealer::new(RustCryptoProviderV1, AeadKey32::from_bytes([byte; 32]))
    }

    #[test]
    fn ciphertext_confidentiality_and_authenticated_context() {
        let namespace = [1; 16];
        let plaintext = b"private title, metadata and content";
        let sealed = sealer(4).seal(namespace, 7, plaintext).unwrap();
        assert!(!sealed.windows(plaintext.len()).any(|w| w == plaintext));
        assert_eq!(sealer(4).open(namespace, 7, &sealed).unwrap(), plaintext);
        assert_eq!(sealer(5).open(namespace, 7, &sealed), Err(PlatformError::Corrupt));
        assert_eq!(sealer(4).open([2; 16], 7, &sealed), Err(PlatformError::Corrupt));
        assert_eq!(sealer(4).open(namespace, 8, &sealed), Err(PlatformError::Corrupt));
        for offset in [0, 8, 12, 26, HEADER_LEN, sealed.len() - 1] {
            let mut altered = sealed.clone();
            altered[offset] ^= 1;
            assert_eq!(sealer(4).open(namespace, 7, &altered), Err(PlatformError::Corrupt));
        }
        assert_eq!(sealer(4).open(namespace, 7, &sealed[..sealed.len() - 1]), Err(PlatformError::Corrupt));
    }
}
