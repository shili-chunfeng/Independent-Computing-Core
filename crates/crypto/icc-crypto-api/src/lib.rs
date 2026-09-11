#![no_std]
#![forbid(unsafe_code)]

//! Algorithm-specific cryptographic boundary for ICC Classical Profile v1.
//!
//! This crate intentionally exposes a narrow, typed, no_std-compatible API.
//! It is an internal A1 workspace interface, not an application-facing API.
//! Secret byte wrappers exist only to connect the future KeyStore/Crypto Service
//! to vetted provider implementations. They MUST NOT cross IPC or be serialized.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use zeroize::Zeroize;

pub const SHA256_DIGEST_LEN: usize = 32;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
pub const CHACHA20_POLY1305_KEY_LEN: usize = 32;
pub const CHACHA20_POLY1305_NONCE_LEN: usize = 12;
pub const CHACHA20_POLY1305_TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum CryptoProfileId {
    ClassicalV1 = 0x0001,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum HashAlgorithmId {
    Sha256 = 0x0001,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum KdfAlgorithmId {
    HkdfSha256 = 0x0001,
    Argon2idV13 = 0x0101,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum SignatureAlgorithmId {
    Ed25519 = 0x0001,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum KeyAgreementAlgorithmId {
    X25519 = 0x0001,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AeadAlgorithmId {
    ChaCha20Poly1305 = 0x0001,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidKey,
    InvalidPublicKey,
    InvalidSignature,
    AuthenticationFailed,
    NonContributoryKeyAgreement,
    InvalidOutputLength,
    InvalidInput,
    UnsupportedAlgorithm,
    Internal,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

macro_rules! public_bytes_type {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub const fn to_bytes(self) -> [u8; $len] {
                self.0
            }
        }
    };
}

public_bytes_type!(Digest256, SHA256_DIGEST_LEN);
public_bytes_type!(Ed25519PublicKey, ED25519_PUBLIC_KEY_LEN);
public_bytes_type!(Ed25519Signature, ED25519_SIGNATURE_LEN);
public_bytes_type!(X25519PublicKey, X25519_PUBLIC_KEY_LEN);
public_bytes_type!(Nonce96, CHACHA20_POLY1305_NONCE_LEN);

macro_rules! secret32_type {
    ($name:ident) => {
        pub struct $name([u8; 32]);

        impl $name {
            /// Internal workspace constructor. Do not expose this type over IPC.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Exposes secret bytes only to code already inside the trusted crypto/keystore domain.
            pub fn expose_secret(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }
    };
}

secret32_type!(Ed25519SigningSeed);
secret32_type!(X25519Secret);
secret32_type!(SharedSecret32);
secret32_type!(AeadKey32);
secret32_type!(DerivedKey32);

/// Fixed algorithm profile for the first classical ICC cryptographic baseline.
///
/// Callers MUST perform protocol-level domain separation and canonical framing
/// before calling `ed25519_sign` or `ed25519_verify`. This provider signs the
/// exact byte string it is given and deliberately does not invent a wire format.
pub trait CryptoProviderV1 {
    fn sha256(&self, data: &[u8]) -> Digest256;

    fn hkdf_sha256_32(
        &self,
        salt: &[u8],
        input_key_material: &[u8],
        info: &[u8],
    ) -> Result<DerivedKey32, CryptoError>;

    fn ed25519_public_from_seed(&self, seed: &Ed25519SigningSeed) -> Ed25519PublicKey;

    fn ed25519_sign(
        &self,
        seed: &Ed25519SigningSeed,
        message: &[u8],
    ) -> Result<Ed25519Signature, CryptoError>;

    fn ed25519_verify(
        &self,
        public_key: &Ed25519PublicKey,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), CryptoError>;

    fn x25519_public_from_secret(&self, secret: &X25519Secret) -> X25519PublicKey;

    fn x25519_shared_secret(
        &self,
        secret: &X25519Secret,
        peer_public_key: &X25519PublicKey,
    ) -> Result<SharedSecret32, CryptoError>;

    /// Returns ciphertext || 16-byte Poly1305 tag.
    ///
    /// The 96-bit nonce MUST be unique for each use of a given key. Nonce
    /// allocation is intentionally outside the crypto provider so protocol or
    /// storage layers can enforce their own uniqueness strategy.
    fn chacha20poly1305_seal(
        &self,
        key: &AeadKey32,
        nonce: Nonce96,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn chacha20poly1305_open(
        &self,
        key: &AeadKey32,
        nonce: Nonce96,
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_ids_are_stable_for_v1() {
        assert_eq!(CryptoProfileId::ClassicalV1 as u16, 0x0001);
        assert_eq!(HashAlgorithmId::Sha256 as u16, 0x0001);
        assert_eq!(SignatureAlgorithmId::Ed25519 as u16, 0x0001);
        assert_eq!(KeyAgreementAlgorithmId::X25519 as u16, 0x0001);
        assert_eq!(AeadAlgorithmId::ChaCha20Poly1305 as u16, 0x0001);
    }
}
