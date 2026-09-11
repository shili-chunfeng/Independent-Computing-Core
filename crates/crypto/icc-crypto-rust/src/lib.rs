#![no_std]
#![forbid(unsafe_code)]

//! Vetted Rust implementation of ICC Classical Crypto Profile v1.
//!
//! Cryptographic primitives are provided by RustCrypto and dalek crates.
//! ICC only defines typed composition and policy boundaries; it does not
//! implement new cryptographic primitives.

extern crate alloc;

use alloc::vec::Vec;
use chacha20poly1305::{
    ChaCha20Poly1305,
    KeyInit,
    Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use icc_crypto_api::{
    AeadKey32, CryptoError, CryptoProviderV1, DerivedKey32, Digest256,
    Ed25519PublicKey, Ed25519Signature, Ed25519SigningSeed, Nonce96,
    SharedSecret32, X25519PublicKey, X25519Secret,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as DalekX25519PublicKey, StaticSecret};

#[derive(Clone, Copy, Debug, Default)]
pub struct RustCryptoProviderV1;

impl CryptoProviderV1 for RustCryptoProviderV1 {
    fn sha256(&self, data: &[u8]) -> Digest256 {
        let digest = Sha256::digest(data);
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        Digest256::from_bytes(out)
    }

    fn hkdf_sha256_32(
        &self,
        salt: &[u8],
        input_key_material: &[u8],
        info: &[u8],
    ) -> Result<DerivedKey32, CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(salt), input_key_material);
        let mut out = [0_u8; 32];
        hk.expand(info, &mut out)
            .map_err(|_| CryptoError::InvalidOutputLength)?;
        Ok(DerivedKey32::from_bytes(out))
    }

    fn ed25519_public_from_seed(&self, seed: &Ed25519SigningSeed) -> Ed25519PublicKey {
        let signing_key = SigningKey::from_bytes(seed.expose_secret());
        Ed25519PublicKey::from_bytes(signing_key.verifying_key().to_bytes())
    }

    fn ed25519_sign(
        &self,
        seed: &Ed25519SigningSeed,
        message: &[u8],
    ) -> Result<Ed25519Signature, CryptoError> {
        let signing_key = SigningKey::from_bytes(seed.expose_secret());
        let signature: Signature = signing_key.sign(message);
        Ok(Ed25519Signature::from_bytes(signature.to_bytes()))
    }

    fn ed25519_verify(
        &self,
        public_key: &Ed25519PublicKey,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), CryptoError> {
        let verifying_key = VerifyingKey::from_bytes(public_key.as_bytes())
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(signature.as_bytes());
        verifying_key
            .verify_strict(message, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    fn x25519_public_from_secret(&self, secret: &X25519Secret) -> X25519PublicKey {
        let secret = StaticSecret::from(*secret.expose_secret());
        let public = DalekX25519PublicKey::from(&secret);
        X25519PublicKey::from_bytes(public.to_bytes())
    }

    fn x25519_shared_secret(
        &self,
        secret: &X25519Secret,
        peer_public_key: &X25519PublicKey,
    ) -> Result<SharedSecret32, CryptoError> {
        let secret = StaticSecret::from(*secret.expose_secret());
        let peer = DalekX25519PublicKey::from(*peer_public_key.as_bytes());
        let shared = secret.diffie_hellman(&peer);

        if !shared.was_contributory() {
            return Err(CryptoError::NonContributoryKeyAgreement);
        }

        Ok(SharedSecret32::from_bytes(shared.to_bytes()))
    }

    fn chacha20poly1305_seal(
        &self,
        key: &AeadKey32,
        nonce: Nonce96,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.expose_secret())
            .map_err(|_| CryptoError::InvalidKey)?;
        let nonce = Nonce::from(nonce.to_bytes());
        cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    fn chacha20poly1305_open(
        &self,
        key: &AeadKey32,
        nonce: Nonce96,
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.expose_secret())
            .map_err(|_| CryptoError::InvalidKey)?;
        let nonce = Nonce::from(nonce.to_bytes());
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext_and_tag,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector_abc() {
        let provider = RustCryptoProviderV1;
        assert_eq!(
            provider.sha256(b"abc").to_bytes(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn ed25519_sign_and_verify_round_trip() {
        let provider = RustCryptoProviderV1;
        let seed = Ed25519SigningSeed::from_bytes([7_u8; 32]);
        let public = provider.ed25519_public_from_seed(&seed);
        let signature = provider.ed25519_sign(&seed, b"ICC test message").unwrap();
        assert_eq!(provider.ed25519_verify(&public, b"ICC test message", &signature), Ok(()));
        assert_eq!(
            provider.ed25519_verify(&public, b"tampered", &signature),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn x25519_both_sides_agree() {
        let provider = RustCryptoProviderV1;
        let alice_secret = X25519Secret::from_bytes([0x11_u8; 32]);
        let bob_secret = X25519Secret::from_bytes([0x22_u8; 32]);
        let alice_public = provider.x25519_public_from_secret(&alice_secret);
        let bob_public = provider.x25519_public_from_secret(&bob_secret);
        let alice_shared = provider.x25519_shared_secret(&alice_secret, &bob_public).unwrap();
        let bob_shared = provider.x25519_shared_secret(&bob_secret, &alice_public).unwrap();
        assert_eq!(alice_shared.expose_secret(), bob_shared.expose_secret());
    }

    #[test]
    fn aead_detects_ciphertext_tampering() {
        let provider = RustCryptoProviderV1;
        let key = AeadKey32::from_bytes([0x42_u8; 32]);
        let nonce = Nonce96::from_bytes([0x24_u8; 12]);
        let aad = b"ICC/aead-test/v1";
        let plaintext = b"secret";
        let mut sealed = provider
            .chacha20poly1305_seal(&key, nonce, aad, plaintext)
            .unwrap();
        assert_eq!(
            provider.chacha20poly1305_open(&key, nonce, aad, &sealed).unwrap(),
            plaintext
        );
        sealed[0] ^= 1;
        assert_eq!(
            provider.chacha20poly1305_open(&key, nonce, aad, &sealed),
            Err(CryptoError::AuthenticationFailed)
        );
    }
}
