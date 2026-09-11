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
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use icc_crypto_api::{
    AeadKey32, CryptoError, CryptoProviderV1, DerivedKey32, Digest256, Ed25519PublicKey,
    Ed25519Signature, Ed25519SigningSeed, Nonce96, SharedSecret32, X25519PublicKey, X25519Secret,
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
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
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

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hexadecimal test vector"),
        }
    }

    fn hex<const N: usize>(input: &str) -> [u8; N] {
        assert_eq!(input.len(), N * 2, "test vector has the wrong length");
        let bytes = input.as_bytes();
        let mut output = [0_u8; N];
        for (index, value) in output.iter_mut().enumerate() {
            *value = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        }
        output
    }

    #[test]
    fn sha256_known_vector_abc_matches_fips_result() {
        let provider = RustCryptoProviderV1;
        assert_eq!(
            provider.sha256(b"abc").to_bytes(),
            hex::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn hkdf_sha256_rfc5869_case1_matches_first_32_okm_octets() {
        let provider = RustCryptoProviderV1;
        let ikm = [0x0b_u8; 22];
        let salt = hex::<13>("000102030405060708090a0b0c");
        let info = hex::<10>("f0f1f2f3f4f5f6f7f8f9");
        let expected =
            hex::<32>("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");

        let output = provider
            .hkdf_sha256_32(&salt, &ikm, &info)
            .expect("RFC 5869 inputs are valid");
        assert_eq!(output.expose_secret(), &expected);
    }

    #[test]
    fn hkdf_sha256_rfc5869_case3_accepts_zero_length_salt_and_info() {
        let provider = RustCryptoProviderV1;
        let ikm = [0x0b_u8; 22];
        let expected =
            hex::<32>("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d");

        let output = provider
            .hkdf_sha256_32(&[], &ikm, &[])
            .expect("RFC 5869 zero-length salt/info are valid");
        assert_eq!(output.expose_secret(), &expected);
    }

    #[test]
    fn hkdf_sha256_domain_inputs_change_derived_output() {
        let provider = RustCryptoProviderV1;
        let baseline = provider
            .hkdf_sha256_32(b"salt-a", b"ikm-a", b"ICC/test/info-a")
            .unwrap();
        let changed_salt = provider
            .hkdf_sha256_32(b"salt-b", b"ikm-a", b"ICC/test/info-a")
            .unwrap();
        let changed_ikm = provider
            .hkdf_sha256_32(b"salt-a", b"ikm-b", b"ICC/test/info-a")
            .unwrap();
        let changed_info = provider
            .hkdf_sha256_32(b"salt-a", b"ikm-a", b"ICC/test/info-b")
            .unwrap();

        assert_ne!(baseline.expose_secret(), changed_salt.expose_secret());
        assert_ne!(baseline.expose_secret(), changed_ikm.expose_secret());
        assert_ne!(baseline.expose_secret(), changed_info.expose_secret());
    }

    fn rfc8032_test1() -> (Ed25519SigningSeed, Ed25519PublicKey, Ed25519Signature) {
        let seed = Ed25519SigningSeed::from_bytes(hex::<32>(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        let public = Ed25519PublicKey::from_bytes(hex::<32>(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ));
        let signature = Ed25519Signature::from_bytes(hex::<64>(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )));
        (seed, public, signature)
    }

    #[test]
    fn ed25519_rfc8032_test1_matches_public_key_and_signature() {
        let provider = RustCryptoProviderV1;
        let (seed, expected_public, expected_signature) = rfc8032_test1();

        assert_eq!(provider.ed25519_public_from_seed(&seed), expected_public);
        assert_eq!(provider.ed25519_sign(&seed, b"").unwrap(), expected_signature);
        assert_eq!(
            provider.ed25519_verify(&expected_public, b"", &expected_signature),
            Ok(())
        );
    }

    #[test]
    fn ed25519_verify_rejects_tampered_message() {
        let provider = RustCryptoProviderV1;
        let (_, public, signature) = rfc8032_test1();
        assert_eq!(
            provider.ed25519_verify(&public, b"tampered", &signature),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn ed25519_verify_rejects_tampered_signature() {
        let provider = RustCryptoProviderV1;
        let (_, public, signature) = rfc8032_test1();
        let mut tampered = signature.to_bytes();
        tampered[0] ^= 1;
        assert_eq!(
            provider.ed25519_verify(
                &public,
                b"",
                &Ed25519Signature::from_bytes(tampered)
            ),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn ed25519_verify_rejects_noncanonical_public_key() {
        let provider = RustCryptoProviderV1;
        let (_, _, signature) = rfc8032_test1();
        let invalid_public = Ed25519PublicKey::from_bytes([0xff_u8; 32]);
        assert_eq!(
            provider.ed25519_verify(&invalid_public, b"", &signature),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn ed25519_verify_rejects_invalid_signature_encoding_or_value() {
        let provider = RustCryptoProviderV1;
        let (_, public, _) = rfc8032_test1();
        let invalid_signature = Ed25519Signature::from_bytes([0xff_u8; 64]);
        assert_eq!(
            provider.ed25519_verify(&public, b"", &invalid_signature),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn x25519_rfc7748_alice_bob_public_keys_and_shared_secret_match() {
        let provider = RustCryptoProviderV1;
        let alice_secret = X25519Secret::from_bytes(hex::<32>(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let bob_secret = X25519Secret::from_bytes(hex::<32>(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        let expected_alice_public = hex::<32>(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        );
        let expected_bob_public = hex::<32>(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        );
        let expected_shared = hex::<32>(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        );

        let alice_public = provider.x25519_public_from_secret(&alice_secret);
        let bob_public = provider.x25519_public_from_secret(&bob_secret);
        assert_eq!(alice_public.as_bytes(), &expected_alice_public);
        assert_eq!(bob_public.as_bytes(), &expected_bob_public);

        let alice_shared = provider
            .x25519_shared_secret(&alice_secret, &bob_public)
            .unwrap();
        let bob_shared = provider
            .x25519_shared_secret(&bob_secret, &alice_public)
            .unwrap();
        assert_eq!(alice_shared.expose_secret(), &expected_shared);
        assert_eq!(bob_shared.expose_secret(), &expected_shared);
    }

    #[test]
    fn x25519_rejects_all_zero_peer_as_non_contributory() {
        let provider = RustCryptoProviderV1;
        let secret = X25519Secret::from_bytes([0x42_u8; 32]);
        let zero_peer = X25519PublicKey::from_bytes([0_u8; 32]);
        assert_eq!(
            provider.x25519_shared_secret(&secret, &zero_peer),
            Err(CryptoError::NonContributoryKeyAgreement)
        );
    }

    fn rfc8439_aead_material() -> (AeadKey32, Nonce96, [u8; 12], &'static [u8]) {
        let key = AeadKey32::from_bytes(hex::<32>(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        ));
        let nonce = Nonce96::from_bytes(hex::<12>("070000004041424344454647"));
        let aad = hex::<12>("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        (key, nonce, aad, plaintext)
    }

    fn rfc8439_expected_sealed() -> Vec<u8> {
        let ciphertext = hex::<114>(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116"
        ));
        let tag = hex::<16>("1ae10b594f09e26a7e902ecbd0600691");
        let mut sealed = Vec::from(ciphertext);
        sealed.extend_from_slice(&tag);
        sealed
    }

    #[test]
    fn chacha20poly1305_rfc8439_aead_ciphertext_and_tag_match() {
        let provider = RustCryptoProviderV1;
        let (key, nonce, aad, plaintext) = rfc8439_aead_material();
        let sealed = provider
            .chacha20poly1305_seal(&key, nonce, &aad, plaintext)
            .unwrap();
        assert_eq!(sealed, rfc8439_expected_sealed());
        assert_eq!(
            provider
                .chacha20poly1305_open(&key, nonce, &aad, &sealed)
                .unwrap(),
            plaintext
        );
    }

    #[test]
    fn chacha20poly1305_rejects_wrong_key_nonce_and_aad() {
        let provider = RustCryptoProviderV1;
        let (key, nonce, aad, _) = rfc8439_aead_material();
        let sealed = rfc8439_expected_sealed();
        let wrong_key = AeadKey32::from_bytes([0x11_u8; 32]);
        let wrong_nonce = Nonce96::from_bytes(hex::<12>("070000004041424344454646"));

        assert_eq!(
            provider.chacha20poly1305_open(&wrong_key, nonce, &aad, &sealed),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            provider.chacha20poly1305_open(&key, wrong_nonce, &aad, &sealed),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            provider.chacha20poly1305_open(&key, nonce, b"wrong aad", &sealed),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn chacha20poly1305_rejects_tampered_ciphertext_and_tag() {
        let provider = RustCryptoProviderV1;
        let (key, nonce, aad, _) = rfc8439_aead_material();

        let mut ciphertext_tampered = rfc8439_expected_sealed();
        ciphertext_tampered[0] ^= 1;
        assert_eq!(
            provider.chacha20poly1305_open(&key, nonce, &aad, &ciphertext_tampered),
            Err(CryptoError::AuthenticationFailed)
        );

        let mut tag_tampered = rfc8439_expected_sealed();
        let last = tag_tampered.len() - 1;
        tag_tampered[last] ^= 1;
        assert_eq!(
            provider.chacha20poly1305_open(&key, nonce, &aad, &tag_tampered),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn chacha20poly1305_rejects_truncated_authenticated_input() {
        let provider = RustCryptoProviderV1;
        let (key, nonce, aad, _) = rfc8439_aead_material();
        let truncated = [0_u8; 15];
        assert_eq!(
            provider.chacha20poly1305_open(&key, nonce, &aad, &truncated),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn chacha20poly1305_supports_empty_plaintext_and_aad() {
        let provider = RustCryptoProviderV1;
        let key = AeadKey32::from_bytes([0x42_u8; 32]);
        let nonce = Nonce96::from_bytes([0x24_u8; 12]);
        let sealed = provider
            .chacha20poly1305_seal(&key, nonce, &[], &[])
            .unwrap();
        assert_eq!(sealed.len(), 16);
        assert_eq!(
            provider
                .chacha20poly1305_open(&key, nonce, &[], &sealed)
                .unwrap(),
            b""
        );
    }
}
