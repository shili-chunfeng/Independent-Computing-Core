#![no_std]
#![forbid(unsafe_code)]

//! Internal, non-exporting identity KeyStore and software reference backend.
//!
//! This is an A1 interface for an authority-owning service, NOT an App API.
//! A key handle is a reference, not a caller-bound authorization grant. The
//! service must check the actual caller before invoking any method here.
//!
//! There is no private-key export operation:
//! ```compile_fail
//! use icc_keystore::{KeyHandle, KeyOperations};
//! fn export<T: KeyOperations>(store: &T, handle: KeyHandle) {
//!     let _ = store.export_private_key(handle);
//! }
//! ```
//! A returned descriptor does not contain an internal signing seed:
//! ```compile_fail
//! fn leak(descriptor: icc_keystore::KeyDescriptor) {
//!     let _ = descriptor.seed;
//! }
//! ```

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::convert::TryInto;

use icc_crypto_api::{
    AeadKey32, CryptoError, CryptoProviderV1, Ed25519Signature, Ed25519SigningSeed, Nonce96,
};
use icc_error::PlatformError;
use icc_identity_core::{IdentityKeyBinding, IdentityKeyPurpose};
use icc_platform_api::{KeyStateStore, SecureRandom};
use icc_types::IdentityKeyId;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"ICCKS4\0\0";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 16 + 8;
const RECORD_LEN: usize = 16 + 1 + 32;
const MAX_KEYS: usize = 128;
const MAX_SNAPSHOT: usize = HEADER_LEN + 2 + MAX_KEYS * RECORD_LEN + 16;
const MAX_ID_ATTEMPTS: usize = 8;
const HKDF_INFO: &[u8] = b"ICC/keystore/state-seal/ClassicalV1/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyHandle([u8; 16]);

impl KeyHandle {
    /// Handle bits are identifiers, not proof of permission to use a key.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyDescriptor {
    handle: KeyHandle,
    binding: IdentityKeyBinding,
}

impl KeyDescriptor {
    pub const fn handle(&self) -> KeyHandle {
        self.handle
    }

    pub const fn binding(&self) -> IdentityKeyBinding {
        self.binding
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyStoreError {
    Unprovisioned,
    AlreadyProvisioned,
    Corrupt,
    Unavailable,
    NotFound,
    BindingMismatch,
    Capacity,
    Entropy,
    Crypto,
    Storage(PlatformError),
}

/// Backend-neutral, authority-internal identity-key operations.
///
/// Future TPM/SE implementations need only provide this operation boundary;
/// they need not adopt the software snapshot format. This trait does NOT
/// perform caller authorization: an owning service must do so first.
pub trait KeyOperations {
    fn generate(&mut self, purpose: IdentityKeyPurpose) -> Result<KeyDescriptor, KeyStoreError>;
    fn verify_binding(&self, descriptor: KeyDescriptor) -> Result<(), KeyStoreError>;
    fn sign(
        &self,
        descriptor: KeyDescriptor,
        message: &[u8],
    ) -> Result<Ed25519Signature, KeyStoreError>;
    fn rotate(&mut self, current: KeyDescriptor) -> Result<KeyDescriptor, KeyStoreError>;
    fn destroy(&mut self, current: KeyDescriptor) -> Result<(), KeyStoreError>;
}

struct Record {
    purpose: IdentityKeyPurpose,
    seed: Ed25519SigningSeed,
}

/// Software KeyStore. The provider, random source and trusted state Port are
/// injected; their concrete types never enter Domain Core or an App API.
pub struct SoftwareKeyStore<C, S, R> {
    crypto: C,
    store: S,
    random: R,
    root: AeadKey32,
    namespace: [u8; 16],
    committed: u64,
    records: BTreeMap<IdentityKeyId, Record>,
    poisoned: bool,
}

impl<C: CryptoProviderV1, S: KeyStateStore, R: SecureRandom> SoftwareKeyStore<C, S, R> {
    /// Explicit initial provisioning. Never called implicitly on load failure.
    pub fn provision(
        crypto: C,
        store: S,
        random: R,
        root: AeadKey32,
    ) -> Result<Self, KeyStoreError> {
        let namespace = store.namespace().map_err(KeyStoreError::Storage)?;
        if namespace == [0; 16] {
            return Err(KeyStoreError::Corrupt);
        }
        if store.load().map_err(KeyStoreError::Storage)?.is_some() {
            return Err(KeyStoreError::AlreadyProvisioned);
        }
        let mut keystore = Self {
            crypto,
            store,
            random,
            root,
            namespace,
            committed: 0,
            records: BTreeMap::new(),
            poisoned: false,
        };
        keystore.persist(None, None)?;
        Ok(keystore)
    }

    /// Load only a trusted current snapshot; missing state is never recreated.
    pub fn open(crypto: C, store: S, random: R, root: AeadKey32) -> Result<Self, KeyStoreError> {
        let namespace = store.namespace().map_err(KeyStoreError::Storage)?;
        if namespace == [0; 16] {
            return Err(KeyStoreError::Corrupt);
        }
        let (epoch, snapshot) = store
            .load()
            .map_err(KeyStoreError::Storage)?
            .ok_or(KeyStoreError::Unprovisioned)?;
        if epoch == 0 {
            return Err(KeyStoreError::Corrupt);
        }
        let records = decode(&crypto, &root, namespace, epoch, &snapshot)?;
        Ok(Self {
            crypto,
            store,
            random,
            root,
            namespace,
            committed: epoch,
            records,
            poisoned: false,
        })
    }

    /// Transfer only the storage adapter out for an explicit restart test.
    /// The sealing key and all owned signing seeds are dropped.
    pub fn into_storage(self) -> S {
        self.store
    }

    fn current_record(&self, descriptor: KeyDescriptor) -> Result<&Record, KeyStoreError> {
        if self.poisoned {
            return Err(KeyStoreError::Unavailable);
        }
        if descriptor.handle.as_bytes() != descriptor.binding.id().as_bytes() {
            return Err(KeyStoreError::BindingMismatch);
        }
        let record = self
            .records
            .get(&descriptor.binding.id())
            .ok_or(KeyStoreError::NotFound)?;
        if record.purpose != descriptor.binding.purpose()
            || self.crypto.ed25519_public_from_seed(&record.seed) != descriptor.binding.public_key()
        {
            return Err(KeyStoreError::BindingMismatch);
        }
        Ok(record)
    }

    fn new_record(&mut self, purpose: IdentityKeyPurpose) -> Result<(IdentityKeyId, Record), KeyStoreError> {
        if self.poisoned {
            return Err(KeyStoreError::Unavailable);
        }
        if self.records.len() >= MAX_KEYS {
            return Err(KeyStoreError::Capacity);
        }
        let mut id_bytes = [0_u8; 16];
        let mut found = None;
        for _ in 0..MAX_ID_ATTEMPTS {
            if self.random.fill(&mut id_bytes).is_err() {
                id_bytes.zeroize();
                return Err(KeyStoreError::Entropy);
            }
            let id = IdentityKeyId::from_bytes(id_bytes);
            if id_bytes != [0; 16] && !self.records.contains_key(&id) {
                found = Some(id);
                break;
            }
        }
        id_bytes.zeroize();
        let id = found.ok_or(KeyStoreError::Entropy)?;
        let mut seed_bytes = [0_u8; 32];
        if self.random.fill(&mut seed_bytes).is_err() || seed_bytes == [0; 32] {
            seed_bytes.zeroize();
            return Err(KeyStoreError::Entropy);
        }
        let seed = Ed25519SigningSeed::from_bytes(seed_bytes);
        seed_bytes.zeroize();
        Ok((id, Record { purpose, seed }))
    }

    fn descriptor(&self, id: IdentityKeyId, record: &Record) -> KeyDescriptor {
        KeyDescriptor {
            handle: KeyHandle::from_bytes(*id.as_bytes()),
            binding: IdentityKeyBinding::new(
                id,
                record.purpose,
                self.crypto.ed25519_public_from_seed(&record.seed),
            ),
        }
    }

    /// Atomically write the next complete state, excluding a removed/rotated
    /// key and optionally including a new one. Never mutate live records here.
    fn persist(
        &mut self,
        excluded: Option<IdentityKeyId>,
        included: Option<(IdentityKeyId, &Record)>,
    ) -> Result<(), KeyStoreError> {
        if self.poisoned {
            return Err(KeyStoreError::Unavailable);
        }
        // Once an external effect starts, any error may represent an ambiguous
        // state. Poison this instance and require a fresh trusted load.
        self.poisoned = true;
        let reserved = self
            .store
            .reserve_epoch(self.committed)
            .map_err(KeyStoreError::Storage)?;
        if reserved <= self.committed {
            return Err(KeyStoreError::Corrupt);
        }
        let count = self.records.len() - usize::from(excluded.is_some())
            + usize::from(included.is_some());
        if count > MAX_KEYS {
            return Err(KeyStoreError::Capacity);
        }
        let mut plaintext = Vec::with_capacity(2 + count * RECORD_LEN);
        plaintext.extend_from_slice(&(count as u16).to_be_bytes());
        for (&id, record) in &self.records {
            if Some(id) != excluded {
                append_record(&mut plaintext, id, record);
            }
        }
        if let Some((id, record)) = included {
            append_record(&mut plaintext, id, record);
        }
        let result = seal(&self.crypto, &self.root, self.namespace, reserved, &plaintext);
        plaintext.zeroize();
        let sealed = result?;
        self.store
            .commit(self.committed, reserved, &sealed)
            .map_err(KeyStoreError::Storage)?;
        self.committed = reserved;
        self.poisoned = false;
        Ok(())
    }
}

impl<C: CryptoProviderV1, S: KeyStateStore, R: SecureRandom> KeyOperations
    for SoftwareKeyStore<C, S, R>
{
    fn generate(&mut self, purpose: IdentityKeyPurpose) -> Result<KeyDescriptor, KeyStoreError> {
        let (id, record) = self.new_record(purpose)?;
        self.persist(None, Some((id, &record)))?;
        let descriptor = self.descriptor(id, &record);
        self.records.insert(id, record);
        Ok(descriptor)
    }

    fn verify_binding(&self, descriptor: KeyDescriptor) -> Result<(), KeyStoreError> {
        self.current_record(descriptor).map(|_| ())
    }

    fn sign(
        &self,
        descriptor: KeyDescriptor,
        message: &[u8],
    ) -> Result<Ed25519Signature, KeyStoreError> {
        let record = self.current_record(descriptor)?;
        self.crypto
            .ed25519_sign(&record.seed, message)
            .map_err(|_| KeyStoreError::Crypto)
    }

    fn rotate(&mut self, current: KeyDescriptor) -> Result<KeyDescriptor, KeyStoreError> {
        self.current_record(current)?;
        let (id, record) = self.new_record(current.binding.purpose())?;
        self.persist(Some(current.binding.id()), Some((id, &record)))?;
        self.records.remove(&current.binding.id());
        let descriptor = self.descriptor(id, &record);
        self.records.insert(id, record);
        Ok(descriptor)
    }

    fn destroy(&mut self, current: KeyDescriptor) -> Result<(), KeyStoreError> {
        self.current_record(current)?;
        self.persist(Some(current.binding.id()), None)?;
        self.records.remove(&current.binding.id());
        Ok(())
    }
}

fn append_record(out: &mut Vec<u8>, id: IdentityKeyId, record: &Record) {
    out.extend_from_slice(id.as_bytes());
    out.push(record.purpose as u8);
    out.extend_from_slice(record.seed.expose_secret());
}

fn purpose_from_byte(byte: u8) -> Option<IdentityKeyPurpose> {
    Some(match byte {
        1 => IdentityKeyPurpose::RootAuthorization,
        2 => IdentityKeyPurpose::RecoveryAuthorization,
        3 => IdentityKeyPurpose::DeviceAuthentication,
        4 => IdentityKeyPurpose::AppAuthentication,
        5 => IdentityKeyPurpose::Communication,
        6 => IdentityKeyPurpose::Financial,
        _ => return None,
    })
}

fn header(namespace: [u8; 16], epoch: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&namespace);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes
}

fn sealing_key<C: CryptoProviderV1>(
    crypto: &C,
    root: &AeadKey32,
    namespace: &[u8; 16],
) -> Result<AeadKey32, KeyStoreError> {
    let derived = crypto
        .hkdf_sha256_32(namespace, root.expose_secret(), HKDF_INFO)
        .map_err(|_| KeyStoreError::Crypto)?;
    let mut bytes = *derived.expose_secret();
    let key = AeadKey32::from_bytes(bytes);
    bytes.zeroize();
    Ok(key)
}

fn nonce(epoch: u64) -> Nonce96 {
    let mut bytes = [0_u8; 12];
    bytes[..4].copy_from_slice(b"KS4\0");
    bytes[4..].copy_from_slice(&epoch.to_be_bytes());
    Nonce96::from_bytes(bytes)
}

fn seal<C: CryptoProviderV1>(
    crypto: &C,
    root: &AeadKey32,
    namespace: [u8; 16],
    epoch: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, KeyStoreError> {
    let aad = header(namespace, epoch);
    let key = sealing_key(crypto, root, &namespace)?;
    let ciphertext = crypto
        .chacha20poly1305_seal(&key, nonce(epoch), &aad, plaintext)
        .map_err(|_| KeyStoreError::Crypto)?;
    let mut result = aad;
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decode<C: CryptoProviderV1>(
    crypto: &C,
    root: &AeadKey32,
    namespace: [u8; 16],
    epoch: u64,
    snapshot: &[u8],
) -> Result<BTreeMap<IdentityKeyId, Record>, KeyStoreError> {
    if snapshot.len() < HEADER_LEN + 2 + 16 || snapshot.len() > MAX_SNAPSHOT {
        return Err(KeyStoreError::Corrupt);
    }
    if snapshot[..HEADER_LEN] != header(namespace, epoch) {
        return Err(KeyStoreError::Corrupt);
    }
    let key = sealing_key(crypto, root, &namespace)?;
    let mut plaintext = crypto
        .chacha20poly1305_open(&key, nonce(epoch), &snapshot[..HEADER_LEN], &snapshot[HEADER_LEN..])
        .map_err(|error| match error {
            CryptoError::AuthenticationFailed => KeyStoreError::Corrupt,
            _ => KeyStoreError::Crypto,
        })?;
    let result = parse_records(&plaintext);
    plaintext.zeroize();
    result
}

fn parse_records(plaintext: &[u8]) -> Result<BTreeMap<IdentityKeyId, Record>, KeyStoreError> {
    if plaintext.len() < 2 {
        return Err(KeyStoreError::Corrupt);
    }
    let count = usize::from(u16::from_be_bytes([plaintext[0], plaintext[1]]));
    if count > MAX_KEYS || plaintext.len() != 2 + count * RECORD_LEN {
        return Err(KeyStoreError::Corrupt);
    }
    let mut records = BTreeMap::new();
    for record in plaintext[2..].chunks_exact(RECORD_LEN) {
        let id = IdentityKeyId::from_bytes(record[..16].try_into().map_err(|_| KeyStoreError::Corrupt)?);
        if id.as_bytes() == &[0; 16] {
            return Err(KeyStoreError::Corrupt);
        }
        let purpose = purpose_from_byte(record[16]).ok_or(KeyStoreError::Corrupt)?;
        let mut bytes: [u8; 32] = record[17..].try_into().map_err(|_| KeyStoreError::Corrupt)?;
        let seed = Ed25519SigningSeed::from_bytes(bytes);
        bytes.zeroize();
        if records.insert(id, Record { purpose, seed }).is_some() {
            return Err(KeyStoreError::Corrupt);
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use icc_crypto_rust::RustCryptoProviderV1;
    use icc_test_support::{DeterministicRandom, InMemoryKeyStateStore};

    fn root() -> AeadKey32 {
        AeadKey32::from_bytes([0x43; 32])
    }

    fn storage() -> InMemoryKeyStateStore {
        InMemoryKeyStateStore::new([0x64; 16])
    }

    fn initial() -> SoftwareKeyStore<RustCryptoProviderV1, InMemoryKeyStateStore, DeterministicRandom> {
        SoftwareKeyStore::provision(RustCryptoProviderV1, storage(), DeterministicRandom::new(1), root()).unwrap()
    }

    #[test]
    fn generate_sign_and_exact_identity_binding_survive_restart() {
        let mut keys = initial();
        let descriptor = keys.generate(IdentityKeyPurpose::RootAuthorization).unwrap();
        let signature = keys.sign(descriptor, b"ICC/test/root/authorization/v1").unwrap();
        RustCryptoProviderV1.ed25519_verify(
            &descriptor.binding().public_key(),
            b"ICC/test/root/authorization/v1",
            &signature,
        ).unwrap();
        assert!(RustCryptoProviderV1.ed25519_verify(
            &descriptor.binding().public_key(), b"other message", &signature
        ).is_err());
        let snapshot = keys.store.snapshot_for_test().unwrap().1;
        let expected_seed: Vec<u8> = (17..49).collect();
        assert!(!snapshot.windows(32).any(|window| window == expected_seed));

        let state = keys.into_storage();
        let restored = SoftwareKeyStore::open(RustCryptoProviderV1, state, DeterministicRandom::new(90), root()).unwrap();
        restored.verify_binding(descriptor).unwrap();
        assert_eq!(restored.sign(descriptor, b"ICC/test/root/authorization/v1"), Ok(signature));
    }

    #[test]
    fn wrong_handle_purpose_and_public_key_cannot_sign() {
        let mut keys = initial();
        let root_key = keys.generate(IdentityKeyPurpose::RootAuthorization).unwrap();
        let app_key = keys.generate(IdentityKeyPurpose::AppAuthentication).unwrap();
        assert_ne!(root_key.handle(), app_key.handle());
        let substitute = KeyDescriptor { handle: root_key.handle(), binding: app_key.binding() };
        assert_eq!(keys.sign(substitute, b"x"), Err(KeyStoreError::BindingMismatch));
        let wrong_purpose = KeyDescriptor {
            handle: root_key.handle(),
            binding: IdentityKeyBinding::new(root_key.binding().id(), IdentityKeyPurpose::AppAuthentication, root_key.binding().public_key()),
        };
        assert_eq!(keys.sign(wrong_purpose, b"x"), Err(KeyStoreError::BindingMismatch));
        let wrong_public = KeyDescriptor {
            handle: root_key.handle(),
            binding: IdentityKeyBinding::new(root_key.binding().id(), IdentityKeyPurpose::RootAuthorization, app_key.binding().public_key()),
        };
        assert_eq!(keys.verify_binding(wrong_public), Err(KeyStoreError::BindingMismatch));
        let missing = KeyDescriptor {
            handle: KeyHandle::from_bytes([99; 16]),
            binding: IdentityKeyBinding::new(IdentityKeyId::from_bytes([99; 16]), IdentityKeyPurpose::RootAuthorization, root_key.binding().public_key()),
        };
        assert_eq!(keys.sign(missing, b"x"), Err(KeyStoreError::NotFound));
    }

    #[test]
    fn rotation_and_destruction_are_persisted_before_success() {
        let mut keys = initial();
        let old = keys.generate(IdentityKeyPurpose::DeviceAuthentication).unwrap();
        let new = keys.rotate(old).unwrap();
        assert_ne!(new.handle(), old.handle());
        assert_eq!(keys.sign(old, b"x"), Err(KeyStoreError::NotFound));
        let keys_store = keys.into_storage();
        let mut restored = SoftwareKeyStore::open(RustCryptoProviderV1, keys_store, DeterministicRandom::new(100), root()).unwrap();
        assert_eq!(restored.sign(old, b"x"), Err(KeyStoreError::NotFound));
        restored.verify_binding(new).unwrap();
        restored.destroy(new).unwrap();
        let state = restored.into_storage();
        let reopened = SoftwareKeyStore::open(RustCryptoProviderV1, state, DeterministicRandom::new(120), root()).unwrap();
        assert_eq!(reopened.sign(new, b"x"), Err(KeyStoreError::NotFound));
    }

    #[test]
    fn failed_and_ambiguous_commit_poison_instance_then_reopen() {
        let mut keys = initial();
        let old = keys.generate(IdentityKeyPurpose::AppAuthentication).unwrap();
        keys.store.fail_before_commit();
        assert!(matches!(keys.rotate(old), Err(KeyStoreError::Storage(PlatformError::Unavailable))));
        assert_eq!(keys.sign(old, b"x"), Err(KeyStoreError::Unavailable));
        let state = keys.into_storage();
        let mut reopened = SoftwareKeyStore::open(RustCryptoProviderV1, state, DeterministicRandom::new(150), root()).unwrap();
        reopened.verify_binding(old).unwrap();
        reopened.store.fail_after_commit();
        assert!(matches!(reopened.destroy(old), Err(KeyStoreError::Storage(PlatformError::Unavailable))));
        assert_eq!(reopened.sign(old, b"x"), Err(KeyStoreError::Unavailable));
        let state = reopened.into_storage();
        let committed = SoftwareKeyStore::open(RustCryptoProviderV1, state, DeterministicRandom::new(170), root()).unwrap();
        assert_eq!(committed.sign(old, b"x"), Err(KeyStoreError::NotFound));
    }

    #[test]
    fn missing_corrupt_old_or_wrong_root_state_fails_closed() {
        assert!(matches!(SoftwareKeyStore::open(RustCryptoProviderV1, storage(), DeterministicRandom::new(1), root()), Err(KeyStoreError::Unprovisioned)));
        let mut keys = initial();
        let prior = keys.store.snapshot_for_test();
        let _ = keys.generate(IdentityKeyPurpose::RecoveryAuthorization).unwrap();
        let mut state = keys.into_storage();
        state.replace_snapshot_for_test(prior);
        assert!(matches!(SoftwareKeyStore::open(RustCryptoProviderV1, state, DeterministicRandom::new(1), root()), Err(KeyStoreError::Storage(PlatformError::Corrupt))));

        let state = initial().into_storage();
        assert!(matches!(SoftwareKeyStore::open(RustCryptoProviderV1, state, DeterministicRandom::new(1), AeadKey32::from_bytes([0x22; 32])), Err(KeyStoreError::Corrupt)));
        let mut state = initial().into_storage();
        let (epoch, mut snapshot) = state.snapshot_for_test().unwrap();
        snapshot[8] ^= 1;
        state.replace_snapshot_for_test(Some((epoch, snapshot)));
        assert!(matches!(SoftwareKeyStore::open(RustCryptoProviderV1, state, DeterministicRandom::new(1), root()), Err(KeyStoreError::Corrupt)));
    }

    struct ZeroRandom;

    impl SecureRandom for ZeroRandom {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), PlatformError> {
            output.fill(0);
            Ok(())
        }
    }

    #[test]
    fn insufficient_entropy_does_not_create_identity_key() {
        let state = initial().into_storage();
        let mut keys = SoftwareKeyStore::open(RustCryptoProviderV1, state, ZeroRandom, root()).unwrap();
        assert!(matches!(keys.generate(IdentityKeyPurpose::RootAuthorization), Err(KeyStoreError::Entropy)));
        assert_eq!(keys.records.len(), 0);
    }

    #[test]
    fn decoder_rejects_truncation_count_purpose_duplicate_and_extra_bytes() {
        assert!(parse_records(&[]).is_err());
        assert!(parse_records(&[0, 1]).is_err());
        let mut record = alloc::vec![0; 2 + RECORD_LEN];
        record[1] = 1;
        record[2] = 7;
        record[18] = 1;
        assert!(parse_records(&record).is_ok());
        record[18] = 255;
        assert!(parse_records(&record).is_err());
        record[18] = 1;
        record.extend_from_slice(&record[2..].to_vec());
        record[1] = 2;
        assert!(parse_records(&record).is_err());
        record.push(1);
        assert!(parse_records(&record).is_err());
    }

    #[test]
    fn bounded_mutation_fuzz_harness_never_accepts_malformed_lengths() {
        let mut state = 0x1234_5678_u32;
        for len in 0..(2 + MAX_KEYS * RECORD_LEN + 64) {
            let mut input = alloc::vec![0_u8; len];
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            if let Ok(parsed) = parse_records(&input) {
                assert!(parsed.len() <= MAX_KEYS);
                assert_eq!(input.len(), 2 + parsed.len() * RECORD_LEN);
            }
        }
    }
}
