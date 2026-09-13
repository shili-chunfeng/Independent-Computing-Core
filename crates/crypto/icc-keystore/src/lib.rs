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
    AeadKey32, CryptoError, CryptoProviderV1, Ed25519PublicKey, Ed25519Signature,
    Ed25519SigningSeed, Nonce96,
};
use icc_error::PlatformError;
use icc_identity_core::{IdentityKeyBinding, IdentityKeyPurpose};
use icc_platform_api::{KeyStateStore, SecureRandom};
use icc_types::IdentityKeyId;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"ICCKS4\0\0";
const VERSION: u16 = 2;
const HEADER_LEN: usize = 8 + 2 + 16 + 8;
const RECORD_LEN: usize = 16 + 8 + 1 + 32;
const MAX_KEYS: usize = 128;
const MAX_SNAPSHOT: usize = HEADER_LEN + 2 + MAX_KEYS * RECORD_LEN + 16;
const MAX_ID_ATTEMPTS: usize = 8;
const HKDF_INFO: &[u8] = b"ICC/keystore/state-seal/ClassicalV1/v2";

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
    generation: u64,
}

impl KeyDescriptor {
    pub const fn handle(&self) -> KeyHandle {
        self.handle
    }

    pub const fn binding(&self) -> IdentityKeyBinding {
        self.binding
    }

    /// Trusted, never-reused issuance epoch for this namespace.
    pub const fn generation(&self) -> u64 {
        self.generation
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
    generation: u64,
    purpose: IdentityKeyPurpose,
    seed: Ed25519SigningSeed,
}

/// Software KeyStore. The provider, random source and trusted state Port are
/// injected; their concrete types never enter Domain Core or an App API. The
/// Port's exclusive namespace lease is acquired before load and held while
/// any in-memory signing seed is usable.
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
        mut store: S,
        random: R,
        root: AeadKey32,
    ) -> Result<Self, KeyStoreError> {
        store.acquire_exclusive().map_err(KeyStoreError::Storage)?;
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
    pub fn open(
        crypto: C,
        mut store: S,
        random: R,
        root: AeadKey32,
    ) -> Result<Self, KeyStoreError> {
        store.acquire_exclusive().map_err(KeyStoreError::Storage)?;
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

    /// One-way handoff for an explicit restart test. Release the lease only
    /// when this instance can perform no further operation; all owned signing
    /// seeds and the sealing root are then dropped.
    pub fn into_storage(mut self) -> S {
        self.store.release_exclusive();
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
        if record.generation != descriptor.generation
            || record.purpose != descriptor.binding.purpose()
            || self.crypto.ed25519_public_from_seed(&record.seed) != descriptor.binding.public_key()
        {
            return Err(KeyStoreError::BindingMismatch);
        }
        Ok(record)
    }

    fn new_record(
        &mut self,
        purpose: IdentityKeyPurpose,
    ) -> Result<(IdentityKeyId, Record), KeyStoreError> {
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
        for _ in 0..MAX_ID_ATTEMPTS {
            if self.random.fill(&mut seed_bytes).is_err() {
                seed_bytes.zeroize();
                return Err(KeyStoreError::Entropy);
            }
            if seed_bytes == [0; 32] {
                seed_bytes.zeroize();
                continue;
            }
            let seed = Ed25519SigningSeed::from_bytes(seed_bytes);
            seed_bytes.zeroize();
            let public = self.crypto.ed25519_public_from_seed(&seed);
            if self
                .records
                .values()
                .all(|record| self.crypto.ed25519_public_from_seed(&record.seed) != public)
            {
                return Ok((
                    id,
                    Record {
                        generation: 0,
                        purpose,
                        seed,
                    },
                ));
            }
        }
        seed_bytes.zeroize();
        Err(KeyStoreError::Entropy)
    }

    fn descriptor(&self, id: IdentityKeyId, record: &Record) -> KeyDescriptor {
        KeyDescriptor {
            handle: KeyHandle::from_bytes(*id.as_bytes()),
            binding: IdentityKeyBinding::new(
                id,
                record.purpose,
                self.crypto.ed25519_public_from_seed(&record.seed),
            ),
            generation: record.generation,
        }
    }

    /// Atomically write the next complete state, excluding a removed/rotated
    /// key and optionally including a new one. Stamp a newly issued record
    /// with the reserved never-reused epoch before sealing. Never mutate live
    /// records here until the durable commit succeeds.
    fn persist(
        &mut self,
        excluded: Option<IdentityKeyId>,
        mut included: Option<(IdentityKeyId, &mut Record)>,
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
        if let Some((_, record)) = &mut included {
            record.generation = reserved;
        }
        let included = included.as_ref().map(|(id, record)| (*id, &**record));
        let count =
            self.records.len() - usize::from(excluded.is_some()) + usize::from(included.is_some());
        if count > MAX_KEYS {
            return Err(KeyStoreError::Capacity);
        }
        let mut plaintext = Vec::with_capacity(2 + count * RECORD_LEN);
        plaintext.extend_from_slice(&(count as u16).to_be_bytes());
        let mut inserted = false;
        for (&id, record) in &self.records {
            if Some(id) == excluded {
                continue;
            }
            if let Some((new_id, new_record)) = included
                && !inserted
                && new_id < id
            {
                append_record(&mut plaintext, new_id, new_record);
                inserted = true;
            }
            append_record(&mut plaintext, id, record);
        }
        if let Some((id, record)) = included
            && !inserted
        {
            append_record(&mut plaintext, id, record);
        }
        let result = seal(
            &self.crypto,
            &self.root,
            self.namespace,
            reserved,
            &plaintext,
        );
        plaintext.as_mut_slice().zeroize();
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
        let (id, mut record) = self.new_record(purpose)?;
        self.persist(None, Some((id, &mut record)))?;
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
        let (id, mut record) = self.new_record(current.binding.purpose())?;
        self.persist(Some(current.binding.id()), Some((id, &mut record)))?;
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
    out.extend_from_slice(&record.generation.to_be_bytes());
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
        .chacha20poly1305_open(
            &key,
            nonce(epoch),
            &snapshot[..HEADER_LEN],
            &snapshot[HEADER_LEN..],
        )
        .map_err(|error| match error {
            CryptoError::AuthenticationFailed => KeyStoreError::Corrupt,
            _ => KeyStoreError::Crypto,
        })?;
    let result = parse_records(&plaintext, epoch, |seed| {
        crypto.ed25519_public_from_seed(seed)
    });
    plaintext.as_mut_slice().zeroize();
    result
}

fn parse_records<F>(
    plaintext: &[u8],
    epoch: u64,
    public_from_seed: F,
) -> Result<BTreeMap<IdentityKeyId, Record>, KeyStoreError>
where
    F: Fn(&Ed25519SigningSeed) -> Ed25519PublicKey,
{
    if plaintext.len() < 2 {
        return Err(KeyStoreError::Corrupt);
    }
    let count = usize::from(u16::from_be_bytes([plaintext[0], plaintext[1]]));
    if count > MAX_KEYS || plaintext.len() != 2 + count * RECORD_LEN {
        return Err(KeyStoreError::Corrupt);
    }
    let mut records = BTreeMap::new();
    let mut previous = None;
    for record in plaintext[2..].as_chunks::<RECORD_LEN>().0 {
        let id = IdentityKeyId::from_bytes(
            record[..16]
                .try_into()
                .map_err(|_| KeyStoreError::Corrupt)?,
        );
        if id.as_bytes() == &[0; 16] {
            return Err(KeyStoreError::Corrupt);
        }
        if previous.is_some_and(|last| id <= last) {
            return Err(KeyStoreError::Corrupt);
        }
        previous = Some(id);
        let generation = u64::from_be_bytes(
            record[16..24]
                .try_into()
                .map_err(|_| KeyStoreError::Corrupt)?,
        );
        if generation == 0
            || generation > epoch
            || records
                .values()
                .any(|existing: &Record| existing.generation == generation)
        {
            return Err(KeyStoreError::Corrupt);
        }
        let purpose = purpose_from_byte(record[24]).ok_or(KeyStoreError::Corrupt)?;
        let mut bytes: [u8; 32] = record[25..]
            .try_into()
            .map_err(|_| KeyStoreError::Corrupt)?;
        if bytes == [0; 32] {
            bytes.zeroize();
            return Err(KeyStoreError::Corrupt);
        }
        let seed = Ed25519SigningSeed::from_bytes(bytes);
        bytes.zeroize();
        let public = public_from_seed(&seed);
        if records.values().any(|existing| {
            existing.seed.expose_secret() == seed.expose_secret()
                || public_from_seed(&existing.seed) == public
        }) {
            return Err(KeyStoreError::Corrupt);
        }
        let _ = records.insert(
            id,
            Record {
                generation,
                purpose,
                seed,
            },
        );
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

    fn test_record(id: u8, generation: u64, purpose: u8, seed: u8) -> [u8; RECORD_LEN] {
        let mut record = [0_u8; RECORD_LEN];
        record[0] = id;
        record[16..24].copy_from_slice(&generation.to_be_bytes());
        record[24] = purpose;
        record[25..].fill(seed);
        record
    }

    fn test_payload(records: &[[u8; RECORD_LEN]]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + records.len() * RECORD_LEN);
        bytes.extend_from_slice(&(records.len() as u16).to_be_bytes());
        for record in records {
            bytes.extend_from_slice(record);
        }
        bytes
    }

    fn parse_test(
        bytes: &[u8],
        epoch: u64,
    ) -> Result<BTreeMap<IdentityKeyId, Record>, KeyStoreError> {
        parse_records(bytes, epoch, |seed| {
            RustCryptoProviderV1.ed25519_public_from_seed(seed)
        })
    }

    fn initial()
    -> SoftwareKeyStore<RustCryptoProviderV1, InMemoryKeyStateStore, DeterministicRandom> {
        SoftwareKeyStore::provision(
            RustCryptoProviderV1,
            storage(),
            DeterministicRandom::new(1),
            root(),
        )
        .unwrap()
    }

    #[test]
    fn generate_sign_and_exact_identity_binding_survive_restart() {
        let mut keys = initial();
        let descriptor = keys
            .generate(IdentityKeyPurpose::RootAuthorization)
            .unwrap();
        let signature = keys
            .sign(descriptor, b"ICC/test/root/authorization/v1")
            .unwrap();
        RustCryptoProviderV1
            .ed25519_verify(
                &descriptor.binding().public_key(),
                b"ICC/test/root/authorization/v1",
                &signature,
            )
            .unwrap();
        assert!(
            RustCryptoProviderV1
                .ed25519_verify(
                    &descriptor.binding().public_key(),
                    b"other message",
                    &signature
                )
                .is_err()
        );
        let snapshot = keys.store.snapshot_for_test().unwrap().1;
        let expected_seed: Vec<u8> = (17..49).collect();
        assert!(!snapshot.windows(32).any(|window| window == expected_seed));

        let state = keys.into_storage();
        let restored = SoftwareKeyStore::open(
            RustCryptoProviderV1,
            state,
            DeterministicRandom::new(90),
            root(),
        )
        .unwrap();
        restored.verify_binding(descriptor).unwrap();
        assert_eq!(
            restored.sign(descriptor, b"ICC/test/root/authorization/v1"),
            Ok(signature)
        );
    }

    #[test]
    fn wrong_handle_purpose_and_public_key_cannot_sign() {
        let mut keys = initial();
        let root_key = keys
            .generate(IdentityKeyPurpose::RootAuthorization)
            .unwrap();
        let app_key = keys
            .generate(IdentityKeyPurpose::AppAuthentication)
            .unwrap();
        assert_ne!(root_key.handle(), app_key.handle());
        let substitute = KeyDescriptor {
            handle: root_key.handle(),
            binding: app_key.binding(),
            generation: root_key.generation(),
        };
        assert_eq!(
            keys.sign(substitute, b"x"),
            Err(KeyStoreError::BindingMismatch)
        );
        let wrong_purpose = KeyDescriptor {
            handle: root_key.handle(),
            binding: IdentityKeyBinding::new(
                root_key.binding().id(),
                IdentityKeyPurpose::AppAuthentication,
                root_key.binding().public_key(),
            ),
            generation: root_key.generation(),
        };
        assert_eq!(
            keys.sign(wrong_purpose, b"x"),
            Err(KeyStoreError::BindingMismatch)
        );
        let wrong_public = KeyDescriptor {
            handle: root_key.handle(),
            binding: IdentityKeyBinding::new(
                root_key.binding().id(),
                IdentityKeyPurpose::RootAuthorization,
                app_key.binding().public_key(),
            ),
            generation: root_key.generation(),
        };
        assert_eq!(
            keys.verify_binding(wrong_public),
            Err(KeyStoreError::BindingMismatch)
        );
        let missing = KeyDescriptor {
            handle: KeyHandle::from_bytes([99; 16]),
            binding: IdentityKeyBinding::new(
                IdentityKeyId::from_bytes([99; 16]),
                IdentityKeyPurpose::RootAuthorization,
                root_key.binding().public_key(),
            ),
            generation: root_key.generation(),
        };
        assert_eq!(keys.sign(missing, b"x"), Err(KeyStoreError::NotFound));
    }

    #[test]
    fn rotation_and_destruction_are_persisted_before_success() {
        let mut keys = initial();
        let old = keys
            .generate(IdentityKeyPurpose::DeviceAuthentication)
            .unwrap();
        let new = keys.rotate(old).unwrap();
        assert_ne!(new.handle(), old.handle());
        assert_eq!(keys.sign(old, b"x"), Err(KeyStoreError::NotFound));
        let keys_store = keys.into_storage();
        let mut restored = SoftwareKeyStore::open(
            RustCryptoProviderV1,
            keys_store,
            DeterministicRandom::new(100),
            root(),
        )
        .unwrap();
        assert_eq!(restored.sign(old, b"x"), Err(KeyStoreError::NotFound));
        restored.verify_binding(new).unwrap();
        restored.destroy(new).unwrap();
        let state = restored.into_storage();
        let reopened = SoftwareKeyStore::open(
            RustCryptoProviderV1,
            state,
            DeterministicRandom::new(120),
            root(),
        )
        .unwrap();
        assert_eq!(reopened.sign(new, b"x"), Err(KeyStoreError::NotFound));
    }

    #[test]
    fn failed_and_ambiguous_commit_poison_instance_then_reopen() {
        let mut keys = initial();
        let old = keys
            .generate(IdentityKeyPurpose::AppAuthentication)
            .unwrap();
        keys.store.fail_before_commit();
        assert!(matches!(
            keys.rotate(old),
            Err(KeyStoreError::Storage(PlatformError::Unavailable))
        ));
        assert_eq!(keys.sign(old, b"x"), Err(KeyStoreError::Unavailable));
        let state = keys.into_storage();
        let mut reopened = SoftwareKeyStore::open(
            RustCryptoProviderV1,
            state,
            DeterministicRandom::new(150),
            root(),
        )
        .unwrap();
        reopened.verify_binding(old).unwrap();
        reopened.store.fail_after_commit();
        assert!(matches!(
            reopened.destroy(old),
            Err(KeyStoreError::Storage(PlatformError::Unavailable))
        ));
        assert_eq!(reopened.sign(old, b"x"), Err(KeyStoreError::Unavailable));
        let state = reopened.into_storage();
        let committed = SoftwareKeyStore::open(
            RustCryptoProviderV1,
            state,
            DeterministicRandom::new(170),
            root(),
        )
        .unwrap();
        assert_eq!(committed.sign(old, b"x"), Err(KeyStoreError::NotFound));
    }

    #[test]
    fn missing_corrupt_old_or_wrong_root_state_fails_closed() {
        assert!(matches!(
            SoftwareKeyStore::open(
                RustCryptoProviderV1,
                storage(),
                DeterministicRandom::new(1),
                root()
            ),
            Err(KeyStoreError::Unprovisioned)
        ));
        let mut keys = initial();
        let prior = keys.store.snapshot_for_test();
        let _ = keys
            .generate(IdentityKeyPurpose::RecoveryAuthorization)
            .unwrap();
        let mut state = keys.into_storage();
        state.replace_snapshot_for_test(prior);
        assert!(matches!(
            SoftwareKeyStore::open(
                RustCryptoProviderV1,
                state,
                DeterministicRandom::new(1),
                root()
            ),
            Err(KeyStoreError::Storage(PlatformError::Corrupt))
        ));

        let state = initial().into_storage();
        assert!(matches!(
            SoftwareKeyStore::open(
                RustCryptoProviderV1,
                state,
                DeterministicRandom::new(1),
                AeadKey32::from_bytes([0x22; 32])
            ),
            Err(KeyStoreError::Corrupt)
        ));
        let mut state = initial().into_storage();
        let (epoch, mut snapshot) = state.snapshot_for_test().unwrap();
        snapshot[8] ^= 1;
        state.replace_snapshot_for_test(Some((epoch, snapshot)));
        assert!(matches!(
            SoftwareKeyStore::open(
                RustCryptoProviderV1,
                state,
                DeterministicRandom::new(1),
                root()
            ),
            Err(KeyStoreError::Corrupt)
        ));
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
        let mut keys =
            SoftwareKeyStore::open(RustCryptoProviderV1, state, ZeroRandom, root()).unwrap();
        assert!(matches!(
            keys.generate(IdentityKeyPurpose::RootAuthorization),
            Err(KeyStoreError::Entropy)
        ));
        assert_eq!(keys.records.len(), 0);
    }

    struct RepeatedSeedRandom {
        next_id: u8,
    }

    impl SecureRandom for RepeatedSeedRandom {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), PlatformError> {
            if output.len() == 16 {
                output.fill(self.next_id);
                self.next_id = self.next_id.wrapping_add(1);
            } else {
                output.fill(7);
            }
            Ok(())
        }
    }

    #[test]
    fn duplicate_public_key_is_rejected_without_losing_existing_key() {
        let state = initial().into_storage();
        let mut keys = SoftwareKeyStore::open(
            RustCryptoProviderV1,
            state,
            RepeatedSeedRandom { next_id: 1 },
            root(),
        )
        .unwrap();
        let original = keys
            .generate(IdentityKeyPurpose::RootAuthorization)
            .unwrap();
        assert_eq!(
            keys.generate(IdentityKeyPurpose::AppAuthentication),
            Err(KeyStoreError::Entropy)
        );
        assert_eq!(keys.records.len(), 1);
        assert!(keys.sign(original, b"still valid").is_ok());
    }

    #[test]
    fn sealed_records_are_canonically_sorted_even_after_id_wrap() {
        let mut keys = SoftwareKeyStore::provision(
            RustCryptoProviderV1,
            storage(),
            DeterministicRandom::new(230),
            root(),
        )
        .unwrap();
        let first = keys
            .generate(IdentityKeyPurpose::RootAuthorization)
            .unwrap();
        let second = keys
            .generate(IdentityKeyPurpose::DeviceAuthentication)
            .unwrap();
        assert!(second.handle() < first.handle());
        let (epoch, snapshot) = keys.store.snapshot_for_test().unwrap();
        let key = sealing_key(&RustCryptoProviderV1, &root(), &[0x64; 16]).unwrap();
        let mut plaintext = RustCryptoProviderV1
            .chacha20poly1305_open(
                &key,
                nonce(epoch),
                &snapshot[..HEADER_LEN],
                &snapshot[HEADER_LEN..],
            )
            .unwrap();
        assert_eq!(&plaintext[..2], &[0, 2]);
        assert!(plaintext[2..18] < plaintext[2 + RECORD_LEN..18 + RECORD_LEN]);
        plaintext.as_mut_slice().zeroize();
    }

    struct RepeatedIdRandom;

    impl SecureRandom for RepeatedIdRandom {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), PlatformError> {
            let byte = if output.len() == 16 { 1 } else { 2 };
            output.fill(byte);
            Ok(())
        }
    }

    #[test]
    fn exhausted_id_collisions_do_not_create_another_key() {
        let state = initial().into_storage();
        let mut keys =
            SoftwareKeyStore::open(RustCryptoProviderV1, state, RepeatedIdRandom, root()).unwrap();
        let existing = keys
            .generate(IdentityKeyPurpose::RootAuthorization)
            .unwrap();
        assert_eq!(
            keys.generate(IdentityKeyPurpose::AppAuthentication),
            Err(KeyStoreError::Entropy)
        );
        assert_eq!(keys.records.len(), 1);
        keys.verify_binding(existing).unwrap();
    }

    #[test]
    fn destroyed_descriptor_never_revives_when_id_and_seed_repeat_after_restart() {
        let state = initial().into_storage();
        let mut keys =
            SoftwareKeyStore::open(RustCryptoProviderV1, state, RepeatedIdRandom, root()).unwrap();
        let old = keys
            .generate(IdentityKeyPurpose::RootAuthorization)
            .unwrap();
        keys.destroy(old).unwrap();
        let replacement = keys
            .generate(IdentityKeyPurpose::RootAuthorization)
            .unwrap();
        assert_eq!(old.handle(), replacement.handle());
        assert_eq!(old.binding(), replacement.binding());
        assert_ne!(old.generation(), replacement.generation());
        assert_eq!(
            keys.sign(old, b"revoked"),
            Err(KeyStoreError::BindingMismatch)
        );
        assert!(keys.sign(replacement, b"current").is_ok());

        let state = keys.into_storage();
        let restored =
            SoftwareKeyStore::open(RustCryptoProviderV1, state, RepeatedIdRandom, root()).unwrap();
        assert_eq!(
            restored.sign(old, b"revoked"),
            Err(KeyStoreError::BindingMismatch)
        );
        restored.verify_binding(replacement).unwrap();
    }

    struct ScriptedRandom {
        next_id: u8,
    }

    impl SecureRandom for ScriptedRandom {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), PlatformError> {
            if output.len() == 16 {
                output.fill(self.next_id);
            } else {
                output.fill(self.next_id + 1);
                self.next_id += 2;
            }
            Ok(())
        }
    }

    #[test]
    fn rotated_descriptor_cannot_revive_after_old_id_and_seed_are_reissued() {
        let state = initial().into_storage();
        let mut keys = SoftwareKeyStore::open(
            RustCryptoProviderV1,
            state,
            ScriptedRandom { next_id: 1 },
            root(),
        )
        .unwrap();
        let old = keys
            .generate(IdentityKeyPurpose::DeviceAuthentication)
            .unwrap();
        let rotated = keys.rotate(old).unwrap();
        assert_ne!(old.binding(), rotated.binding());
        keys.random.next_id = 1;
        let repeated = keys
            .generate(IdentityKeyPurpose::DeviceAuthentication)
            .unwrap();
        assert_eq!(old.binding(), repeated.binding());
        assert_ne!(old.generation(), repeated.generation());
        assert_eq!(keys.sign(old, b"old"), Err(KeyStoreError::BindingMismatch));
        let state = keys.into_storage();
        let restored = SoftwareKeyStore::open(
            RustCryptoProviderV1,
            state,
            ScriptedRandom { next_id: 7 },
            root(),
        )
        .unwrap();
        assert_eq!(
            restored.sign(old, b"old"),
            Err(KeyStoreError::BindingMismatch)
        );
        assert!(restored.sign(repeated, b"new").is_ok());
    }

    #[test]
    fn exclusive_lease_prevents_parallel_stale_signing_across_destroy_and_rotate() {
        let mut owner = initial();
        let old = owner
            .generate(IdentityKeyPurpose::DeviceAuthentication)
            .unwrap();
        let contender = owner.store.fork_for_test();
        assert!(matches!(
            SoftwareKeyStore::open(RustCryptoProviderV1, contender, ZeroRandom, root()),
            Err(KeyStoreError::Storage(PlatformError::Unavailable))
        ));
        owner.destroy(old).unwrap();
        let contender = owner.store.fork_for_test();
        assert!(matches!(
            SoftwareKeyStore::open(RustCryptoProviderV1, contender, ZeroRandom, root()),
            Err(KeyStoreError::Storage(PlatformError::Unavailable))
        ));
        let contender = owner.store.fork_for_test();
        drop(owner);
        let next =
            SoftwareKeyStore::open(RustCryptoProviderV1, contender, ZeroRandom, root()).unwrap();
        assert_eq!(next.sign(old, b"stale"), Err(KeyStoreError::NotFound));

        let state = next.into_storage();
        let mut owner = SoftwareKeyStore::open(
            RustCryptoProviderV1,
            state,
            DeterministicRandom::new(40),
            root(),
        )
        .unwrap();
        let old = owner
            .generate(IdentityKeyPurpose::AppAuthentication)
            .unwrap();
        let contender = owner.store.fork_for_test();
        let current = owner.rotate(old).unwrap();
        assert!(matches!(
            SoftwareKeyStore::open(RustCryptoProviderV1, contender, ZeroRandom, root()),
            Err(KeyStoreError::Storage(PlatformError::Unavailable))
        ));
        let contender = owner.store.fork_for_test();
        drop(owner);
        let next =
            SoftwareKeyStore::open(RustCryptoProviderV1, contender, ZeroRandom, root()).unwrap();
        assert_eq!(next.sign(old, b"stale"), Err(KeyStoreError::NotFound));
        next.verify_binding(current).unwrap();
    }

    #[test]
    fn failed_open_releases_lease_without_unprovisioned_recreation() {
        let state = initial().into_storage();
        let contender = state.fork_for_test();
        assert!(matches!(
            SoftwareKeyStore::open(
                RustCryptoProviderV1,
                state,
                ZeroRandom,
                AeadKey32::from_bytes([0x22; 32])
            ),
            Err(KeyStoreError::Corrupt)
        ));
        let reopened =
            SoftwareKeyStore::open(RustCryptoProviderV1, contender, ZeroRandom, root()).unwrap();
        assert!(reopened.records.is_empty());
    }

    #[test]
    fn decoder_rejects_truncation_count_purpose_duplicate_and_extra_bytes() {
        assert!(parse_test(&[], 3).is_err());
        assert!(parse_test(&[0, 1], 3).is_err());
        let mut record = test_payload(&[test_record(7, 2, 1, 9)]);
        assert!(parse_test(&record, 3).is_ok());
        record[26] = 255;
        assert!(parse_test(&record, 3).is_err());
        record[26] = 1;
        record.extend_from_within(2..);
        record[1] = 2;
        assert!(parse_test(&record, 3).is_err());
        record.push(1);
        assert!(parse_test(&record, 3).is_err());
        assert!(
            parse_test(
                &test_payload(&[test_record(9, 2, 1, 7), test_record(7, 3, 2, 8),]),
                3
            )
            .is_err()
        );
    }

    #[test]
    fn decoder_rejects_zero_seed_duplicate_seed_public_and_generation() {
        let zero = test_payload(&[test_record(1, 2, 1, 0)]);
        assert!(parse_test(&zero, 3).is_err());
        let duplicate_seed = test_payload(&[test_record(1, 2, 1, 7), test_record(2, 3, 2, 7)]);
        assert!(parse_test(&duplicate_seed, 3).is_err());
        let duplicate_generation =
            test_payload(&[test_record(1, 2, 1, 7), test_record(2, 2, 2, 8)]);
        assert!(parse_test(&duplicate_generation, 3).is_err());
        assert!(parse_test(&test_payload(&[test_record(1, 0, 1, 7)]), 3).is_err());
        assert!(parse_test(&test_payload(&[test_record(1, 4, 1, 7)]), 3).is_err());
        let different_seeds = test_payload(&[test_record(1, 2, 1, 7), test_record(2, 3, 2, 8)]);
        assert!(parse_test(&different_seeds, 3).is_ok());
        assert!(
            parse_records(&different_seeds, 3, |_| {
                Ed25519PublicKey::from_bytes([42; 32])
            })
            .is_err()
        );

        let mut keys = initial();
        let _ = keys
            .generate(IdentityKeyPurpose::RootAuthorization)
            .unwrap();
        let _ = keys
            .generate(IdentityKeyPurpose::DeviceAuthentication)
            .unwrap();
        let mut state = keys.into_storage();
        let epoch = state.snapshot_for_test().unwrap().0;
        for payload in [&zero, &duplicate_seed] {
            let sealed = seal(&RustCryptoProviderV1, &root(), [0x64; 16], epoch, payload).unwrap();
            state.replace_snapshot_for_test(Some((epoch, sealed)));
            let attempt = SoftwareKeyStore::open(
                RustCryptoProviderV1,
                state.fork_for_test(),
                ZeroRandom,
                root(),
            );
            assert!(matches!(attempt, Err(KeyStoreError::Corrupt)));
        }
    }

    #[test]
    fn authenticated_v1_snapshot_is_rejected_without_implicit_migration() {
        let mut state = initial().into_storage();
        let epoch = state.snapshot_for_test().unwrap().0;
        let mut aad = header([0x64; 16], epoch);
        aad[8..10].copy_from_slice(&1_u16.to_be_bytes());
        let old_info = b"ICC/keystore/state-seal/ClassicalV1/v1";
        let derived = RustCryptoProviderV1
            .hkdf_sha256_32(&[0x64; 16], root().expose_secret(), old_info)
            .unwrap();
        let mut bytes = *derived.expose_secret();
        let key = AeadKey32::from_bytes(bytes);
        bytes.zeroize();
        let ciphertext = RustCryptoProviderV1
            .chacha20poly1305_seal(&key, nonce(epoch), &aad, &[0, 0])
            .unwrap();
        aad.extend_from_slice(&ciphertext);
        state.replace_snapshot_for_test(Some((epoch, aad)));
        let other = state.fork_for_test();
        assert!(matches!(
            SoftwareKeyStore::open(RustCryptoProviderV1, state, ZeroRandom, root()),
            Err(KeyStoreError::Corrupt)
        ));
        assert!(matches!(
            SoftwareKeyStore::provision(RustCryptoProviderV1, other, ZeroRandom, root()),
            Err(KeyStoreError::AlreadyProvisioned)
        ));
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
            if let Ok(parsed) = parse_test(&input, u64::MAX) {
                assert!(parsed.len() <= MAX_KEYS);
                assert_eq!(input.len(), 2 + parsed.len() * RECORD_LEN);
            }
        }
    }
}
