#![no_std]
#![forbid(unsafe_code)]

//! Portable, authority-internal logical object state machine. Object IDs and
//! content references are names, never grants. All access decisions are made
//! before record lookup by an injected trusted policy; a caller-bound service
//! must supply the real caller in a later runtime Phase.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use icc_error::PlatformError;
use icc_platform_api::{SecureRandom, VaultSeal, VaultStateStore};
use icc_types::{AppId, ObjectId, VaultOwnerId};

pub const MAX_OBJECTS: usize = 64;
pub const MAX_METADATA: usize = 1024;
pub const MAX_CONTENT: usize = 16 * 1024;
const MAX_SNAPSHOT: usize = 1_200_000;
const MAGIC: &[u8; 8] = b"ICCVOB5\0";
const VERSION: u16 = 1;
const ID_ATTEMPTS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VaultAction {
    Create,
    Read,
    Write,
    Delete,
    List,
}

/// Implement only in the owning authority; never from a request-supplied
/// closure, App process, claimed principal or unverified serialized token.
pub trait VaultAuthorizer {
    fn permits(
        &self,
        caller: AppId,
        owner: VaultOwnerId,
        object: Option<ObjectId>,
        action: VaultAction,
    ) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultError {
    Denied,
    Unprovisioned,
    AlreadyProvisioned,
    Capacity,
    InvalidInput,
    Entropy,
    Corrupt,
    Unavailable,
    Storage(PlatformError),
}

/// This is returned only after authorization. The inline content is logically
/// referenced by an opaque, non-authorizing content_ref; no physical path or
/// database row enters this API. Metadata is encrypted at rest with content.
#[derive(Clone, Eq, PartialEq)]
pub struct VaultObject {
    id: ObjectId,
    owner: VaultOwnerId,
    kind: u16,
    content_ref: [u8; 16],
    revision: u64,
    metadata: Vec<u8>,
    content: Vec<u8>,
}

impl VaultObject {
    pub const fn id(&self) -> ObjectId {
        self.id
    }
    pub const fn owner(&self) -> VaultOwnerId {
        self.owner
    }
    pub const fn kind(&self) -> u16 {
        self.kind
    }
    pub const fn content_ref(&self) -> &[u8; 16] {
        &self.content_ref
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }
    pub fn content(&self) -> &[u8] {
        &self.content
    }
}

/// One atomic sealed snapshot for a bounded prototype namespace. The store
/// owns a non-stealable lease, trusted committed revision and never-reused
/// reservations; uncertain commits poison this instance until trusted reopen.
pub struct VaultCore<S, C, R, A> {
    store: S,
    sealer: C,
    random: R,
    authority: A,
    namespace: [u8; 16],
    epoch: u64,
    objects: BTreeMap<ObjectId, VaultObject>,
    poisoned: bool,
}

impl<S: VaultStateStore, C: VaultSeal, R: SecureRandom, A: VaultAuthorizer> VaultCore<S, C, R, A> {
    /// Provision explicitly. A missing provisioned snapshot is never treated
    /// as an empty Vault after restart.
    pub fn initialize(
        mut store: S,
        sealer: C,
        random: R,
        authority: A,
    ) -> Result<Self, VaultError> {
        store.acquire_exclusive().map_err(VaultError::Storage)?;
        let namespace = store.namespace().map_err(VaultError::Storage)?;
        if namespace == [0; 16] {
            return Err(VaultError::Corrupt);
        }
        if store.load().map_err(VaultError::Storage)?.is_some() {
            return Err(VaultError::AlreadyProvisioned);
        }
        let mut core = Self {
            store,
            sealer,
            random,
            authority,
            namespace,
            epoch: 0,
            objects: BTreeMap::new(),
            poisoned: false,
        };
        core.commit(BTreeMap::new())?;
        Ok(core)
    }

    pub fn open(mut store: S, sealer: C, random: R, authority: A) -> Result<Self, VaultError> {
        store.acquire_exclusive().map_err(VaultError::Storage)?;
        let namespace = store.namespace().map_err(VaultError::Storage)?;
        if namespace == [0; 16] {
            return Err(VaultError::Corrupt);
        }
        let (epoch, sealed) = store
            .load()
            .map_err(VaultError::Storage)?
            .ok_or(VaultError::Unprovisioned)?;
        if epoch == 0 || sealed.len() > MAX_SNAPSHOT + 50 {
            return Err(VaultError::Corrupt);
        }
        let plaintext = sealer
            .open(namespace, epoch, &sealed)
            .map_err(|_| VaultError::Corrupt)?;
        let objects = decode(&plaintext, epoch)?;
        Ok(Self {
            store,
            sealer,
            random,
            authority,
            namespace,
            epoch,
            objects,
            poisoned: false,
        })
    }

    fn ready(&self) -> Result<(), VaultError> {
        if self.poisoned {
            Err(VaultError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn require(
        &self,
        caller: AppId,
        owner: VaultOwnerId,
        object: Option<ObjectId>,
        action: VaultAction,
    ) -> Result<(), VaultError> {
        self.ready()?;
        if owner.as_bytes() == &[0; 16] || !self.authority.permits(caller, owner, object, action) {
            return Err(VaultError::Denied);
        }
        Ok(())
    }

    fn new_reference(&mut self, avoid: Option<[u8; 16]>) -> Result<[u8; 16], VaultError> {
        for _ in 0..ID_ATTEMPTS {
            let mut bytes = [0; 16];
            self.random
                .fill(&mut bytes)
                .map_err(|_| VaultError::Entropy)?;
            if bytes != [0; 16]
                && Some(bytes) != avoid
                && !self.objects.contains_key(&ObjectId::from_bytes(bytes))
                && !self.objects.values().any(|o| o.content_ref == bytes)
            {
                return Ok(bytes);
            }
        }
        Err(VaultError::Entropy)
    }

    pub fn create(
        &mut self,
        caller: AppId,
        owner: VaultOwnerId,
        kind: u16,
        metadata: &[u8],
        content: &[u8],
    ) -> Result<ObjectId, VaultError> {
        self.require(caller, owner, None, VaultAction::Create)?;
        validate_input(kind, metadata, content)?;
        if self.objects.len() >= MAX_OBJECTS {
            return Err(VaultError::Capacity);
        }
        let id = ObjectId::from_bytes(self.new_reference(None)?);
        let content_ref = self.new_reference(Some(*id.as_bytes()))?;
        let mut next = self.objects.clone();
        next.insert(
            id,
            VaultObject {
                id,
                owner,
                kind,
                content_ref,
                revision: 1,
                metadata: metadata.to_vec(),
                content: content.to_vec(),
            },
        );
        self.commit(next)?;
        Ok(id)
    }

    pub fn read(
        &self,
        caller: AppId,
        owner: VaultOwnerId,
        id: ObjectId,
    ) -> Result<VaultObject, VaultError> {
        self.require(caller, owner, Some(id), VaultAction::Read)?;
        match self.objects.get(&id) {
            Some(object) if object.owner == owner => Ok(object.clone()),
            _ => Err(VaultError::Denied),
        }
    }

    /// IDs are returned only with a separate owner-scoped List decision. No
    /// object metadata, names, kinds, sizes or existence leaks to other callers.
    pub fn list(&self, caller: AppId, owner: VaultOwnerId) -> Result<Vec<ObjectId>, VaultError> {
        self.require(caller, owner, None, VaultAction::List)?;
        Ok(self
            .objects
            .values()
            .filter(|o| o.owner == owner)
            .map(|o| o.id)
            .collect())
    }

    pub fn replace(
        &mut self,
        caller: AppId,
        owner: VaultOwnerId,
        id: ObjectId,
        metadata: &[u8],
        content: &[u8],
    ) -> Result<u64, VaultError> {
        self.require(caller, owner, Some(id), VaultAction::Write)?;
        let current = self
            .objects
            .get(&id)
            .filter(|o| o.owner == owner)
            .ok_or(VaultError::Denied)?;
        validate_input(current.kind, metadata, content)?;
        let revision = current
            .revision
            .checked_add(1)
            .ok_or(VaultError::Capacity)?;
        let content_ref = self.new_reference(None)?;
        let mut next = self.objects.clone();
        let record = next.get_mut(&id).ok_or(VaultError::Corrupt)?;
        record.revision = revision;
        record.content_ref = content_ref;
        record.metadata = metadata.to_vec();
        record.content = content.to_vec();
        self.commit(next)?;
        Ok(revision)
    }

    pub fn delete(
        &mut self,
        caller: AppId,
        owner: VaultOwnerId,
        id: ObjectId,
    ) -> Result<(), VaultError> {
        self.require(caller, owner, Some(id), VaultAction::Delete)?;
        if !self.objects.get(&id).is_some_and(|o| o.owner == owner) {
            return Err(VaultError::Denied);
        }
        let mut next = self.objects.clone();
        next.remove(&id);
        self.commit(next)
    }

    fn commit(&mut self, next: BTreeMap<ObjectId, VaultObject>) -> Result<(), VaultError> {
        self.ready()?;
        let plaintext = encode(&next)?;
        let reserved = match self.store.reserve_epoch(self.epoch) {
            Ok(value) if value > self.epoch => value,
            Ok(_) => {
                self.poisoned = true;
                return Err(VaultError::Corrupt);
            }
            Err(error) => {
                self.poisoned = true;
                return Err(VaultError::Storage(error));
            }
        };
        let sealed = self
            .sealer
            .seal(self.namespace, reserved, &plaintext)
            .map_err(VaultError::Storage)?;
        if let Err(error) = self.store.commit(self.epoch, reserved, &sealed) {
            self.poisoned = true;
            return Err(VaultError::Storage(error));
        }
        self.epoch = reserved;
        self.objects = next;
        Ok(())
    }
}

fn validate_input(kind: u16, metadata: &[u8], content: &[u8]) -> Result<(), VaultError> {
    if kind == 0 || metadata.len() > MAX_METADATA || content.len() > MAX_CONTENT {
        Err(VaultError::InvalidInput)
    } else {
        Ok(())
    }
}

fn encode(objects: &BTreeMap<ObjectId, VaultObject>) -> Result<Vec<u8>, VaultError> {
    if objects.len() > MAX_OBJECTS {
        return Err(VaultError::Capacity);
    }
    let mut data = Vec::new();
    data.extend_from_slice(MAGIC);
    data.extend_from_slice(&VERSION.to_be_bytes());
    data.extend_from_slice(&(objects.len() as u16).to_be_bytes());
    for (id, object) in objects {
        validate_input(object.kind, &object.metadata, &object.content)?;
        data.extend_from_slice(id.as_bytes());
        data.extend_from_slice(object.owner.as_bytes());
        data.extend_from_slice(&object.content_ref);
        data.extend_from_slice(&object.kind.to_be_bytes());
        data.extend_from_slice(&object.revision.to_be_bytes());
        data.extend_from_slice(&(object.metadata.len() as u16).to_be_bytes());
        data.extend_from_slice(&(object.content.len() as u32).to_be_bytes());
        data.extend_from_slice(&object.metadata);
        data.extend_from_slice(&object.content);
    }
    if data.len() > MAX_SNAPSHOT {
        return Err(VaultError::Capacity);
    }
    Ok(data)
}

fn decode(data: &[u8], epoch: u64) -> Result<BTreeMap<ObjectId, VaultObject>, VaultError> {
    if data.len() < 12 || data.len() > MAX_SNAPSHOT || &data[..8] != MAGIC {
        return Err(VaultError::Corrupt);
    }
    let mut cursor = Cursor { data, offset: 8 };
    if cursor.u16()? != VERSION {
        return Err(VaultError::Corrupt);
    }
    let count = usize::from(cursor.u16()?);
    if count > MAX_OBJECTS {
        return Err(VaultError::Corrupt);
    }
    let mut objects = BTreeMap::new();
    let mut previous = None;
    let mut refs = alloc::collections::BTreeSet::new();
    for _ in 0..count {
        let id = ObjectId::from_bytes(cursor.fixed()?);
        let owner = VaultOwnerId::from_bytes(cursor.fixed()?);
        let content_ref: [u8; 16] = cursor.fixed()?;
        let kind = cursor.u16()?;
        let revision = cursor.u64()?;
        let metadata_len = usize::from(cursor.u16()?);
        let content_len = usize::try_from(cursor.u32()?).map_err(|_| VaultError::Corrupt)?;
        if id.as_bytes() == &[0; 16]
            || owner.as_bytes() == &[0; 16]
            || content_ref == [0; 16]
            || previous.is_some_and(|p| id <= p)
            || !refs.insert(content_ref)
            || kind == 0
            || revision == 0
            || revision > epoch
            || metadata_len > MAX_METADATA
            || content_len > MAX_CONTENT
        {
            return Err(VaultError::Corrupt);
        }
        let metadata = cursor.take(metadata_len)?.to_vec();
        let content = cursor.take(content_len)?.to_vec();
        objects.insert(
            id,
            VaultObject {
                id,
                owner,
                kind,
                content_ref,
                revision,
                metadata,
                content,
            },
        );
        previous = Some(id);
    }
    if cursor.offset != data.len() {
        return Err(VaultError::Corrupt);
    }
    Ok(objects)
}

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], VaultError> {
        let end = self
            .offset
            .checked_add(count)
            .filter(|&end| end <= self.data.len())
            .ok_or(VaultError::Corrupt)?;
        let value = &self.data[self.offset..end];
        self.offset = end;
        Ok(value)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], VaultError> {
        self.take(N)?.try_into().map_err(|_| VaultError::Corrupt)
    }
    fn u16(&mut self) -> Result<u16, VaultError> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    fn u32(&mut self) -> Result<u32, VaultError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64, VaultError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
}

#[cfg(test)]
mod tests;
