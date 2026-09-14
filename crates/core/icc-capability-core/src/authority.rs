//! Authority-owned persistent grants and session-local opaque handles.
//!
//! Only a trusted service may call the root/activation/revocation methods or
//! construct caller contexts. The future IPC runtime must authenticate these
//! identities; this portable core deliberately has no App-facing endpoint.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use icc_error::PlatformError;
use icc_platform_api::{CapabilityClock, CapabilitySeal, CapabilityStateStore, SecureRandom};
use icc_rights::Rights;
use icc_types::{AppId, ObjectId, VaultOwnerId};

pub const MAX_GRANTS: usize = 128;
pub const MAX_HANDLES_PER_RUNTIME: usize = 256;
pub const MAX_DELEGATION_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_SNAPSHOT: usize = 16_384;
const MAGIC: &[u8; 8] = b"ICCCAP6\0";
const VERSION: u16 = 1;
const RECORD_SIZE: usize = 8 + 8 + 16 + 1 + 16 + 16 + 4 + 8 + 1 + 8 + 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Scope {
    VaultOwner(VaultOwnerId),
    VaultObject(VaultOwnerId, ObjectId),
}

impl Scope {
    pub const fn owner(self) -> VaultOwnerId {
        match self {
            Self::VaultOwner(owner) | Self::VaultObject(owner, _) => owner,
        }
    }

    pub fn includes(self, other: Self) -> bool {
        match (self, other) {
            (Self::VaultOwner(a), Self::VaultOwner(b) | Self::VaultObject(b, _)) => a == b,
            (Self::VaultObject(a, x), Self::VaultObject(b, y)) => a == b && x == y,
            _ => false,
        }
    }

    fn valid(self) -> bool {
        *self.owner().as_bytes() != [0; 16]
            && match self {
                Self::VaultOwner(_) => true,
                Self::VaultObject(_, object) => *object.as_bytes() != [0; 16],
            }
    }

    fn permits_rights(self, rights: Rights) -> bool {
        rights != Rights::NONE
            && (matches!(self, Self::VaultOwner(_))
                || !rights.contains(Rights::CREATE) && !rights.contains(Rights::LIST))
    }
}

/// Untrusted byte strings may be parsed into handles; possession alone is not
/// authority. The server checks random value, caller, session, grant and tree.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LocalHandle([u8; 16]);

impl LocalHandle {
    pub const fn from_untrusted_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// A public grant ID is only a name. It never authorizes access or activation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GrantId(u64);

impl GrantId {
    pub const fn from_untrusted_raw(raw: u64) -> Self {
        Self(raw)
    }
}

/// This must be constructed exclusively by the trusted runtime from its
/// authenticated execution-domain identity and fresh session nonce. A caller
/// supplied AppId or session nonce is not a valid runtime binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundCaller {
    app: AppId,
    session: [u8; 16],
}

impl BoundCaller {
    pub const fn from_trusted_runtime(app: AppId, session: [u8; 16]) -> Self {
        Self { app, session }
    }
    fn valid(self) -> bool {
        *self.app.as_bytes() != [0; 16] && self.session != [0; 16]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    Denied,
    Revoked,
    Expired,
    InvalidScope,
    InvalidInput,
    Capacity,
    Entropy,
    Clock,
    Corrupt,
    Unprovisioned,
    AlreadyProvisioned,
    Unavailable,
    Storage(PlatformError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    pub grants: usize,
    pub handles_issued: usize,
    pub max_grants: usize,
    pub max_handles_per_runtime: usize,
}

#[derive(Clone)]
struct Grant {
    id: GrantId,
    parent: Option<GrantId>,
    subject: AppId,
    scope: Scope,
    rights: Rights,
    expires_at: Option<u64>,
    delegable: bool,
    generation: u64,
    revoked: bool,
}

#[derive(Clone, Copy)]
struct HandleEntry {
    grant: GrantId,
    generation: u64,
    caller: BoundCaller,
}

/// A lifetime-exclusive, authority-owned instance. Session handles are never
/// serialized. &mut self is held through the supplied operation: revocation
/// waits for an in-flight operation, and subsequent operations observe it.
/// Never hand a raw preflight decision to another endpoint for later use.
pub struct CapabilityAuthority<
    S: CapabilityStateStore,
    C: CapabilitySeal,
    R: SecureRandom,
    T: CapabilityClock,
> {
    store: S,
    seal: C,
    random: R,
    clock: T,
    namespace: [u8; 16],
    epoch: u64,
    next_id: u64,
    floor: u64,
    grants: BTreeMap<GrantId, Grant>,
    // Closed entries remain as tombstones for the life of this instance.
    handles: BTreeMap<LocalHandle, Option<HandleEntry>>,
    poisoned: bool,
}

impl<S: CapabilityStateStore, C: CapabilitySeal, R: SecureRandom, T: CapabilityClock> Drop
    for CapabilityAuthority<S, C, R, T>
{
    fn drop(&mut self) {
        self.store.release_exclusive();
    }
}

impl<S: CapabilityStateStore, C: CapabilitySeal, R: SecureRandom, T: CapabilityClock>
    CapabilityAuthority<S, C, R, T>
{
    pub fn initialize(mut store: S, seal: C, random: R, clock: T) -> Result<Self, AuthorityError> {
        store.acquire_exclusive().map_err(AuthorityError::Storage)?;
        let namespace = store.namespace().map_err(AuthorityError::Storage)?;
        if namespace == [0; 16] {
            store.release_exclusive();
            return Err(AuthorityError::Corrupt);
        }
        if store.load().map_err(AuthorityError::Storage)?.is_some() {
            store.release_exclusive();
            return Err(AuthorityError::AlreadyProvisioned);
        }
        let floor = clock
            .trusted_time_ms()
            .map_err(|_| AuthorityError::Clock)?
            .get();
        let mut authority = Self {
            store,
            seal,
            random,
            clock,
            namespace,
            epoch: 0,
            next_id: 1,
            floor,
            grants: BTreeMap::new(),
            handles: BTreeMap::new(),
            poisoned: false,
        };
        authority.commit(BTreeMap::new(), 1, floor)?;
        Ok(authority)
    }

    pub fn open(mut store: S, seal: C, random: R, clock: T) -> Result<Self, AuthorityError> {
        store.acquire_exclusive().map_err(AuthorityError::Storage)?;
        let namespace = store.namespace().map_err(AuthorityError::Storage)?;
        if namespace == [0; 16] {
            store.release_exclusive();
            return Err(AuthorityError::Corrupt);
        }
        let (epoch, sealed) = store
            .load()
            .map_err(AuthorityError::Storage)?
            .ok_or(AuthorityError::Unprovisioned)?;
        if epoch == 0 || sealed.len() > MAX_SNAPSHOT + 64 {
            return Err(AuthorityError::Corrupt);
        }
        let plaintext = seal
            .open(namespace, epoch, &sealed)
            .map_err(|_| AuthorityError::Corrupt)?;
        let (next_id, floor, grants) = decode(&plaintext, epoch)?;
        if clock
            .trusted_time_ms()
            .map_err(|_| AuthorityError::Clock)?
            .get()
            < floor
        {
            return Err(AuthorityError::Clock);
        }
        Ok(Self {
            store,
            seal,
            random,
            clock,
            namespace,
            epoch,
            next_id,
            floor,
            grants,
            handles: BTreeMap::new(),
            poisoned: false,
        })
    }

    pub fn usage(&self) -> Usage {
        Usage {
            grants: self.grants.len(),
            handles_issued: self.handles.len(),
            max_grants: MAX_GRANTS,
            max_handles_per_runtime: MAX_HANDLES_PER_RUNTIME,
        }
    }

    fn ready(&self) -> Result<(), AuthorityError> {
        if self.poisoned {
            Err(AuthorityError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn now(&mut self) -> Result<u64, AuthorityError> {
        self.ready()?;
        let now = self
            .clock
            .trusted_time_ms()
            .map_err(|_| AuthorityError::Clock)?
            .get();
        if now < self.floor {
            return Err(AuthorityError::Clock);
        }
        self.floor = now;
        Ok(now)
    }

    fn mint(&mut self, recipient: BoundCaller) -> Result<LocalHandle, AuthorityError> {
        if self.handles.len() >= MAX_HANDLES_PER_RUNTIME {
            return Err(AuthorityError::Capacity);
        }
        for _ in 0..8 {
            let mut raw = [0; 16];
            self.random
                .fill(&mut raw)
                .map_err(|_| AuthorityError::Entropy)?;
            for (byte, session) in raw.iter_mut().zip(recipient.session) {
                *byte ^= session;
            }
            let handle = LocalHandle(raw);
            if raw != [0; 16] && !self.handles.contains_key(&handle) {
                return Ok(handle);
            }
        }
        Err(AuthorityError::Entropy)
    }

    fn next_grant_id(&self) -> Result<GrantId, AuthorityError> {
        if self.grants.len() >= MAX_GRANTS {
            return Err(AuthorityError::Capacity);
        }
        self.next_id
            .checked_add(1)
            .ok_or(AuthorityError::Capacity)?;
        Ok(GrantId(self.next_id))
    }

    fn commit(
        &mut self,
        next: BTreeMap<GrantId, Grant>,
        next_id: u64,
        floor: u64,
    ) -> Result<(), AuthorityError> {
        self.ready()?;
        // Any uncertain mutation must require a trusted reopen before use.
        self.poisoned = true;
        let epoch = self
            .store
            .reserve_epoch(self.epoch)
            .map_err(AuthorityError::Storage)?;
        let plaintext = encode(&next, next_id, floor, epoch);
        let sealed = self
            .seal
            .seal(self.namespace, epoch, &plaintext)
            .map_err(AuthorityError::Storage)?;
        self.store
            .commit(self.epoch, epoch, &sealed)
            .map_err(AuthorityError::Storage)?;
        self.grants = next;
        self.next_id = next_id;
        self.epoch = epoch;
        self.floor = floor;
        self.poisoned = false;
        Ok(())
    }

    /// Privileged owner path. An App cannot grant itself a root authority.
    pub fn grant_root(
        &mut self,
        owner: VaultOwnerId,
        recipient: BoundCaller,
        scope: Scope,
        rights: Rights,
        expires_at: Option<u64>,
    ) -> Result<(GrantId, LocalHandle), AuthorityError> {
        let now = self.now()?;
        if !recipient.valid()
            || !scope.valid()
            || scope.owner() != owner
            || !scope.permits_rights(rights)
            || expires_at.is_some_and(|expiry| expiry <= now)
        {
            return Err(AuthorityError::InvalidInput);
        }
        let id = self.next_grant_id()?;
        let handle = self.mint(recipient)?;
        let grant = Grant {
            id,
            parent: None,
            subject: recipient.app,
            scope,
            rights,
            expires_at,
            delegable: rights.contains(Rights::DELEGATE),
            generation: 1,
            revoked: false,
        };
        let mut next = self.grants.clone();
        next.insert(id, grant);
        self.commit(next, id.0 + 1, now)?;
        self.handles.insert(
            handle,
            Some(HandleEntry {
                grant: id,
                generation: 1,
                caller: recipient,
            }),
        );
        Ok((id, handle))
    }

    fn live_grant(&self, id: GrantId, now: u64) -> Result<&Grant, AuthorityError> {
        let grant = self.grants.get(&id).ok_or(AuthorityError::Denied)?;
        let mut node = grant;
        loop {
            if node.revoked {
                return Err(AuthorityError::Revoked);
            }
            if node.expires_at.is_some_and(|expiry| now >= expiry) {
                return Err(AuthorityError::Expired);
            }
            match node.parent {
                Some(parent) => node = self.grants.get(&parent).ok_or(AuthorityError::Corrupt)?,
                None => break,
            }
        }
        Ok(grant)
    }

    fn bound_grant(
        &self,
        caller: BoundCaller,
        handle: LocalHandle,
        now: u64,
    ) -> Result<&Grant, AuthorityError> {
        if !caller.valid() {
            return Err(AuthorityError::Denied);
        }
        let entry = self
            .handles
            .get(&handle)
            .and_then(|entry| entry.as_ref())
            .ok_or(AuthorityError::Denied)?;
        if entry.caller != caller {
            return Err(AuthorityError::Denied);
        }
        let grant = self.live_grant(entry.grant, now)?;
        if grant.generation != entry.generation || grant.subject != caller.app {
            return Err(AuthorityError::Revoked);
        }
        Ok(grant)
    }

    pub fn delegate(
        &mut self,
        caller: BoundCaller,
        parent_handle: LocalHandle,
        recipient: BoundCaller,
        scope: Scope,
        rights: Rights,
        expires_at: Option<u64>,
    ) -> Result<(GrantId, LocalHandle), AuthorityError> {
        let now = self.now()?;
        if !recipient.valid()
            || !scope.valid()
            || !scope.permits_rights(rights)
            || expires_at.is_some_and(|expiry| expiry <= now)
        {
            return Err(AuthorityError::InvalidInput);
        }
        if !expires_at.is_some_and(|expiry| expiry - now <= MAX_DELEGATION_LIFETIME_MS) {
            return Err(AuthorityError::InvalidScope);
        }
        let parent = self.bound_grant(caller, parent_handle, now)?;
        if !parent.delegable || !parent.rights.contains(Rights::DELEGATE) {
            return Err(AuthorityError::Denied);
        }
        if !parent.scope.includes(scope)
            || !rights.is_subset_of(parent.rights)
            || match (parent.expires_at, expires_at) {
                (Some(limit), Some(child)) => child > limit,
                (Some(_), None) => true,
                _ => false,
            }
        {
            return Err(AuthorityError::InvalidScope);
        }
        let parent_id = parent.id;
        let id = self.next_grant_id()?;
        let handle = self.mint(recipient)?;
        let grant = Grant {
            id,
            parent: Some(parent_id),
            subject: recipient.app,
            scope,
            rights,
            expires_at,
            delegable: rights.contains(Rights::DELEGATE),
            generation: 1,
            revoked: false,
        };
        let mut next = self.grants.clone();
        next.insert(id, grant);
        self.commit(next, id.0 + 1, now)?;
        self.handles.insert(
            handle,
            Some(HandleEntry {
                grant: id,
                generation: 1,
                caller: recipient,
            }),
        );
        Ok((id, handle))
    }

    /// Revocation is committed before returning. Descendants fail via their
    /// ancestor chain; existing handles never cache a positive decision.
    pub fn revoke(&mut self, owner: VaultOwnerId, id: GrantId) -> Result<(), AuthorityError> {
        let now = self.now()?;
        let grant = self.grants.get(&id).ok_or(AuthorityError::Denied)?;
        if owner.as_bytes() == &[0; 16] || grant.scope.owner() != owner {
            return Err(AuthorityError::Denied);
        }
        if grant.revoked {
            return Err(AuthorityError::Revoked);
        }
        let mut next = self.grants.clone();
        let target = next.get_mut(&id).ok_or(AuthorityError::Corrupt)?;
        target.generation = target
            .generation
            .checked_add(1)
            .ok_or(AuthorityError::Capacity)?;
        target.revoked = true;
        self.commit(next, self.next_id, now)
    }

    /// Trusted owner rebind after a restart. IDs alone cannot activate grants;
    /// revoked or expired ancestors still deny. Old session handles stay dead.
    pub fn activate(
        &mut self,
        owner: VaultOwnerId,
        id: GrantId,
        recipient: BoundCaller,
    ) -> Result<LocalHandle, AuthorityError> {
        let now = self.now()?;
        if !recipient.valid() {
            return Err(AuthorityError::Denied);
        }
        let grant = self.live_grant(id, now)?;
        if owner.as_bytes() == &[0; 16]
            || grant.scope.owner() != owner
            || grant.subject != recipient.app
        {
            return Err(AuthorityError::Denied);
        }
        let generation = grant.generation;
        let handle = self.mint(recipient)?;
        self.handles.insert(
            handle,
            Some(HandleEntry {
                grant: id,
                generation,
                caller: recipient,
            }),
        );
        Ok(handle)
    }

    pub fn close(
        &mut self,
        caller: BoundCaller,
        handle: LocalHandle,
    ) -> Result<(), AuthorityError> {
        self.ready()?;
        let slot = self
            .handles
            .get_mut(&handle)
            .ok_or(AuthorityError::Denied)?;
        if !slot.as_ref().is_some_and(|entry| entry.caller == caller) {
            return Err(AuthorityError::Denied);
        }
        *slot = None;
        Ok(())
    }

    /// The supplied effect runs while the exclusive authority borrow and
    /// trusted storage lease are held. A server must route *all* effects on
    /// this resource through this path, including secondary endpoints.
    pub fn execute<V>(
        &mut self,
        caller: BoundCaller,
        handle: LocalHandle,
        resource: Scope,
        required: Rights,
        effect: impl FnOnce() -> V,
    ) -> Result<V, AuthorityError> {
        let now = self.now()?;
        if !resource.valid()
            || !resource.permits_rights(required)
            || required.contains(Rights::DELEGATE)
        {
            return Err(AuthorityError::InvalidInput);
        }
        let grant = self.bound_grant(caller, handle, now)?;
        if !grant.scope.includes(resource) || !grant.rights.contains(required) {
            return Err(AuthorityError::Denied);
        }
        Ok(effect())
    }
}

fn encode(grants: &BTreeMap<GrantId, Grant>, next_id: u64, floor: u64, epoch: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + 2 + 8 + 8 + 8 + 2 + grants.len() * RECORD_SIZE);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&next_id.to_be_bytes());
    bytes.extend_from_slice(&floor.to_be_bytes());
    bytes.extend_from_slice(&(grants.len() as u16).to_be_bytes());
    for grant in grants.values() {
        bytes.extend_from_slice(&grant.id.0.to_be_bytes());
        bytes.extend_from_slice(&grant.parent.map_or(0, |parent| parent.0).to_be_bytes());
        bytes.extend_from_slice(grant.subject.as_bytes());
        match grant.scope {
            Scope::VaultOwner(owner) => {
                bytes.push(1);
                bytes.extend_from_slice(owner.as_bytes());
                bytes.extend_from_slice(&[0; 16]);
            }
            Scope::VaultObject(owner, object) => {
                bytes.push(2);
                bytes.extend_from_slice(owner.as_bytes());
                bytes.extend_from_slice(object.as_bytes());
            }
        }
        bytes.extend_from_slice(&grant.rights.bits().to_be_bytes());
        bytes.extend_from_slice(&grant.expires_at.unwrap_or(0).to_be_bytes());
        bytes.push(u8::from(grant.delegable));
        bytes.extend_from_slice(&grant.generation.to_be_bytes());
        bytes.push(u8::from(grant.revoked));
    }
    bytes
}

fn decode(
    bytes: &[u8],
    epoch: u64,
) -> Result<(u64, u64, BTreeMap<GrantId, Grant>), AuthorityError> {
    if bytes.len() < 36 || bytes.len() > MAX_SNAPSHOT || &bytes[..8] != MAGIC {
        return Err(AuthorityError::Corrupt);
    }
    let mut pos = 8;
    fn take<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], AuthorityError> {
        let end = pos.checked_add(len).ok_or(AuthorityError::Corrupt)?;
        let value = bytes.get(*pos..end).ok_or(AuthorityError::Corrupt)?;
        *pos = end;
        Ok(value)
    }
    fn word(bytes: &[u8], pos: &mut usize) -> Result<u64, AuthorityError> {
        Ok(u64::from_be_bytes(
            take(bytes, pos, 8)?
                .try_into()
                .map_err(|_| AuthorityError::Corrupt)?,
        ))
    }
    if u16::from_be_bytes(
        take(bytes, &mut pos, 2)?
            .try_into()
            .map_err(|_| AuthorityError::Corrupt)?,
    ) != VERSION
        || word(bytes, &mut pos)? != epoch
    {
        return Err(AuthorityError::Corrupt);
    }
    let next_id = word(bytes, &mut pos)?;
    let floor = word(bytes, &mut pos)?;
    let count = u16::from_be_bytes(
        take(bytes, &mut pos, 2)?
            .try_into()
            .map_err(|_| AuthorityError::Corrupt)?,
    ) as usize;
    if next_id == 0 || count > MAX_GRANTS || bytes.len() != 36 + count * RECORD_SIZE {
        return Err(AuthorityError::Corrupt);
    }
    let mut grants = BTreeMap::new();
    let mut last_id = 0;
    for _ in 0..count {
        let id = GrantId(word(bytes, &mut pos)?);
        let parent_id = word(bytes, &mut pos)?;
        let subject = AppId::from_bytes(
            take(bytes, &mut pos, 16)?
                .try_into()
                .map_err(|_| AuthorityError::Corrupt)?,
        );
        let tag = take(bytes, &mut pos, 1)?[0];
        let owner = VaultOwnerId::from_bytes(
            take(bytes, &mut pos, 16)?
                .try_into()
                .map_err(|_| AuthorityError::Corrupt)?,
        );
        let object: [u8; 16] = take(bytes, &mut pos, 16)?
            .try_into()
            .map_err(|_| AuthorityError::Corrupt)?;
        let scope = match tag {
            1 if object == [0; 16] => Scope::VaultOwner(owner),
            2 => Scope::VaultObject(owner, ObjectId::from_bytes(object)),
            _ => return Err(AuthorityError::Corrupt),
        };
        let rights = Rights::from_bits(u32::from_be_bytes(
            take(bytes, &mut pos, 4)?
                .try_into()
                .map_err(|_| AuthorityError::Corrupt)?,
        ))
        .ok_or(AuthorityError::Corrupt)?;
        let expiry = word(bytes, &mut pos)?;
        let delegable = match take(bytes, &mut pos, 1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(AuthorityError::Corrupt),
        };
        let generation = word(bytes, &mut pos)?;
        let revoked = match take(bytes, &mut pos, 1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(AuthorityError::Corrupt),
        };
        if id.0 <= last_id
            || id.0 >= next_id
            || *subject.as_bytes() == [0; 16]
            || !scope.valid()
            || !scope.permits_rights(rights)
            || generation == 0
            || delegable != rights.contains(Rights::DELEGATE)
            || revoked != (generation > 1)
        {
            return Err(AuthorityError::Corrupt);
        }
        let parent = if parent_id == 0 {
            None
        } else {
            if parent_id >= id.0 {
                return Err(AuthorityError::Corrupt);
            }
            let ancestor: &Grant = grants
                .get(&GrantId(parent_id))
                .ok_or(AuthorityError::Corrupt)?;
            if !ancestor.delegable
                || !ancestor.scope.includes(scope)
                || !rights.is_subset_of(ancestor.rights)
                || match (ancestor.expires_at, expiry) {
                    (Some(_), 0) => true,
                    (Some(limit), child) => child > limit,
                    _ => false,
                }
            {
                return Err(AuthorityError::Corrupt);
            }
            Some(GrantId(parent_id))
        };
        let grant = Grant {
            id,
            parent,
            subject,
            scope,
            rights,
            expires_at: (expiry != 0).then_some(expiry),
            delegable,
            generation,
            revoked,
        };
        grants.insert(id, grant);
        last_id = id.0;
    }
    Ok((next_id, floor, grants))
}

#[cfg(test)]
mod tests {
    use super::*;
    use icc_platform_api::CapabilitySeal;
    use icc_test_support::{
        DeterministicRandom, FakeCapabilityClock, InMemoryCapabilityStateStore,
    };

    // Domain parser/state-machine fixture only; real AEAD is exercised in the
    // crypto crate's integrated tests. No integrity claim follows from this.
    struct IdentitySeal;
    impl CapabilitySeal for IdentitySeal {
        fn seal(&self, _ns: [u8; 16], _epoch: u64, data: &[u8]) -> Result<Vec<u8>, PlatformError> {
            Ok(data.to_vec())
        }
        fn open(&self, _ns: [u8; 16], _epoch: u64, data: &[u8]) -> Result<Vec<u8>, PlatformError> {
            Ok(data.to_vec())
        }
    }

    const OWNER: VaultOwnerId = VaultOwnerId::from_bytes([3; 16]);
    const OTHER_OWNER: VaultOwnerId = VaultOwnerId::from_bytes([4; 16]);
    const OBJECT: ObjectId = ObjectId::from_bytes([5; 16]);
    const OTHER_OBJECT: ObjectId = ObjectId::from_bytes([6; 16]);
    const A: BoundCaller = BoundCaller::from_trusted_runtime(AppId::from_bytes([1; 16]), [11; 16]);
    const B: BoundCaller = BoundCaller::from_trusted_runtime(AppId::from_bytes([2; 16]), [12; 16]);
    type TestAuthority = CapabilityAuthority<
        InMemoryCapabilityStateStore,
        IdentitySeal,
        DeterministicRandom,
        FakeCapabilityClock,
    >;
    fn new(store: InMemoryCapabilityStateStore, clock: FakeCapabilityClock) -> TestAuthority {
        TestAuthority::initialize(store, IdentitySeal, DeterministicRandom::new(20), clock).unwrap()
    }
    fn read(
        authority: &mut TestAuthority,
        caller: BoundCaller,
        handle: LocalHandle,
        object: ObjectId,
    ) -> Result<bool, AuthorityError> {
        authority.execute(
            caller,
            handle,
            Scope::VaultObject(OWNER, object),
            Rights::READ,
            || true,
        )
    }

    #[test]
    fn phase_6_mandatory_flow_and_restart_revocation() {
        let clock = FakeCapabilityClock::new(10);
        let store = InMemoryCapabilityStateStore::new([8; 16]);
        let fork = store.fork_for_test();
        let mut authority = new(store, clock.clone());
        let random = LocalHandle::from_untrusted_bytes([7; 16]);
        // User and object already exist in the Vault namespace; IDs are names.
        assert_eq!(
            read(&mut authority, A, random, OBJECT),
            Err(AuthorityError::Denied)
        );
        assert_eq!(
            read(
                &mut authority,
                A,
                LocalHandle::from_untrusted_bytes(*OBJECT.as_bytes()),
                OBJECT
            ),
            Err(AuthorityError::Denied)
        );
        let (parent_id, parent) = authority
            .grant_root(
                OWNER,
                A,
                Scope::VaultOwner(OWNER),
                Rights::READ.union(Rights::DELEGATE),
                Some(100),
            )
            .unwrap();
        assert_eq!(read(&mut authority, A, parent, OBJECT), Ok(true));
        assert_eq!(
            authority.execute(
                A,
                parent,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::WRITE,
                || true
            ),
            Err(AuthorityError::Denied)
        );
        assert_eq!(
            authority.delegate(
                A,
                parent,
                B,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::WRITE,
                Some(50)
            ),
            Err(AuthorityError::InvalidScope)
        );
        assert_eq!(
            authority.delegate(
                A,
                parent,
                B,
                Scope::VaultOwner(OTHER_OWNER),
                Rights::READ,
                Some(50)
            ),
            Err(AuthorityError::InvalidScope)
        );
        assert_eq!(
            authority.delegate(
                A,
                parent,
                B,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                Some(101)
            ),
            Err(AuthorityError::InvalidScope)
        );
        assert_eq!(
            authority.delegate(
                A,
                parent,
                B,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                None
            ),
            Err(AuthorityError::InvalidScope)
        );
        let (child_id, child) = authority
            .delegate(
                A,
                parent,
                B,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                Some(50),
            )
            .unwrap();
        assert_eq!(read(&mut authority, B, child, OBJECT), Ok(true));
        assert_eq!(
            read(&mut authority, B, child, OTHER_OBJECT),
            Err(AuthorityError::Denied)
        );
        assert_eq!(
            read(&mut authority, A, child, OBJECT),
            Err(AuthorityError::Denied)
        );
        assert_eq!(
            read(&mut authority, B, parent, OBJECT),
            Err(AuthorityError::Denied)
        );
        assert_eq!(
            authority.execute(B, child, Scope::VaultOwner(OWNER), Rights::LIST, || true),
            Err(AuthorityError::Denied)
        );
        assert_eq!(
            authority.delegate(
                B,
                child,
                A,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                Some(40)
            ),
            Err(AuthorityError::Denied)
        );
        let alternate_session =
            BoundCaller::from_trusted_runtime(AppId::from_bytes([2; 16]), [99; 16]);
        assert_eq!(
            read(&mut authority, alternate_session, child, OBJECT),
            Err(AuthorityError::Denied)
        );
        assert_eq!(
            authority.revoke(OTHER_OWNER, parent_id),
            Err(AuthorityError::Denied)
        );
        authority.revoke(OWNER, parent_id).unwrap();
        assert_eq!(
            read(&mut authority, A, parent, OBJECT),
            Err(AuthorityError::Revoked)
        );
        assert_eq!(
            read(&mut authority, B, child, OBJECT),
            Err(AuthorityError::Revoked)
        );
        drop(authority);
        let mut reopened =
            TestAuthority::open(fork, IdentitySeal, DeterministicRandom::new(20), clock).unwrap();
        assert_eq!(
            read(&mut reopened, A, parent, OBJECT),
            Err(AuthorityError::Denied)
        );
        assert_eq!(
            read(&mut reopened, B, child, OBJECT),
            Err(AuthorityError::Denied)
        );
        assert_eq!(
            reopened.activate(OWNER, parent_id, A),
            Err(AuthorityError::Revoked)
        );
        assert_eq!(
            reopened.activate(OWNER, child_id, B),
            Err(AuthorityError::Revoked)
        );
    }

    #[test]
    fn reboot_discards_old_handles_even_when_random_sequence_repeats() {
        let clock = FakeCapabilityClock::new(10);
        let store = InMemoryCapabilityStateStore::new([8; 16]);
        let fork = store.fork_for_test();
        let mut authority = new(store, clock.clone());
        let (id, old_handle) = authority
            .grant_root(
                OWNER,
                A,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ.union(Rights::DELEGATE),
                None,
            )
            .unwrap();
        assert_eq!(
            authority.delegate(
                A,
                old_handle,
                B,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                Some(11 + MAX_DELEGATION_LIFETIME_MS),
            ),
            Err(AuthorityError::InvalidScope)
        );
        drop(authority);
        let fresh = BoundCaller::from_trusted_runtime(AppId::from_bytes([1; 16]), [22; 16]);
        let mut reopened =
            TestAuthority::open(fork, IdentitySeal, DeterministicRandom::new(20), clock).unwrap();
        assert_eq!(
            read(&mut reopened, A, old_handle, OBJECT),
            Err(AuthorityError::Denied)
        );
        let new_handle = reopened.activate(OWNER, id, fresh).unwrap();
        assert_ne!(old_handle, new_handle);
        assert_eq!(
            read(&mut reopened, fresh, old_handle, OBJECT),
            Err(AuthorityError::Denied)
        );
        assert_eq!(read(&mut reopened, fresh, new_handle, OBJECT), Ok(true));
    }

    #[test]
    fn effect_finishes_before_revoke_ack_and_cannot_replay() {
        let clock = FakeCapabilityClock::new(10);
        let store = InMemoryCapabilityStateStore::new([8; 16]);
        let mut authority = new(store, clock);
        let (id, handle) = authority
            .grant_root(
                OWNER,
                A,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                None,
            )
            .unwrap();
        let mut executions = 0;
        authority
            .execute(
                A,
                handle,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                || {
                    executions += 1;
                },
            )
            .unwrap();
        authority.revoke(OWNER, id).unwrap();
        assert_eq!(
            authority.execute(
                A,
                handle,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                || {
                    executions += 1;
                }
            ),
            Err(AuthorityError::Revoked)
        );
        assert_eq!(executions, 1);
    }

    #[test]
    fn expiry_including_restart_and_clock_rollback() {
        let clock = FakeCapabilityClock::new(10);
        let store = InMemoryCapabilityStateStore::new([8; 16]);
        let fork = store.fork_for_test();
        let mut authority = new(store, clock.clone());
        let (id, handle) = authority
            .grant_root(
                OWNER,
                A,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                Some(20),
            )
            .unwrap();
        clock.set_for_test(20);
        assert_eq!(
            read(&mut authority, A, handle, OBJECT),
            Err(AuthorityError::Expired)
        );
        drop(authority);
        clock.set_for_test(9);
        assert!(matches!(
            TestAuthority::open(
                fork.fork_for_test(),
                IdentitySeal,
                DeterministicRandom::new(1),
                clock.clone()
            ),
            Err(AuthorityError::Clock)
        ));
        clock.set_for_test(21);
        let mut reopened =
            TestAuthority::open(fork, IdentitySeal, DeterministicRandom::new(1), clock).unwrap();
        assert_eq!(
            reopened.activate(OWNER, id, A),
            Err(AuthorityError::Expired)
        );
    }

    struct ConstantRandom;
    impl SecureRandom for ConstantRandom {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), PlatformError> {
            bytes.fill(9);
            Ok(())
        }
    }

    #[test]
    fn closed_handle_is_tombstoned_and_never_reissued() {
        let clock = FakeCapabilityClock::new(1);
        let store = InMemoryCapabilityStateStore::new([8; 16]);
        let mut authority =
            CapabilityAuthority::initialize(store, IdentitySeal, ConstantRandom, clock).unwrap();
        let (_, handle) = authority
            .grant_root(
                OWNER,
                A,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                None,
            )
            .unwrap();
        authority.close(A, handle).unwrap();
        assert_eq!(
            authority.execute(
                A,
                handle,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                || true
            ),
            Err(AuthorityError::Denied)
        );
        assert!(matches!(
            authority.grant_root(
                OWNER,
                A,
                Scope::VaultObject(OWNER, OTHER_OBJECT),
                Rights::READ,
                None
            ),
            Err(AuthorityError::Entropy)
        ));
        assert_eq!(authority.usage().handles_issued, 1);
    }

    #[test]
    fn commit_failure_poison_lease_and_trusted_rollback() {
        let clock = FakeCapabilityClock::new(1);
        let store = InMemoryCapabilityStateStore::new([8; 16]);
        let mut fork = store.fork_for_test();
        let contender = store.fork_for_test();
        let authority = new(store, clock.clone());
        let original = fork.snapshot_for_test();
        assert!(matches!(
            TestAuthority::open(
                contender.fork_for_test(),
                IdentitySeal,
                DeterministicRandom::new(1),
                clock.clone()
            ),
            Err(AuthorityError::Storage(PlatformError::Unavailable))
        ));
        // Fail-after-commit simulates an ambiguous ack. The live instance must
        // stop serving requests until reopen against trusted committed state.
        // Inject through a fresh adapter after handoff.
        drop(authority);
        let mut faulty = fork.fork_for_test();
        faulty.fail_after_commit();
        let mut authority = TestAuthority::open(
            faulty,
            IdentitySeal,
            DeterministicRandom::new(20),
            clock.clone(),
        )
        .unwrap();
        assert_eq!(
            authority
                .grant_root(
                    OWNER,
                    A,
                    Scope::VaultObject(OWNER, OBJECT),
                    Rights::READ,
                    None
                )
                .err(),
            Some(AuthorityError::Storage(PlatformError::Unavailable))
        );
        assert_eq!(
            read(
                &mut authority,
                A,
                LocalHandle::from_untrusted_bytes([7; 16]),
                OBJECT
            ),
            Err(AuthorityError::Unavailable)
        );
        drop(authority);
        let mut reopened = TestAuthority::open(
            fork.fork_for_test(),
            IdentitySeal,
            DeterministicRandom::new(20),
            clock.clone(),
        )
        .unwrap();
        let (id, handle) = reopened
            .grant_root(
                OWNER,
                A,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                None,
            )
            .unwrap();
        reopened.revoke(OWNER, id).unwrap();
        drop(reopened);
        fork.replace_snapshot_for_test(original);
        assert!(matches!(
            TestAuthority::open(fork, IdentitySeal, DeterministicRandom::new(20), clock),
            Err(AuthorityError::Storage(PlatformError::Corrupt))
        ));
        assert_ne!(handle.as_bytes(), [0; 16]);
        // The earlier lease contender never owned the namespace.
        assert!(contender.snapshot_for_test().is_some());
    }

    #[test]
    fn malformed_snapshot_rejected_even_with_test_sealer() {
        let clock = FakeCapabilityClock::new(1);
        let store = InMemoryCapabilityStateStore::new([8; 16]);
        let mut fork = store.fork_for_test();
        let mut authority = new(store, clock.clone());
        authority
            .grant_root(
                OWNER,
                A,
                Scope::VaultObject(OWNER, OBJECT),
                Rights::READ,
                None,
            )
            .unwrap();
        let (epoch, original) = fork.snapshot_for_test().unwrap();
        drop(authority);
        for index in [0, 8, 10, 34, 36, 44, 68, 101, 113, 114, original.len() - 1] {
            let mut altered = original.clone();
            altered[index] ^= 0xff;
            fork.replace_snapshot_for_test(Some((epoch, altered)));
            assert!(matches!(
                TestAuthority::open(
                    fork.fork_for_test(),
                    IdentitySeal,
                    DeterministicRandom::new(20),
                    clock.clone()
                ),
                Err(AuthorityError::Corrupt)
            ));
        }
        for len in [0, 8, 35, original.len() - 1] {
            fork.replace_snapshot_for_test(Some((epoch, original[..len].to_vec())));
            assert!(matches!(
                TestAuthority::open(
                    fork.fork_for_test(),
                    IdentitySeal,
                    DeterministicRandom::new(20),
                    clock.clone()
                ),
                Err(AuthorityError::Corrupt)
            ));
        }
        let mut trailing = original;
        trailing.push(0);
        fork.replace_snapshot_for_test(Some((epoch, trailing)));
        assert!(matches!(
            TestAuthority::open(fork, IdentitySeal, DeterministicRandom::new(20), clock),
            Err(AuthorityError::Corrupt)
        ));
    }
}
