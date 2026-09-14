use super::*;
use alloc::rc::Rc;
use core::cell::RefCell;
use icc_test_support::{DeterministicRandom, InMemoryVaultStateStore};

const ALICE: AppId = AppId::from_bytes([1; 16]);
const BOB: AppId = AppId::from_bytes([2; 16]);
const OWNER: VaultOwnerId = VaultOwnerId::from_bytes([3; 16]);
const OTHER: VaultOwnerId = VaultOwnerId::from_bytes([4; 16]);
const NS: [u8; 16] = [9; 16];

// Test fixture only. Deliberately NOT a cryptographic sealer; the production
// software implementation is exercised separately in icc-vault-crypto tests.
struct FakeSeal;
impl VaultSeal for FakeSeal {
    fn seal(
        &self,
        namespace: [u8; 16],
        epoch: u64,
        plain: &[u8],
    ) -> Result<Vec<u8>, PlatformError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&namespace);
        bytes.extend_from_slice(&epoch.to_be_bytes());
        bytes.extend(plain.iter().map(|b| b ^ 0xa5));
        let checksum = bytes
            .iter()
            .fold(0u64, |n, &b| n.wrapping_mul(131).wrapping_add(u64::from(b)));
        bytes.extend_from_slice(&checksum.to_be_bytes());
        Ok(bytes)
    }
    fn open(
        &self,
        namespace: [u8; 16],
        epoch: u64,
        sealed: &[u8],
    ) -> Result<Vec<u8>, PlatformError> {
        if sealed.len() < 32 || sealed[..16] != namespace || sealed[16..24] != epoch.to_be_bytes() {
            return Err(PlatformError::Corrupt);
        }
        let (data, digest) = sealed.split_at(sealed.len() - 8);
        let checksum = data
            .iter()
            .fold(0u64, |n, &b| n.wrapping_mul(131).wrapping_add(u64::from(b)));
        if digest != checksum.to_be_bytes() {
            return Err(PlatformError::Corrupt);
        }
        Ok(data[24..].iter().map(|b| b ^ 0xa5).collect())
    }
}

type Grants =
    Rc<RefCell<alloc::collections::BTreeSet<(AppId, VaultOwnerId, Option<ObjectId>, VaultAction)>>>;
struct Policy(Grants);
impl VaultAuthorizer for Policy {
    fn permits(
        &self,
        caller: AppId,
        owner: VaultOwnerId,
        id: Option<ObjectId>,
        action: VaultAction,
    ) -> bool {
        self.0.borrow().contains(&(caller, owner, id, action))
    }
}
type TestVault = VaultCore<InMemoryVaultStateStore, FakeSeal, DeterministicRandom, Policy>;
fn setup() -> (TestVault, InMemoryVaultStateStore, Grants) {
    let store = InMemoryVaultStateStore::new(NS);
    let fork = store.fork_for_test();
    let grants = Rc::new(RefCell::new(alloc::collections::BTreeSet::new()));
    grants
        .borrow_mut()
        .insert((ALICE, OWNER, None, VaultAction::Create));
    let vault = TestVault::initialize(
        store,
        FakeSeal,
        DeterministicRandom::new(1),
        Policy(grants.clone()),
    )
    .unwrap_or_else(|_| panic!("provision failed"));
    (vault, fork, grants)
}
fn permit(
    grants: &Grants,
    caller: AppId,
    owner: VaultOwnerId,
    id: Option<ObjectId>,
    action: VaultAction,
) {
    grants.borrow_mut().insert((caller, owner, id, action));
}
fn reopen(store: InMemoryVaultStateStore, grants: Grants) -> Result<TestVault, VaultError> {
    TestVault::open(
        store,
        FakeSeal,
        DeterministicRandom::new(77),
        Policy(grants),
    )
}

#[test]
fn explicit_provision_and_authority_before_lookup() {
    let store = InMemoryVaultStateStore::new(NS);
    assert!(matches!(
        reopen(store, Rc::new(RefCell::new(Default::default()))),
        Err(VaultError::Unprovisioned)
    ));
    let (mut vault, fork, grants) = setup();
    let id = vault
        .create(ALICE, OWNER, 1, b"private title", b"secret content")
        .unwrap();
    assert_ne!(id.as_bytes(), &[0; 16]);
    assert_eq!(vault.read(ALICE, OWNER, id).err(), Some(VaultError::Denied));
    assert_eq!(vault.read(BOB, OWNER, id).err(), Some(VaultError::Denied));
    assert_eq!(vault.list(BOB, OWNER), Err(VaultError::Denied));
    permit(&grants, ALICE, OWNER, Some(id), VaultAction::Read);
    permit(&grants, BOB, OTHER, Some(id), VaultAction::Read);
    assert_eq!(vault.read(BOB, OTHER, id).err(), Some(VaultError::Denied));
    let view = vault.read(ALICE, OWNER, id).unwrap();
    assert_eq!(view.metadata(), b"private title");
    assert_eq!(view.content(), b"secret content");
    assert_eq!(
        vault
            .read(ALICE, OWNER, ObjectId::from_bytes([99; 16]))
            .err(),
        Some(VaultError::Denied)
    );
    assert_eq!(vault.list(ALICE, OWNER), Err(VaultError::Denied));
    permit(&grants, ALICE, OWNER, None, VaultAction::List);
    assert_eq!(vault.list(ALICE, OWNER), Ok(alloc::vec![id]));
    assert_eq!(
        vault.create(BOB, OWNER, 1, b"", b""),
        Err(VaultError::Denied)
    );
    drop(vault);
    assert!(matches!(
        TestVault::initialize(fork, FakeSeal, DeterministicRandom::new(1), Policy(grants)),
        Err(VaultError::AlreadyProvisioned)
    ));
}

#[test]
fn replace_delete_restart_and_owner_mismatch() {
    let (mut vault, fork, grants) = setup();
    let id = vault.create(ALICE, OWNER, 2, b"m0", b"v0").unwrap();
    permit(&grants, ALICE, OWNER, Some(id), VaultAction::Write);
    permit(&grants, ALICE, OWNER, Some(id), VaultAction::Read);
    permit(&grants, ALICE, OWNER, Some(id), VaultAction::Delete);
    permit(&grants, ALICE, OTHER, Some(id), VaultAction::Write);
    assert_eq!(
        vault.replace(ALICE, OTHER, id, b"m1", b"v1"),
        Err(VaultError::Denied)
    );
    let first_ref = *vault.read(ALICE, OWNER, id).unwrap().content_ref();
    assert_eq!(vault.replace(ALICE, OWNER, id, b"m1", b"v1"), Ok(2));
    assert_ne!(
        *vault.read(ALICE, OWNER, id).unwrap().content_ref(),
        first_ref
    );
    drop(vault);
    let mut reopened = reopen(fork.fork_for_test(), grants.clone()).unwrap();
    assert_eq!(reopened.read(ALICE, OWNER, id).unwrap().content(), b"v1");
    reopened.delete(ALICE, OWNER, id).unwrap();
    drop(reopened);
    assert_eq!(
        reopen(fork, grants).unwrap().read(ALICE, OWNER, id).err(),
        Some(VaultError::Denied)
    );
}

#[test]
fn corruption_rollback_and_context_are_rejected() {
    let (mut vault, mut fork, grants) = setup();
    let old = fork.snapshot_for_test().unwrap();
    let id = vault
        .create(ALICE, OWNER, 2, b"private metadata", b"private content")
        .unwrap();
    let current = fork.snapshot_for_test().unwrap();
    assert_ne!(old.0, current.0);
    drop(vault);
    fork.replace_snapshot_for_test(Some(old));
    assert!(matches!(
        reopen(fork.fork_for_test(), grants.clone()),
        Err(VaultError::Storage(PlatformError::Corrupt))
    ));
    fork.replace_snapshot_for_test(Some(current.clone()));
    let mut tampered = current.clone();
    tampered.1[32] ^= 1;
    fork.replace_snapshot_for_test(Some(tampered));
    assert!(matches!(
        reopen(fork.fork_for_test(), grants.clone()),
        Err(VaultError::Corrupt)
    ));
    fork.replace_snapshot_for_test(Some(current.clone()));
    let mut plaintext = FakeSeal.open(NS, current.0, &current.1).unwrap();
    assert!(plaintext.windows(16).any(|window| window == id.as_bytes()));
    // Authenticated but malformed metadata length and unknown version fail
    // independently of the AEAD tag verification in the production adapter.
    plaintext[8] = 0xff;
    fork.replace_snapshot_for_test(Some((
        current.0,
        FakeSeal.seal(NS, current.0, &plaintext).unwrap(),
    )));
    assert!(matches!(
        reopen(fork.fork_for_test(), grants.clone()),
        Err(VaultError::Corrupt)
    ));
    plaintext[8] = 0;
    plaintext[70] = 0xff;
    fork.replace_snapshot_for_test(Some((
        current.0,
        FakeSeal.seal(NS, current.0, &plaintext).unwrap(),
    )));
    assert!(matches!(
        reopen(fork.fork_for_test(), grants.clone()),
        Err(VaultError::Corrupt)
    ));
    fork.replace_snapshot_for_test(Some(current));
    assert!(reopen(fork, grants).is_ok());
}

#[test]
fn partial_commit_ambiguous_commit_and_lease_fence() {
    let (mut vault, fork, grants) = setup();
    assert!(matches!(
        reopen(fork.fork_for_test(), grants.clone()),
        Err(VaultError::Storage(PlatformError::Unavailable))
    ));
    vault.store.fail_before_commit();
    assert_eq!(
        vault.create(ALICE, OWNER, 1, b"a", b"b"),
        Err(VaultError::Storage(PlatformError::Unavailable))
    );
    assert_eq!(vault.list(ALICE, OWNER), Err(VaultError::Unavailable));
    drop(vault);
    let mut reopened = reopen(fork.fork_for_test(), grants.clone()).unwrap();
    permit(&grants, ALICE, OWNER, None, VaultAction::List);
    assert_eq!(reopened.list(ALICE, OWNER), Ok(Vec::new()));
    reopened.store.fail_after_commit();
    assert_eq!(
        reopened.create(ALICE, OWNER, 1, b"a", b"b"),
        Err(VaultError::Storage(PlatformError::Unavailable))
    );
    drop(reopened);
    let after = reopen(fork, grants).unwrap();
    assert_eq!(after.list(ALICE, OWNER).unwrap().len(), 1);
}

#[test]
fn failed_reservation_poison_requires_trusted_reopen() {
    let (mut vault, fork, grants) = setup();
    vault.store.fail_next_reservation();
    assert_eq!(
        vault.create(ALICE, OWNER, 1, b"a", b"b"),
        Err(VaultError::Storage(PlatformError::Unavailable))
    );
    assert_eq!(vault.create(ALICE, OWNER, 1, b"a", b"b"), Err(VaultError::Unavailable));
    drop(vault);
    let mut trusted = reopen(fork, grants).unwrap();
    assert!(trusted.create(ALICE, OWNER, 1, b"a", b"b").is_ok());
}

#[test]
fn bounds_entropy_and_parser_mutations() {
    let (mut vault, fork, grants) = setup();
    assert_eq!(
        vault.create(ALICE, OWNER, 0, b"", b""),
        Err(VaultError::InvalidInput)
    );
    assert_eq!(
        vault.create(ALICE, OWNER, 1, &alloc::vec![0; MAX_METADATA + 1], b""),
        Err(VaultError::InvalidInput)
    );
    assert_eq!(
        vault.create(ALICE, OWNER, 1, b"", &alloc::vec![0; MAX_CONTENT + 1]),
        Err(VaultError::InvalidInput)
    );
    vault.create(ALICE, OWNER, 1, b"", b"").unwrap();
    let mut too_many = BTreeMap::new();
    for value in 1..=(MAX_OBJECTS + 1) {
        let id = ObjectId::from_bytes([value as u8; 16]);
        too_many.insert(
            id,
            VaultObject {
                id,
                owner: OWNER,
                kind: 1,
                content_ref: [(value + 100) as u8; 16],
                revision: 1,
                metadata: Vec::new(),
                content: Vec::new(),
            },
        );
    }
    assert_eq!(encode(&too_many), Err(VaultError::Capacity));
    let snapshot = fork.snapshot_for_test().unwrap();
    let plain = FakeSeal.open(NS, snapshot.0, &snapshot.1).unwrap();
    for position in 0..plain.len() {
        let mut mutated = plain.clone();
        mutated.truncate(position);
        assert!(decode(&mutated, snapshot.0).is_err());
    }
    let mut extra = plain;
    extra.push(1);
    assert!(decode(&extra, snapshot.0).is_err());
    drop(vault);
    drop(grants);
}

#[test]
fn bounded_decoder_mutation_harness_never_accepts_noncanonical_records() {
    let (mut vault, fork, _) = setup();
    vault.create(ALICE, OWNER, 1, b"metadata", b"content").unwrap();
    let snapshot = fork.snapshot_for_test().unwrap();
    let plain = FakeSeal.open(NS, snapshot.0, &snapshot.1).unwrap();
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..512 {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let mut mutated = plain.clone();
        let offset = (rng as usize) % mutated.len();
        mutated[offset] ^= ((rng >> 24) as u8) | 1;
        if let Ok(objects) = decode(&mutated, snapshot.0) {
            assert_eq!(encode(&objects), Ok(mutated));
        }
    }
}
