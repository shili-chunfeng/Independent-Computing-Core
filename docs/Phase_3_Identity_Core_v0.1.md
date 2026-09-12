# Independent Computing Core
## Phase 3 — Identity Core v0.1

**Status:** Proposed implementation specification  
**Stage:** Phase 3  
**Base:** `main` at `ec9d2a050652bad1c0f8a698652ef880ba67064a`  
**Parent documents:** Phase 0, Phase 0.2, Phase 0.3, Phase 1, Phase 2, accepted ADRs, and `PROJECT_EXECUTION_CONTRACT.md`  
**Target:** Linux/VM prototype → portable Core → OurOS  
**Date:** 2026-09-12

---

# 1. Goal

Phase 3 establishes a portable identity domain in which the root/recovery
identity is an internal trust anchor rather than a global application login ID.
It provides explicit, cryptographically authorized state transitions for
device enrollment, device rotation, device revocation, and recovery, plus
independent per-application pseudonyms and key bindings.

The implementation is a domain state machine. It is not yet an identity
service, KeyStore, persistence engine, network identity protocol, or UI.

---

# 2. In Scope

- private root-domain identifier and versioned root authorization-key binding;
- typed device, enrollment, recovery-attempt, recovery-authority, key-reference,
  and per-App pseudonym identifiers;
- active/revoked device state;
- pending → active device-enrollment state machine;
- device-key rotation with stale-proof rejection;
- device revocation authorized by a different active device;
- random, stored, App-specific pseudonyms and distinct App public-key bindings;
- active/suspended/revoked App identity state and key rotation/reactivation;
- purpose separation hooks for root, recovery, device, App, communication, and
  financial identity keys;
- configurable M-of-N recovery authority policy with `M >= 2`;
- recovery approval collection, root rotation, old-device revocation, pending
  enrollment cancellation, and App-identity suspension;
- versioned, domain-separated canonical authorization transcripts;
- bounded collections and bounded random-ID collision retries;
- movable, non-serialized domain state plus validated restart restoration;
- unit, integration, negative, boundary, and restart-state tests.

---

# 3. Out of Scope

- raw private-key generation, storage, export, signing, or destruction;
- full Phase 4 KeyStore and SecretStore implementation;
- persistent byte encoding or database schema;
- IPC or network wire protocol and any identity import/export parser;
- Vault, capability authority, Messaging, Wallet, package/store, or cloud account;
- social-recovery UX, email/SMS recovery, identity proofing, or server-held master
  recovery authority;
- recovery notification transport and audit-log storage;
- rate-limiting scheduler or trusted wall/monotonic time source;
- communication and financial protocols; Phase 3 only reserves distinct key
  purposes so those domains cannot silently reuse root/App/device keys;
- global public username, advertising identifier, or cross-App identity lookup;
- hardware-backed keys and host-root/kernel-compromise protection.

---

# 4. Architecture Boundaries

`icc-identity-core` remains L2, `#![no_std] + alloc`, and
`#![forbid(unsafe_code)]`.

Allowed dependencies:

```text
icc-identity-core
├── icc-types
├── icc-error
├── icc-platform-api::SecureRandom
└── icc-crypto-api::CryptoProviderV1 (verification and public values only)
```

Forbidden dependencies/effects:

```text
icc-crypto-rust
Linux adapter
filesystem / database
wall clock / SystemTime
network / IPC transport
raw secret wrappers
global mutable state
```

The authority-owning future service selects the crypto provider and binds the
caller/device/App identity. A client-supplied boolean, claimed caller name, or
claimed right is never treated as authorization. `indie-cli` is removed from
the identity-domain dependency edge and cannot obtain the real root state.

Domain types are not wire types. Local key references are included in domain
state, while authorization transcripts bind the stable key-reference ID and
public verification key, never a process-local raw handle.

---

# 5. Assets

| Asset | Classification | Phase 3 treatment |
|---|---|---|
| Root/recovery identity state | A-01 Crown Jewel | private state; absent from App disclosure |
| Identity key references | Class B / integrity-critical | typed purpose + stable key ID + public key |
| Device enrollment/revocation state | Security State | signed transitions, generations, fail closed |
| Recovery policy/approvals | Security State | distinct M-of-N approvals over exact target state |
| App pseudonyms/public keys | Class B privacy data | unique per App; no root/device fields disclosed |
| Authorization transcripts | Integrity-critical | fixed v1 canonical encoding and domain separation |

Private key material remains a Phase 4/crypto-boundary asset and is not owned
or exposed by Identity Core.

---

# 6. Threat Model Delta

No new external trust boundary, parser, network surface, physical storage
format, or Linux dependency is introduced.

New attack surfaces are:

- state-transition proof verification;
- canonical authorization-transcript construction;
- random identifier generation and collision handling;
- recovery quorum accounting;
- collection/resource growth;
- restoration of previously produced in-memory domain state.

New trusted code is limited to the portable state machine and transcript
encoder. The existing reviewed crypto provider performs Ed25519 verification.
The composition root/provider remains trusted to implement the provider trait
honestly; process isolation arrives in later service/runtime phases.

---

# 7. Threat IDs

| Threat / invariant | Required evidence |
|---|---|
| T-ID-001 Root Identity Exposure | no root getter/App field; CLI no longer prints an identity; private fields and compile-fail API regressions |
| T-ID-002 Cross-App Identity Correlation | independently random App pseudonyms; distinct App public keys; key reuse rejected |
| T-ID-003 Unauthorized Device Enrollment | active-device signature over pending enrollment; wrong/revoked approver and replay denied |
| T-ID-004 Recovery Channel Takeover | distinct M-of-N signatures; attempt-specific target binding; root rotation; old-device revocation; App suspension |
| T-PLT-004 Weak Randomness | injected `SecureRandom`; entropy failure and repeated invalid/colliding IDs fail closed |
| T-IPC-001 Caller Spoofing (future boundary) | no caller string/boolean in authorization API; runtime caller binding explicitly required |
| INV-007 Key Non-Export | only stable key references and public keys occur in identity state/API |
| INV-011 Rollback Must Not Restore Revoked Trust | state restoration preserves revocation; durable anti-rollback remains explicitly unverified |
| INV-012 Failure Defaults to Deny | malformed state, failed proof, overflow, missing state, revoked/suspended state all reject |
| INV-013 Root Identity Is Not Public Identity | App disclosure contains only App pseudonym/public key/generation |
| INV-014 Local Security Does Not Depend on Cloud | all transitions are local and require no network |

---

# 8. Security Invariants

1. Root-domain identifiers and root key references never appear in
   `AppIdentityView` or CLI output.
2. Each active App has exactly one independently generated pseudonym; no two
   App records may share a pseudonym, key reference, or public key.
3. A key binding has exactly one typed purpose. Wrong-purpose bindings are
   rejected before state mutation.
4. Device enrollment becomes active only after verification under the current
   key of an active, already enrolled device.
5. A revoked device cannot authorize enrollment, rotation, revocation, or App
   identity transitions.
6. Device/App key rotations increment a checked generation. Old proofs and old
   public keys no longer authorize the new generation.
7. Device revocation requires a distinct active approver. Recovery is the
   fallback when no second active device exists.
8. Recovery requires the configured number of distinct current recovery
   authorities; duplicate approvals never increase progress.
9. Recovery approvals bind the current domain, current recovery epoch, exact
   attempt, next root generation, new root key, new device, and complete target
   recovery policy.
10. Successful recovery rotates the root key/generation, increments recovery
    epoch, revokes all old devices, cancels pending enrollments, activates only
    the new recovery device, and suspends active App identities.
11. No failed verification or validation path mutates authoritative active
    identity state.
12. Unknown/corrupt restored state is rejected. Durable freshness and rollback
    detection are not claimed until authenticated security-state persistence
    exists.

---

# 9. Public API Plan

All Phase 3 Rust APIs are A1 workspace interfaces, not A2 App SDK or A3 wire
protocol.

Primary types:

```text
IdentityCore / IdentityState
IdentityKeyBinding / IdentityKeyPurpose
RecoveryAuthority / RecoveryPolicy
DeviceStatus / DeviceView
AppIdentityStatus / AppIdentityView
AuthorizationTranscript
IdentityError
```

Primary transitions:

```text
bootstrap
begin_device_enrollment
device_enrollment_transcript
approve_device_enrollment
device_rotation_transcript / rotate_device_key
device_revocation_transcript / revoke_device
create_app_identity
app_rotation_transcript / rotate_app_identity_key
app_revocation_transcript / revoke_app_identity
begin_recovery
recovery_transcript / approve_recovery / finalize_recovery
into_state / restore
```

Transcript-producing APIs exist so the owner/device/recovery agent signs the
exact state-machine statement. Commit APIs reconstruct the transcript from
current authoritative state before verification; callers cannot substitute a
different statement.

`app_identity_view(app_id)` is authority-side. Its `app_id` argument must come
from future runtime/kernel caller binding, never from an App self-claim. Apps do
not receive direct access to the IdentityCore state object.

---

# 10. Internal API Plan

- checked generation increment helper;
- bounded non-zero random-ID generation with collision predicate;
- key-purpose and cross-domain key-reuse validators;
- canonical transcript builder with fixed-width big-endian integers;
- state-wide invariant validator used by bootstrap and restart restoration;
- uniform signature-verification error mapping;
- mutation-after-verification ordering.

No `unsafe`, global registry, runtime executor, physical path, or OS error type
is introduced.

---

# 11. Persistence Plan

Phase 3 introduces no byte-level persistent schema.

`IdentityState` is a private-field, non-serialized domain state container that
can be moved out of a service and validated on restoration. A future
`SecurityStateStore` adapter must add:

```text
explicit schema version
canonical encoding
authenticated integrity
atomic commit
freshness / monotonic security state
rollback detection
corruption handling
migration policy
```

Serializing Rust memory layout, `BTreeMap`, `usize`, or enum discriminants is
forbidden. Phase 3 does not claim durable restart or snapshot-rollback safety.

---

# 12. Wire Format Plan

There is no decoder or externally accepted wire format in Phase 3.

Authorization signatures use one internal canonical transcript format:

```text
"ICC/identity-core/authorization/v1" || 0x00
|| action:u8
|| identity-domain-id:[u8;32]
|| root-generation:u64-be
|| action-specific fixed-width fields
```

Action-specific fields include their current generations and exact target
public/key-reference values. Recovery additionally canonically encodes the
sorted complete target recovery policy.

The transcript is A1 and one-way encoded only. Any future IPC, persistent, or
network exposure requires a separate versioned wire type, bounded parser,
unknown-field policy, migration review, and fuzz target.

---

# 13. Dependencies

No new third-party dependency is added.

`icc-identity-core` adds one reviewed first-party dependency on
`icc-crypto-api`; this follows ADR-0004 and does not permit a dependency on
`icc-crypto-rust`. The integration-test package uses `icc-crypto-rust` only to
exercise the real provider boundary with deterministic test keys.

Existing third-party versions, features, `Cargo.lock` package versions, and
ClassicalV1 behavior are unchanged.

---

# 14. Unsafe Impact

```text
new first-party unsafe: none
unsafe policy exception: none
new FFI: none
```

Third-party unsafe-code claims remain exactly as documented in Phase 2:
source-level exhaustive verification is NOT VERIFIED.

---

# 15. no_std Impact

`icc-identity-core` remains `no_std + alloc`. It uses only `alloc` collections,
portable ICC types/ports, and the existing no_std crypto API. CI must compile it
for `thumbv7em-none-eabi` with `--no-default-features --locked`.

Passing that target is selected portability evidence, not proof of every future
OurOS target.

---

# 16. Test Plan

- valid bootstrap with distinct root/device/recovery bindings;
- valid signed device enrollment;
- valid device-key rotation and generation increment;
- valid cross-device revocation;
- distinct App pseudonyms and keys;
- valid App key rotation/reactivation;
- valid 2-of-3 recovery and exact post-recovery effects;
- recovery policy canonical-order stability;
- state move/restore with revocation and recovery epoch preserved;
- exact transcript domain/action separation;
- architecture dependency policy and App/root boundary regressions;
- existing default/all-features and bare-metal CI suite.

---

# 17. Negative Test Plan

- zero/duplicate/wrong-purpose key identifiers and public keys;
- entropy failure and repeated zero/colliding generated identifiers;
- duplicate App or Device identity;
- wrong signature and cross-action proof substitution;
- enrollment approved by unknown or revoked device;
- enrollment proof replay after activation;
- stale device-key proof after rotation;
- self-revocation and last/only-device shortcut paths;
- duplicate recovery approval;
- recovery below threshold;
- stale recovery proof after epoch/root rotation;
- recovery target reusing old root/device/App key material;
- App cross-scope key reuse;
- App lookup while suspended/revoked;
- generation overflow;
- restoration with violated uniqueness, threshold, status, or capacity invariant;
- compile-fail attempts to retrieve root identity through App/CLI-facing APIs.

---

# 18. Fuzz Plan

Phase 3 has no parser, decoder, recursive input, variable-length untrusted field,
or wire import/export path, so no fuzz target is added. All transcript inputs
are already validated fixed-size domain types and the encoder has no decode
path.

The first identity import/export, persistence decoder, recovery package, or IPC
decoder MUST add a bounded fuzz target whose success criteria include no state
transition, authority creation, secret disclosure, or unbounded allocation for
invalid input.

---

# 19. Failure / Restart Semantics

- entropy unavailable → no ID/state creation;
- proof invalid/provider error → deny with one domain error and no mutation;
- missing/revoked/suspended state → deny;
- capacity or generation overflow → deny;
- duplicate/replayed approval → deny and do not count it;
- recovery under threshold → remain pending and deny finalization;
- successful recovery → fail closed for all old devices and App identities;
- service restart may restore only an `IdentityState` that passes all invariant
  validation;
- missing, corrupt, unauthenticated, or stale persistent state → deny/unavailable;
- durable rollback resistance is NOT VERIFIED in Phase 3 and cannot be inferred
  from the in-memory restoration test.

---

# 20. Migration / Compatibility

The Phase 1 `provision_local_identity_id` demo API is removed. It generated and
printed a generic identity identifier without the Phase 3 root/App separation
model and must not be grandfathered as an App login API.

`IdentityId` remains only as a legacy neutral value type during this phase; no
Phase 3 state or App disclosure uses it. A later compatibility cleanup may
remove it after workspace consumers are known.

No stable A2/A3 ABI, persistent format, or network protocol exists, so this
change requires no user-data migration. Future KeyStore work must bind
`IdentityKeyId` to a non-exported secret-operation handle without changing App
pseudonyms or exposing root key bytes.

---

# 21. Performance Considerations

- state uses bounded `BTreeMap`/`Vec` collections for deterministic no_std+alloc
  behavior;
- current limits: devices, pending enrollments, Apps, recovery authorities, and
  random-ID retries are explicit constants;
- transition work is O(number of current bindings) for duplicate-key checks and
  O(number of recovery authorities) for quorum/policy encoding;
- limits keep those scans bounded and avoid adding a hashing dependency;
- one Ed25519 verification is performed per approval/transition;
- recovery finalization is intentionally infrequent and may scan all devices and
  App identities to revoke/suspend them;
- no benchmark claim is made before representative service integration exists.

---

# 22. Architecture Boundary Review

| Question | Decision |
|---|---|
| New authority? | active device signatures and M-of-N recovery approvals; both state-bound and authority-side verified |
| New identifier? | typed private domain/device/recovery/key/App pseudonym IDs; only App pseudonym crosses the App disclosure boundary |
| New trust? | existing crypto provider verification; no cloud/server/repository trust |
| New persistent state? | domain state exists, but no byte persistence format is introduced |
| New network surface? | none |
| New parser? | none |
| New dependency? | first-party `icc-crypto-api` edge only; no third-party addition |
| Linux coupling? | none; SecureRandom and crypto provider are injected |
| Secret expansion? | none; only key IDs and public verification keys |
| Blast radius | compromised Identity service can corrupt identity state; it still receives no raw private key bytes from this API |

---

# 23. Exit Criteria

- [ ] specification merged with implementation branch;
- [ ] ADR-0007 proposed with alternatives and consequences;
- [ ] root/device/App/recovery typed model implemented;
- [ ] device enrollment, rotation, and revocation transitions implemented;
- [ ] App-specific pseudonym and key separation implemented;
- [ ] M-of-N recovery and post-recovery containment implemented;
- [ ] positive, negative, boundary, replay, and restart-state tests pass;
- [ ] normal App/CLI path exposes no root identity identifier/key reference;
- [ ] no new production third-party dependency or unsafe code;
- [ ] default and all-features architecture policy passes;
- [ ] `thumbv7em-none-eabi` portability check passes;
- [ ] completion report added;
- [ ] latest branch-head Actions pass;
- [ ] PR opened against `main`;
- [ ] latest PR-head Actions pass;
- [ ] state reported as `READY FOR OWNER REVIEW — DO NOT MERGE`.

---

# 24. References

- OpenID Connect Core 1.0, §8 Subject Identifier Types and §8.1 Pairwise
  Identifier Algorithm: <https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes>
- Web Authentication Level 3, RP scoping and privacy considerations:
  <https://www.w3.org/TR/webauthn-3/>
- NIST SP 800-63B-4, authenticator binding and account recovery:
  <https://pages.nist.gov/800-63-4/sp800-63b.html#account-recovery>

These are design references, not adopted ICC wire protocols.

---

**End — Phase 3 Identity Core v0.1**
