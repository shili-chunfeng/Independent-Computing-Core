# ADR-0007 — Scoped Identity, Signed State Transitions, and Quorum Recovery

## Status

Proposed for Phase 3 owner review.

## Context

Phase 0 requires user-controlled identity, forbids a global App-visible user ID,
and reserves root identity for ownership/recovery. Phase 0.2 identifies root
exposure, cross-App correlation, unauthorized device enrollment, and recovery
takeover as explicit threats. Phase 3 must make those constraints executable
before the KeyStore, service runtime, persistence format, or network protocols
exist.

Three design questions are coupled:

1. how an App receives a stable identity without learning a global identifier;
2. how device/identity transitions are authorized without raw private keys in
   Identity Core;
3. how recovery restores control without becoming a universal server bypass or
   a single weak credential.

Relevant external design evidence:

- OpenID Connect defines pairwise subject identifiers so different clients
  receive different identifiers and gives stored random GUIDs per client/account
  pair as one valid construction.
- WebAuthn scopes credentials/public keys to one relying party and describes
  cross-relying-party non-correlation as a privacy objective.
- NIST SP 800-63B-4 treats recovery as a distinct, infrequent security ceremony;
  after recovery, new authenticators are bound and recovery events require
  notification. ICC does not adopt NIST's CSP/account model, but the separation
  of normal authentication from recovery is applicable.

References:

- <https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes>
- <https://www.w3.org/TR/webauthn-3/>
- <https://pages.nist.gov/800-63-4/sp800-63b.html#account-recovery>

## Decision

### 1. Root identity is private authority state

Identity Core generates a private random identity-domain identifier and stores a
typed root authorization-key binding. No normal App view or CLI API contains
the root-domain identifier, root key reference, device identifier, or recovery
authority identifier.

The root key is an ownership/recovery anchor, not an App login credential.

### 2. App identities are random stored pairwise records

Each `AppId` receives:

```text
independently generated 256-bit AppPseudonymId
+ distinct AppAuthentication key reference
+ distinct public verification key
+ checked key generation
```

Identity Core stores the mapping. It does not derive the App pseudonym from a
public/root identifier, does not expose a global correlator, and rejects key ID
or public-key reuse across Apps and other identity purposes.

This is analogous to the stored pairwise-identifier construction identified by
OpenID Connect, but it is an ICC-local domain rule rather than OIDC behavior.
The choice avoids introducing a master pseudonym-derivation secret before the
Phase 4 KeyStore and durable security-state design exist.

### 3. Identity keys use typed references, never raw private bytes

`IdentityKeyBinding` contains:

```text
IdentityKeyId
IdentityKeyPurpose
Ed25519 public verification key
```

It contains no private seed/key bytes and no process-local raw handle. Phase 4
must bind `IdentityKeyId` to a non-exported secret-operation object and verify
that the public key corresponds to that object.

Key purposes are distinct for:

```text
RootAuthorization
RecoveryAuthorization
DeviceAuthentication
AppAuthentication
Communication
Financial
```

Phase 3 implements the first four and reserves the latter two as separation
hooks; it does not implement Messaging or Wallet protocols.

### 4. Security transitions use exact signed transcripts

Device enrollment, device rotation/revocation, App rotation/revocation, and
recovery approval use Ed25519 verification through `icc-crypto-api`.

Identity Core reconstructs the signed statement from current authoritative
state. Each statement includes a fixed v1 domain separator, action code,
identity-domain ID, current root generation, actor/target identifiers, relevant
key generations, and exact target key material. Recovery additionally includes
the recovery epoch, attempt ID, next root generation, new device, and complete
target recovery policy.

No caller-provided boolean or claimed caller string is authorization. A future
service/runtime must bind the real caller and select the trusted provider.

### 5. Recovery uses distinct M-of-N approvals

A recovery policy contains 2–8 distinct recovery authorities and requires a
threshold of at least two. Each authority uses its own
`RecoveryAuthorization` key and signs the same exact recovery target.

This is not a new threshold-signature primitive. It is bounded collection and
verification of multiple independent ClassicalV1 Ed25519 signatures.

Successful recovery atomically performs the domain transition:

```text
rotate root key and generation
increment recovery epoch
revoke every old device
cancel pending enrollments
activate the new recovery device
suspend active App identities pending new-device key reauthorization
replace recovery policy with the quorum-approved target policy
consume the recovery attempt
```

Duplicate approvals do not count. Stale attempts/proofs do not survive the
generation/epoch change. Notification/audit delivery is mandatory future
service work but is not fabricated inside this I/O-free domain crate.

### 6. State is separate from persistence/wire format

Phase 3 provides private-field movable `IdentityState` and validated
restoration, but no serializer. Durable storage must later add authenticated,
versioned, atomic, rollback-aware security-state persistence. Passing the
in-memory restart test is not a durable anti-rollback claim.

## Alternatives Considered

### One global public user identifier

Rejected. It directly violates C-005/C-006, INV-013, and T-ID-002.

### Deterministically derive every App identifier from a root secret now

Deferred. A correctly domain-separated PRF/HKDF construction can provide
pairwise stability, but Phase 3 has no KeyStore, durable secret lifecycle, or
rollback-aware state. Giving Identity Core root secret bytes would violate the
secret boundary. The stored-random construction is simpler and preserves the
option to migrate behind an explicit future protocol.

### Reuse one public key while changing only the App identifier

Rejected. The stable public key itself becomes a cross-App correlator.

### Let the requesting device self-report that enrollment was approved

Rejected. A client boolean/role string is not authority and would enable
T-ID-003.

### Allow the root private key to enter Identity Core for signing

Rejected. It violates C-009, INV-007, ADR-0005, and the future KeyStore
operation boundary.

### Single recovery key or ordinary active-device proof only

Rejected as the Phase 3 baseline because one stolen recovery credential would
be a universal takeover path. Active-device authorization remains the normal
device-binding path; recovery is deliberately separate and stronger.

### Cloud account, email, SMS, or repository as recovery authority

Rejected. It would make replaceable infrastructure an identity owner and would
violate offline-normal operation. Such channels could later carry notifications
or individually scoped evidence, but cannot silently become master authority.

### Invent a custom threshold signature protocol

Rejected. Phase 0 C-010 forbids inventing cryptographic primitives. Counting
distinct verified signatures provides explicit quorum semantics without a new
primitive.

### Persist Rust structs directly

Rejected. Rust layout, enum representation, `usize`, and collection internals
are not a wire/persistence contract.

## Security Consequences

Positive:

- root identity is absent from the App disclosure surface;
- App identifiers and public keys are independently scoped;
- authorization proofs are action-, domain-, target-, and generation-bound;
- revoked/stale devices and replayed proofs fail closed;
- recovery requires multiple distinct authorities and rotates compromised state;
- no private key bytes enter Identity Core;
- state and wire/persistence representations remain separate.

Limitations / remaining risks:

- Phase 3 trusts the future composition root to bind callers and inject an honest
  crypto provider; runtime/process isolation is not yet implemented;
- `IdentityKeyId` ↔ KeyStore secret/public-key correspondence cannot be proven
  until Phase 4;
- durable corruption, crash atomicity, freshness, and snapshot rollback defense
  are not implemented;
- recovery notification delivery and operational rate limiting are deferred;
- loss of enough recovery authorities can still cause permanent lockout;
- colluding Apps can correlate a user through external behavior or voluntarily
  shared data despite pairwise ICC identifiers;
- Linux root/kernel compromise remains outside the prototype guarantee;
- no formal verification is claimed.

## Performance Consequences

- one Ed25519 verification is required per authorized transition/approval;
- duplicate-binding checks scan bounded identity collections;
- recovery verifies at most eight authorities and scans bounded device/App
  state once at finalization;
- stored pairwise identifiers consume persistent security state in the future;
- no new runtime, parser, database, or third-party dependency is introduced.

## Portability Consequences

- Identity Core remains `no_std + alloc` and OS-independent;
- randomness and crypto verification are injected through existing portable
  interfaces;
- no Linux path, clock, process, socket, or database type enters the domain;
- the selected bare-metal target remains a required CI gate.

## Migration Consequences

- the Phase 1 generic identity provisioning/CLI display is removed and is not a
  stable compatibility promise;
- Phase 4 must implement KeyStore binding for `IdentityKeyId` without exposing
  raw key bytes;
- future persistence requires an explicit schema and security-state migration;
- future App/IPC SDK must expose only scoped views and bind caller `AppId`
  authority-side;
- changing transcript format requires a new version/action policy and migration
  analysis; v1 is not silently reinterpreted.

