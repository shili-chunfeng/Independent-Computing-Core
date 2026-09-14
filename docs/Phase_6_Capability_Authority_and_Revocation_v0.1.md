# Phase 6 — Capability Authority and Revocation v0.1

**Status:** Proposed prototype for owner review  
**Base:** merged `main` `aab2d8331d903cec6636ab10fb096c1221cd5370`  
**Scope:** `no_std + alloc` authority state machine, not a deployed App service

## Authority contract

The trusted authority owns a separate sealed security-state namespace. Root
issuance and revocation take an owner from a *trusted owner path*, never from an
App request. `GrantId` and `ObjectId` are names, not credentials. A random
128-bit `LocalHandle` is an index into the live authority's volatile table.
Each entry binds one grant generation, authenticated `AppId` and fresh runtime
session nonce. Callers cannot recover an entry from a name, guess another
App's handle, reuse a closed handle within an instance, or carry a handle
through restart. The runtime must supply `BoundCaller` from its own verified
execution-domain state; the public constructor is **not** an authentication
primitive. The prototype has no IPC caller binding or App-facing endpoint.

Capabilities have a typed `Scope`: a Vault owner collection or one Vault
object under that owner. Owner scope includes matching objects; object scope
never includes a different object or collection. `CREATE` and `LIST` apply
only to collections; object scope may carry `READ`, `WRITE`, `DELETE` and
`DELEGATE`. Both resource and rights are checked on the server. Delegation
requires live parent authority, its `DELEGATE` bit, exact recipient binding,
child scope contained by parent, rights subset, and expiry no later than the
parent. All delegated grants must have an expiry at most 24 hours from issuance.
A grant may itself carry `DELEGATE` only if the parent allows it. A root grant
may be long-lived by explicit owner action; no default grant is created.

A monotonic, never-reused grant ID and per-grant generation are stored in a
bounded canonical snapshot. Revoking any grant increments its generation and
sets a durable tombstone. Its descendants become invalid through the checked
ancestor chain, including their current handles and future reactivations.
The revoked subtree is not independently resurrected. A successful revoke
returns only after the security-state commit. An `execute` call holds an
exclusive mutable authority borrow and trusted store lease while applying
its effect; revocation waits for an in-flight operation and all subsequent
operations see the committed revocation. This atomicity requires *every*
resource effect, including secondary endpoints, to go through this same
service and lease. A separate check-then-use API would violate the contract.

The `CapabilityClock` Port has a reboot-stable monotonic epoch and must fail
closed on uncertainty. Reads compare the clock with the instance's floor and
check each ancestor's expiry; the committed snapshot includes the time floor.
A boot-relative clock cannot implement this Port. Session nonces must be
fresh across restarts; the handle combines fresh random bytes with the session
nonce and has an in-memory closed-handle tombstone. Handle slots and durable
grants are capped at 256 and 128 respectively. `usage()` exposes these limits
for authority-owned accounting/telemetry, without App-supplied quotas.

## Storage and cryptographic boundary

`CapabilityStateStore` is separate from `VaultStateStore` (user data),
`KeyStateStore` (secret keys), and the generic `SecurityStateStore`. It
requires a trusted non-rollbackable epoch, durable never-reused reservations,
atomic snapshot-plus-epoch commit, and a non-stealable lifetime lease.
`CapabilitySeal` authenticates format, namespace, epoch and all grants under
an independent ClassicalV1 HKDF-derived capability key. Its nonce uses the
`ICAP` domain prefix and the reserved epoch, not the Vault/KeyStore nonce.
The plaintext snapshot is bounded (128 grants; <= 16 KiB) and canonical:
magic, version, committed epoch, next ID, trusted time floor, count, and
sorted typed grant records including parent, subject, rights, expiry,
delegation flag, generation and revocation flag. Unknown versions, malformed
lengths, invalid flags/rights, dangling or forward parents, widened children,
wrong epoch and trailing bytes fail closed. Uncertain mutation poisons the
instance until trusted reopen. Restart requires explicit trusted activation of
an unrevoked grant into a fresh session. It cannot revive a revoked ancestor.

## Threats and verification

| Threat / gate | Authority regression evidence |
|---|---|
| T-CAP-001 | unknown, guessed ID and random handles denied; App/session binding checked |
| T-CAP-002 | closed token tombstone and collision rejection; restart drops handle table and binds new session |
| T-CAP-003 | exhaustive 64 × 64 rights subset property and scope/expiry expansion rejection |
| T-CAP-004 | parent and child handles denied on revoke and after restart; ambiguous commit poisons instance |
| T-CAP-005 | owner/object typed scope, unrelated object and collection action denied |
| T-CAP-006 | only explicit parent-authorized recipient delegation; child cannot redelegate without bit |
| T-CAP-007 | operation closure holds authority borrow and exclusive lease; revoke commits before return |
| T-CAP-008 | trusted clock expiry at boundary and after restart, backwards clock rejected; 24h delegation ceiling |
| Gate S2 | unauthorized, malformed/corrupt snapshot, expired and revoked negative paths |

## Explicit limits

The `InMemoryCapabilityStateStore` and fake clock simulate trusted lease,
atomicity, rollback detection and reboot-stable time only inside one test
process. The software sealer's root key is test-injected; there is no
production Linux store, durable anti-rollback, cross-process lease, trusted
clock/key provisioning or authenticated IPC caller. Phase 5 Vault still uses
its temporary injected `VaultAuthorizer`; no production binding between its
endpoints and this authority has been delivered. Gate S2 is model evidence,
not proof that an App process cannot bypass an unbuilt runtime. Deployment
requires a trusted composition root and Phase 7 IPC wiring, including enforced
routing of Vault effects through `execute`. No destructive migration, reset,
new third-party cryptography or permanent trust-root change is proposed.
