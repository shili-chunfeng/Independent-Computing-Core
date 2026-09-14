# Phase 5 — Personal Vault and Object Storage v0.1

**Status:** Proposed implementation for owner review  
**Base:** merged `main` at `ec7dbf2a7eba662fd56b8deee49274d805205bb6`  
**Scope:** portable A1 Vault authority model; no production storage deployment

## Contract

An object is owned by a local `VaultOwnerId`, not by a filesystem path or an
App. A random `ObjectId` locates a record, and a separate random `content_ref`
names its inline content version. Neither value carries authority. A future
caller-bound service must supply the actual `AppId` and trusted
`VaultAuthorizer` implementation. The five operations (create, read, write,
delete, list) each require an explicit policy decision before object lookup or
metadata disclosure; owner equality is checked after authorization. Unknown
IDs and mismatched owners return the same `Denied` error. List is separately
authorized and returns only IDs of that owner. The authority trait is a
temporary narrow Phase 5 boundary, not Phase 6 capability delegation.

`icc-vault-core` is `no_std + alloc`: it accepts narrow `SecureRandom`,
`VaultStateStore`, and `VaultSeal` Ports and never depends on Linux or a concrete
crypto provider. `icc-vault-crypto` keeps root key material inside the crypto
boundary and implements the sealer with the reviewed ClassicalV1 HKDF-SHA-256
and ChaCha20-Poly1305 provider API. A root key must be injected by a trusted
future composition root; Phase 4 does not yet provide a production symmetric
Vault key lifecycle. The internal sealer is not an App API.

## Internal format and storage

- Stored envelope v1: 8-byte magic, big-endian u16 format version, 16-byte
  namespace, big-endian u64 reserved epoch, ciphertext and 16-byte AEAD tag.
  This header is authenticated AAD. A 96-bit nonce consists of the fixed Vault
  domain prefix and the never-reused 64-bit reserved epoch. HKDF derives a
  distinct key for each namespace with a Vault-specific info label.
- Plaintext snapshot v1: magic, version, u16 count, then sorted records each
  containing ID, owner, content reference, u16 nonzero type, u64 positive
  revision, u16 metadata length, u32 content length, metadata, and content.
  Unknown versions, duplicate/noncanonical IDs and references, bad lengths,
  trailing bytes, zero IDs/owners, and invalid revisions are rejected. Rust
  struct layout is never serialized. Metadata and content are encrypted
  together. Metadata is currently opaque bytes, not a stable App wire schema.
- Capacity: at most 64 records, 1 KiB metadata and 16 KiB inline content per
  record. Total plaintext and ciphertext are separately bounded. Large files,
  streaming, deduplication and external chunks are deferred; a content
  reference in v1 is logical, not a physical storage path.
- `VaultStateStore` is a distinct user-data namespace, not
  `SecurityStateStore` or `KeyStateStore`. Its contract requires an exclusive
  non-stealable lease, atomic commit of whole sealed snapshot with trusted
  committed epoch, durable strictly increasing epoch reservations, and
  rollback detection. No ordinary file or the existing generic `ObjectStore`
  fulfills it. Restoring user data through a controlled future workflow may
  be legitimate, but raw snapshot rollback cannot reinstate stale policy;
  authorization grants and revocation generations are not Vault payload.
- `initialize` is explicit and refuses an already provisioned namespace.
  `open` refuses missing, stale, corrupted, or unknown-version state. A failed
  or ambiguous commit poisons that instance and requires trusted reopen.

## Threat mapping and limits

| Threat | Control / evidence |
|---|---|
| T-VLT-001/002, C-007/C-008 | authorize before lookup, owner check, authenticated ciphertext and metadata |
| T-VLT-003/004 | random opaque IDs, distinct List permission, metadata encrypted at rest |
| T-VLT-005 | trusted epoch/freshness Port model; old snapshot replacement refused |
| T-VLT-006 | bounded canonical decoder, atomic snapshot commit model, fail-closed poison/restart tests |
| T-IPC-001, T-CAP-007 | caller binding and capability decision must be enforced by future owning runtime; no App API claim |

No production Linux `VaultStateStore`, cross-process lease, trusted epoch,
seal-root provisioning, crash-safe fsync implementation, user-facing grant
flow, KeyStore integration, or runtime caller binding exists. The shared-memory
test adapter only simulates these properties within one process. A hostile host
root/kernel, process dumps, side channels, physical extraction, formal
verification and long-running coverage-guided fuzzing are NOT VERIFIED.
No new third-party dependency, algorithm, unsafe exemption, or irreversible
state migration is introduced. Snapshot v1 is not committed as an immutable
future production on-disk format; any future migration/reset needs explicit
review and owner decision when destructive.

## Exit evidence

The PR must pass exact-head push and PR CI: architecture negative tests,
default/all-features check/clippy/test, doctests, bare-metal `no_std`, dependency
policy and repeated release builds. Unit tests include authorization,
wrong-owner/context, enumeration, tamper, truncation, unknown version,
rollback, reservation/commit failure, concurrent lease and restart. This
evidence establishes only the portable prototype boundary above.
