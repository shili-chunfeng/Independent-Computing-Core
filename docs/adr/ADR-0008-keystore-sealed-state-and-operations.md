# ADR-0008 — Non-exporting KeyStore operations and sealed security state

## Status

Proposed for Phase 4 owner review. This does not select a permanent hardware
or password-derived cryptographic trust root.

## Context

ADR-0005 keeps seeds within the crypto boundary; ADR-0007 supplies stable
identity key IDs and public bindings, but cannot prove their correspondence or
persist revocation. The ordinary Phase 1 `SecurityStateStore::put` cannot
promise atomic, rollback-aware mutation or nonce reservation.

## Decision

Define an A1 `KeyOperations` trait for non-exporting identity signing, exact
binding verification, generation, rotation, and destruction. Implement the
ClassicalV1 software reference under `crates/crypto`. Define a separate narrow
`KeyStateStore` Port requiring a stable unique namespace, durable monotonic
reservation, atomic compare-and-commit and trusted freshness rejection. Seal a
bounded versioned snapshot with ChaCha20-Poly1305 using a per-namespace
HKDF-SHA-256 key derived from an externally injected root, and a nonce from a
never-reused reserved epoch. Any uncertain commit poisons the current instance.

The Port must also acquire a non-stealable **exclusive lifetime lease** before
provision/load and retain it for the whole software KeyStore instance, across
signing and mutations. A competing adapter for the same namespace cannot
acquire another lease; its methods fail without one. The adapter releases the
lease on drop or a one-way storage handoff, including failed opens. A lease
that can expire while its old holder still signs is invalid. This makes the
commit the cross-instance revocation linearization point: an operation that
completed before commit may have used the old key, but none begun afterward
may use a stale live instance. Non-atomic pre-sign `load` was rejected because
revocation could race between the read and the signing operation.

Snapshot **v2** replaces the proposed v1 layout. Each active key record now
contains its never-reused issuance generation, set to the trusted Port's
durably reserved epoch at its first successful commit; the descriptor must
match that generation as well as its ID, purpose and public key. This blocks
destroy/rotate ABA even if the random ID and signing seed are reissued after
all active records of the old key have been removed. The decoder rejects zero
seeds, duplicate active seeds/public keys, duplicate/zero/future generations,
and noncanonical order. v2 uses a distinct HKDF label. No tombstone list with
unbounded growth is required, but the Port's non-reuse/freshness guarantee is
now critical to both nonce safety and historical descriptor invalidation.

The test Port models these requirements and injects faults; it is not a Linux
anti-rollback implementation. No App may reach the trusted operation interface
directly. A future service must authorize each call based on its real caller.

## Alternatives considered

- Plaintext secret persistence: rejected for obvious disclosure on storage
  copy or backup.
- Reuse `SecurityStateStore::put`: rejected for lost-update, partial write,
  freshness, and AEAD nonce-reuse hazards.
- Recheck `load` immediately before signing: rejected as a non-atomic TOCTOU
  window across a competing instance's durable revocation commit.
- Compare only currently active IDs/seeds: rejected because a previously
  destroyed key can be recreated with the same randomness and old descriptor.
- Auto-generate on a missing snapshot: rejected; loss could resurrect a
  revoked identity or destroy access unexpectedly.
- Treat a key handle, claimed App name, or caller boolean as authority:
  rejected; handles are references, not caller-bound capabilities.
- Select a permanent TPM/SE/password/file-hosted root here: deferred to owner
  trust-root decision and proper implementation/deployment review.
- Raw private-key export for backup: rejected; requires an explicit future
  owner decision and a separate reviewed recovery protocol.

## Security and performance consequences

The KeyStore now verifies `IdentityKeyId` ↔ purpose ↔ public-key ↔ secret
correspondence; mutation is committed before visibility and unknown state
denies. Whole-snapshot authenticated encryption makes each change O(number of
keys) and intentionally caps records. Availability depends on the trusted Port
and externally provisioned root. No anti-rollback, secrecy from Linux root,
physical extraction, swap/core-dump protection, runtime isolation, caller
authentication, or formal zeroization is claimed for an absent production
backend. Authentication does not on its own make a copied old snapshot fresh.
The exclusive lease reduces concurrency by design to one live signing instance
per namespace; production cross-process enforcement and no-steal fencing are
not yet implemented. The in-memory Port proves only the modeled sequence.

## Portability and migration consequences

The operation API and core are `no_std + alloc` and can be backed by software,
TPM, SE, or future hardware without rewriting Identity Core. The ciphertext
format is explicitly versioned and unknown versions fail closed; it is not a
Rust layout or an App/IPC protocol. **v1 is rejected on v2 open, not silently
reinterpreted or automatically migrated.** A provisioned v1 namespace cannot
be initialized anew through `provision`. A separately reviewed, owner-authorized
rekey and IdentityState reconciliation procedure is required before enabling
pre-v2 keys; no raw-key export or fallback legacy signer is introduced here.
The placeholder Phase 1 `SecretStore` Port remains separate until a real
symmetric consumer and authorization/wire design exist.
