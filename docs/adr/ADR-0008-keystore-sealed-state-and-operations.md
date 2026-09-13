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

The test Port models these requirements and injects faults; it is not a Linux
anti-rollback implementation. No App may reach the trusted operation interface
directly. A future service must authorize each call based on its real caller.

## Alternatives considered

- Plaintext secret persistence: rejected for obvious disclosure on storage
  copy or backup.
- Reuse `SecurityStateStore::put`: rejected for lost-update, partial write,
  freshness, and AEAD nonce-reuse hazards.
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

## Portability and migration consequences

The operation API and core are `no_std + alloc` and can be backed by software,
TPM, SE, or future hardware without rewriting Identity Core. The ciphertext
format is explicitly versioned and unknown versions fail closed; it is not a
Rust layout or an App/IPC protocol. No existing persisted key data is migrated.
The placeholder Phase 1 `SecretStore` Port remains separate until a real
symmetric consumer and authorization/wire design exist.
