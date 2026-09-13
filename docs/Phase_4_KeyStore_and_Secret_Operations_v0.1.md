# Independent Computing Core
## Phase 4 — KeyStore & Secret Operations v0.1

**Status:** Proposed implementation specification  
**Base:** `main` at `ed4fc74fa33813c8663e22c7824e5dafb3ec7b4e`  
**Stage:** Phase 4  
**Date:** 2026-09-13

## Goal

Establish an A1-only, portable, non-exporting KeyStore operation boundary and
software reference implementation. Bind the Phase 3 `IdentityKeyId`, purpose,
and public verification key to the signing seed actually used. Security-state
changes must be authenticated and committed before an operation succeeds.

## In scope

- Opaque random `KeyHandle`, generation, signing, key rotation, destruction,
  and exact identity-binding verification for Ed25519 ClassicalV1 keys.
- A backend-neutral operation trait, no raw-key return method, and a portable
  `no_std + alloc` software implementation inside the crypto/KeyStore boundary.
- A narrow `KeyStateStore` Port for separate authenticated security-state bytes,
  durable monotonic nonce reservation, atomic expected-revision commit, and
  rollback rejection. A fault-injectable test implementation exercises it.
- Versioned, bounded, authenticated sealed snapshot encoding, fail-closed
  decoding, restart, crash, corruption, stale snapshot, wrong key, and
  ambiguous-commit tests.

## Out of scope

- App, IPC, network, service, user presence, caller authentication, or
  capability issuance. The trusted authority-owning future runtime must bind
  its actual caller before invoking this A1 interface. A handle is **not** an
  authorization token.
- Production Linux durable/rollback-resistant Port, hardware provisioning,
  hardware anti-rollback, unattended seal-root storage, TPM/SE commitment,
  password unlock, backup/export/recovery protocol, and full IdentityState
  persistence. No one should deploy the test Port as durable production state.
- Symmetric user-data decryption and derivation: no Vault/sync consumer has a
  defined authorization, nonce, or wire protocol yet. The existing portable
  `SecretStore` Port and `SecretHandle` remain reserved, not silently treated
  as a completed Vault key service. No Argon2id password mechanism is needed.

## Architecture and assets

`icc-keystore` lives inside `crates/crypto`, is `no_std + alloc`, and forbids
first-party unsafe. It depends on the provider-neutral crypto API, the Identity
Core's public binding type, the random and security-state Ports, and core
identifiers. It does not depend on `icc-crypto-rust`, Linux, a filesystem,
clock, network, or IPC. Applications cannot depend directly on the crate under
the repository dependency allowlist. Provider selection and Port injection are
trusted composition responsibilities. The A-01 root/recovery seed and A-02
KeyStore seeds remain internal; snapshots are security state, not user data.

## Threat IDs and invariants

| ID | Phase 4 control |
|---|---|
| T-ID-001, INV-007 | no raw export API, private seed ownership and drop cleanup; signature-only result |
| T-ID-002 | random distinct handles; purpose and public-key correspondence verified |
| T-VLT-005, INV-011 | authenticated epoch/store binding and trusted Port rollback rejection; no Linux anti-rollback claim |
| T-VLT-006, INV-012 | commit-before-publish, fail-closed parse/load, poisoned instance after ambiguous commit |
| T-PLT-004 | injected secure entropy; failure and collisions reject |
| T-IPC-001 | A1-only, no caller-supplied role/boolean as authorization; caller binding deferred to service |

Every mutation commits a complete encrypted snapshot before changing live
records or returning a new handle. A commit error poisons that instance even
when the Port reports an ordinary error: it cannot know whether the write took
effect. Reopen is permitted only through the Port's trusted current state and
freshness check. Epoch reservations are durable and strictly increasing even
on failed commits, so nonce reuse is forbidden across crash/restart. A stored
snapshot's store namespace and epoch are authenticated as AEAD AAD; malformed,
stale, unknown-version, wrong-root, duplicate, and oversized records deny.

## API, persistence and wire plan

`KeyOperations` returns a `KeyDescriptor { handle, binding }`; `sign` and
`rotate` require both handle and exact current binding. `verify_binding`
recomputes the Ed25519 public key from the internal seed. Neither the handle
nor public binding is a caller grant. A future TPM/SE adapter may implement
this operation trait without using software seeds. An A2 App API/IPC format
must be separately reviewed and must not expose this trusted trait object.

The snapshot format is internal A3 **v1**, independent of Rust struct layout:
authenticated header (magic, version, namespace, epoch), encrypted bounded
record count and fixed-format sorted records (ID, purpose, 32-byte seed). The
root sealing key is injected as an internal crypto wrapper and HKDF derives a
per-namespace AEAD key. A fixed 96-bit nonce encodes a domain prefix and the
Port-reserved never-reused epoch. Plaintext assembly and decoding buffers are
best-effort zeroized; this does not eliminate compiler copies, swap, dumps,
root/kernel compromise, or physical extraction. No raw secret is returned by
the Port: its bytes are an authenticated ciphertext envelope only.

`KeyStateStore` must preserve namespace identity, provisioned state, atomic
commit with expected revision, durable never-reused epoch reservations, and
trusted committed-epoch freshness across crashes. The in-memory test adapter
models those semantics; an ordinary file, copy, or backup alone does not.
Provisioning a missing snapshot is always an explicit call, never implicit
recovery from missing data. No persisted Phase 3 state is migrated or reset.

## Dependencies and unsafe policy

Only first-party dependency edges are added. Existing reviewed `zeroize` and
ClassicalV1 provider primitives are reused; no new registry crate, unsafe
exception, new crypto algorithm, password KDF, or hardware trust root is
introduced. A reversible Port/format design is proposed in ADR-0008; the
permanent trust-root policy is left for owner decision.

## Tests, fuzz, failure, migration, exit

Tests cover sign/verify, cross-purpose and public-key substitution, unknown
and destroyed handles, rotation, entropy failure/collision, commit error and
ambiguous commit, restart, snapshot tampering, wrong root, stale snapshot,
unknown version, malformed/truncated input, duplicate records, and size
bounds. The bounded snapshot decoder has a deterministic mutation fuzz harness
in tests, with corpus-like malformed seeds and randomized byte mutations;
coverage-guided long-running fuzzing remains NOT VERIFIED and is a future CI
hardening item. Bare-metal target, architecture allowlist, compile-fail
non-export API checks, formatting, clippy, test suite, and actual push/PR CI
must pass before owner review.

Changing snapshot v1 requires an explicit migration/read policy; unknown
versions fail closed. Phase 3's non-serialized `IdentityState` remains without
durable persistence and must not be described as rollback-safe. Production
activation requires a separately reviewed trusted Port and external seal-root
provisioning, plus runtime caller binding; neither is claimed by this PR.
