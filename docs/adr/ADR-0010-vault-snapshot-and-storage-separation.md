# ADR-0010 — Separate Vault User Data from Security State

**Status:** Proposed (Phase 5; owner review required)  
**Date:** 2026-09-14

## Context

The existing generic `ObjectStore` has individual get/put/delete operations,
but no transaction, authenticated metadata, or rollback semantics. KeyStore's
trusted `KeyStateStore` holds secret security state. Phase 0 C-007/C-008 and
Phase 0.2 T-VLT-001–006 require a user-owned logical object model without
confusing its names with authorization or silently mixing data backups with
revocation/security state.

## Decision proposed

Use a bounded, versioned, encrypted, whole-namespace snapshot for the Phase 5
portable reference model. Define a distinct `VaultStateStore` Port with
trusted current revision, reserved non-reused epochs, atomic commit and an
exclusive lifetime lease. Keep actual grants, revocation and KeyStore seeds
outside the Vault payload. Authenticate the envelope, namespace, version and
epoch, and encrypt both object metadata and content. Authorization remains a
narrow injected server-side decision until Phase 6 defines formal capability
authority. Do not use `ObjectId`, `content_ref`, or owner ID as proof of access.

## Consequences and alternatives

The snapshot provides straightforward all-or-nothing reference semantics and
small attack surface, but caps data size and rewrites the whole namespace on
mutation. A transactional object/chunk backend may replace it behind the Port
after independent crash/rollback review. Reusing `ObjectStore` would allow
partial writes; reusing `KeyStateStore` would conflate recovery domains.
The in-memory adapter is test evidence only. No production anti-rollback or
host-root confidentiality claim follows from this ADR. Unknown format versions
fail closed; destructive migration or a permanent trust-root policy must be
reviewed separately rather than silently resetting Vault state.
