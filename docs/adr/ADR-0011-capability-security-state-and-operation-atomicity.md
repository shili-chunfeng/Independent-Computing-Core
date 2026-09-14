# ADR-0011 — Separate Capability Security State and Operation-Level Revocation

**Status:** Proposed (Phase 6; owner review required)  
**Date:** 2026-09-14

## Context

Phase 5 Vault stores user data separately from security state and temporarily
injects an authorization decision. Phase 0.2 T-CAP-001–008 requires actual
caller-bound, delegable and revocable authority, including restart and
check/revoke/use races. Persisting grants inside Vault backups could reinstate
revoked authority, and a checked boolean passed to a later effect could race
with revocation.

## Decision proposed

Use an independently provisioned capability security-state namespace with
sealed canonical snapshots, trusted freshness/lease and non-reused nonce
reservations. Store grant tree/generations and revocation tombstones, not active
session handles. For every effect, check the handle and ancestor chain and run
the effect under the same exclusive authority borrow and lifetime lease.
Revocation waits for that operation, commits, then invalidates all descendant
use and reactivation. Bind local handles to authenticated runtime App/session
identity; require fresh session nonces and cryptographic randomness. Require a
trusted reboot-stable clock for expiry and bound all explicit delegations to
24 hours. An ordinary file, boot-relative clock, request-supplied identity,
or preflight boolean does not satisfy these contracts.

## Consequences

This bounded prototype serializes effects and rewrites at most 128 grant
records per mutation. A future production backend may use transactional
records, but must preserve the same atomic revocation, lease, freshness,
nonce and recovery semantics. The test storage/clock models are not durable
implementations. Phase 7 must authenticate caller identity and connect Vault
operations to the authority without a bypass path; until then there is no
App-level permission enforcement. Unknown snapshot formats fail closed; any
irreversible migration needs separate owner review.
