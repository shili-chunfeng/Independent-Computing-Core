# Phase 6 — Capability Authority and Revocation: completion evidence v0.1

**Status:** Implementation-head CI green; final test/report HEAD and PR CI pending
**Base main:** `aab2d8331d903cec6636ab10fb096c1221cd5370`  
**Branch:** `phase-6-capability-authority`; do not merge automatically

## Delivered prototype

- `icc-capability-core::authority` owns a bounded grant tree, typed Vault
  collection/object scopes, App/session-bound opaque local handles, monotonic
  IDs, generations, persistent revocation tombstones and a serialized
  operation entry point. Delegation is explicit, strictly attenuated, and
  bounded to 24 hours. Closing a handle leaves a runtime tombstone.
- Separate `CapabilityStateStore`, `CapabilitySeal` and `CapabilityClock`
  Ports define atomic, lease-guarded, authenticated and reboot-stable security
  state semantics. `icc-capability-crypto` uses the existing ClassicalV1
  crypto provider with a capability-specific key/nonce domain. Test support
  models the store/clock; no production backend is claimed.
- Snapshot format is bounded, versioned and canonical. Unknown formats,
  malformed records and stale trusted epochs fail closed; uncertain commits
  poison the instance until a trusted reopen. On restart, handles disappear
  and owner-controlled activation checks the entire surviving grant ancestry.
- Adds the Phase 6 specification and proposed ADR-0011. The fail-closed
  architecture policy includes the new crypto crate; portable crates receive
  bare-metal checks. No new third-party dependencies or unsafe code.

## Threat and Gate S2 evidence

The executable acceptance flow and T-CAP-001–008 mapping are in
`docs/Phase_6_Capability_Authority_and_Revocation_v0.1.md`. Core tests cover
no grant, guessed object/handle, wrong App/session, read-only versus write,
explicit scoped temporary delegation, expansion, revoked parent and child,
restart, expiry/clock rollback, closed-handle ABA, ambiguous commit poisoning,
lease collision, snapshot rollback and malformed records. Crypto integration
tests cover authenticated context, tamper and revoked child after reopen.
The rights test exhausts all 64 × 64 known-rights pairs. Architecture self
and negative tests add App-to-capability-crypto and core-to-provider denials.

## Exact-head CI evidence

The pre-report implementation-head [push run 34825973743](https://github.com/shili-chunfeng/Independent-Computing-Core/actions/runs/34825973743)
at `76266a47816281b37234991c48a6ae62e828d247` completed **success**;
its [verify job 103918112314](https://github.com/shili-chunfeng/Independent-Computing-Core/actions/runs/34825973743/job/103918112314)
reports:

| Gate | Result on that implementation head |
|---|---|
| locked default/all-feature metadata and dependency inventory | PASS |
| architecture policy/self/negative checks | PASS — 42 Python tests |
| rustfmt, default/all-feature check and strict Clippy | PASS |
| default/all-feature tests and security compile-fail doctests | PASS |
| bare-metal no_std, including new capability crypto | PASS |
| all-feature cargo-deny advisories/bans/licenses/sources | PASS |
| repeated locked release builds and lockfile stability | PASS |

Two later tests explicitly cover fresh-session stale-handle rejection after a
simulated restart and effect ordering around a revoke. Their final HEAD must
pass its own push and PR CI; the older run is not evidence for those changes.

## Remaining boundaries

The in-memory test Port does not implement real anti-rollback, durable
reservation, interprocess exclusion, reboot-stable clock or key provisioning.
The Phase 5 Vault endpoints still take an injected `VaultAuthorizer` and are
not wired to this authority. The trusted runtime must authenticate
`BoundCaller`, control owner-only root/revocation paths, provide fresh session
nonces, and route *all* resource operations through `execute` while holding the
exclusive authority lease. Without that integration, App-level enforcement
and production revocation consistency are **NOT VERIFIED**. No destructive
format migration, root-key change, physical/hostile-root protection, formal
proof or long-running coverage-guided fuzzing is claimed.

## Gate

Only the latest PR HEAD with successful push and PR CI may be marked
**READY FOR OWNER REVIEW — DO NOT MERGE**. Until then Phase 6 is a proposed
implementation, not a merged complete milestone.
