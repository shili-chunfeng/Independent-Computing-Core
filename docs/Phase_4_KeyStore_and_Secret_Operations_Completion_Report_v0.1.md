# Independent Computing Core
## Phase 4 — KeyStore & Secret Operations Completion Report v0.1

- **Status:** Pre-review evidence record
- **Base HEAD:** `ed4fc74fa33813c8663e22c7824e5dafb3ec7b4e`
- **Branch:** `phase-4-keystore`
- **Evidence branch HEAD:** `ff55b5d74072caf6501651eb37bd2e1dc9fbd600`
- **Pull request:** [#4](https://github.com/shili-chunfeng/Independent-Computing-Core/pull/4)
- **Review date:** 2026-09-13
- **Merge status:** **NOT MERGED**

The evidence HEAD is the last implementation commit before this report. The
final report/PR HEAD and its latest CI run belong in the PR, because adding
either to this file creates a new HEAD and another required run.

## Source of truth and milestone

GitHub `main` was re-read after PR #3 merged. Its exact HEAD was the base above;
the matching required CI passed. No open PR covered the first unfinished
mandatory milestone, Phase 4, under `PROJECT_EXECUTION_CONTRACT.md`. The new
branch was created from that exact merged HEAD; `main` was not changed.

Reviewed material included the Constitution, full threat model and architecture
parts, accepted ADRs, merged Phase specifications and reports, repository
policy/lockfile, relevant code/tests, CI, README, and SECURITY.

## Delivered scope and changed files

- An A1-only `no_std + alloc` `icc-keystore` crate, with backend-neutral
  non-exporting `KeyOperations` and software Ed25519 reference implementation.
- Random opaque handles, generation, exact ID/purpose/public/seed binding,
  sign, rotate, destroy, duplicate-public-key and handle-collision rejection.
- A separate `KeyStateStore` Port requiring a stable namespace, durable
  never-reused epoch reservations, atomic expected-revision commits, and
  trusted freshness checks. The supplied in-memory adapter is a test model,
  not a production Linux implementation.
- Versioned and bounded ChaCha20-Poly1305 sealed security snapshots, a
  per-namespace HKDF key, authenticated epoch/namespace, canonical sorted
  records, fail-closed decoding, and instance poisoning after ambiguous writes.

Changed paths:

```text
.github/workflows/ci.yml
Cargo.lock
Cargo.toml
README.md
SECURITY.md
crates/crypto/icc-keystore/Cargo.toml
crates/crypto/icc-keystore/src/lib.rs
crates/ports/icc-platform-api/src/lib.rs
crates/testing/icc-test-support/src/lib.rs
docs/Phase_4_KeyStore_and_Secret_Operations_v0.1.md
docs/Phase_4_KeyStore_and_Secret_Operations_Completion_Report_v0.1.md
docs/adr/ADR-0008-keystore-sealed-state-and-operations.md
scripts/check_architecture.py
```

## Architecture, security and dependency impact

The KeyStore is within the crypto boundary; no App directly depends on it.
It depends on the provider-neutral crypto and Identity Core public binding
APIs, core IDs/errors, and portable random/state Ports. The concrete Rust
provider and fault-injectable memory Port are dev-only composition. Domain
Core does not receive seeds or a concrete backend dependency. A handle is a
reference, never proof of caller authority; a future service must bind the
actual caller and authorize every operation.

| Threat / invariant | Evidence and explicit limit |
|---|---|
| T-ID-001, INV-007 | no private export API; signing seed stays in owned secret wrapper; compile-fail regressions for export/descriptor seed |
| T-ID-002 | distinct handles and public keys, exact purpose/public/seed binding; negative substitution/collision tests |
| T-VLT-005, INV-011 | authenticated epoch and namespace plus Port freshness contract; **no production anti-rollback adapter** |
| T-VLT-006, INV-012 | complete commit before visibility, fail-closed parser/load, poisoned instance after ambiguous commit |
| T-PLT-004 | injected entropy, zero-entropy and collision exhaustion deny |
| T-IPC-001 | no App/IPC surface or claimed-role switch; real caller binding remains future service work |

No new external dependency, version, or unsafe exception is added. The
existing exact-pinned `zeroize = 1.9.0` and reviewed ClassicalV1 provider
primitives are reused; `Cargo.lock` adds only the first-party KeyStore package
edges. Proposed ADR-0008 records the Port/seal/operation decision and leaves
the permanent trust root for owner decision. Earlier ADRs are unchanged.

## Commands and CI evidence

Executed locally:

```text
git status / git log / git diff --check / source-policy scans
python3 -m unittest discover -s scripts -p 'test_*.py'
```

The Python suite passed 37 tests. This workspace has no local Rust toolchain;
there is no claim of locally executed Cargo checks. The branch CI ran the
repository's pinned Rust 1.98.1 formatting, default/all-features metadata,
dependency inventories, architecture checks, workspace checks, Clippy, tests,
compile-fail doctests, bare-metal checks, cargo-deny and repeated locked
release builds. The full push run below passed at the exact implementation
HEAD. Its decoded job log confirms all named steps completed successfully.

- [Full successful push run 34739252811](https://github.com/shili-chunfeng/Independent-Computing-Core/actions/runs/34739252811),
  head `ff55b5d74072caf6501651eb37bd2e1dc9fbd600`, conclusion `success`.
- [Full successful PR run 34739405449](https://github.com/shili-chunfeng/Independent-Computing-Core/actions/runs/34739405449),
  same implementation head, conclusion `success`.
- Earlier failing runs: formatting (#34738899895, #34739122543,
  #34739206957) and strict Clippy (#34739036115, #34739159129); those are
  repair evidence, not completion evidence.
- Latest report/PR HEAD run: recorded in PR after this report commit.

## Tests passed and NOT VERIFIED

The KeyStore has 11 unit tests and two compiler-level compile-fail doctests.
Cases cover Ed25519 sign/verify and restart, exact binding substitution,
rotation/destruction before success, crash before/after commit, stale/tampered
snapshot, wrong root, entropy failure, duplicate public key, handle collision,
canonical order, malformed counts/purposes/duplicates/truncation/extra bytes,
and a bounded deterministic mutation harness. Repository-wide checks include
the existing crypto vectors and architecture policy negative tests. Actual
full CI outcomes are recorded above, not inferred from the source.

**NOT VERIFIED:** coverage-guided long-running fuzzing; production durable
atomic storage/nonce reservation/anti-rollback on Linux or hardware; seal-root
provisioning and custody; real caller authorization/IPC; full IdentityState
persistence; formal verification; hostile-root/kernel, dump/swap, physical or
side-channel resistance; exhaustive third-party unsafe review.

## Remaining risks, migration, and explicit non-goals

The test Port deliberately models trusted freshness in memory only. Ordinary
filesystem copies cannot fulfill its contract: a copied older sealed snapshot
would authenticate unless a separate trusted committed epoch rejects it.
External root loss makes sealed keys unavailable; root compromise defeats
software confidentiality. Ambiguous errors poison the live instance and
require a trusted reload. The fixed key cap can deny availability. Snapshot v1
is internal, not an App wire format; unknown versions fail closed and future
format changes require a reviewed migration. No old persistent secret state is
migrated or reset. Phase 3's non-serialized IdentityState is still not durable.

Explicitly out of scope: Linux production `KeyStateStore`, TPM/SE, hardware
trust root, password unlock/Argon2id, backup/export/recovery protocol, Vault
or symmetric decrypt/derive (no consumer contract yet), App/IPC/network service,
caller-binding runtime, hardware isolation, wallet/messaging/sync, and OS
work. The existing `SecretStore`/`SecretHandle` remain a reserved Port/model,
not a completed Vault key service. Owner decisions on project license,
private vulnerability channel, and branch protection also remain open.

## PR, review, and merge status

PR: [#4](https://github.com/shili-chunfeng/Independent-Computing-Core/pull/4),
opened as a draft while its CI and this report were finalized. After a
successful latest report/PR-head CI, handoff is
**READY FOR OWNER REVIEW — DO NOT MERGE**. Owner review and a manual merge
are required. This branch is **NOT MERGED** and is not the next milestone's
source of truth.
