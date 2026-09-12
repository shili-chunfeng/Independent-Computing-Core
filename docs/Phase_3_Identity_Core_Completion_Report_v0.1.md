# Independent Computing Core
## Phase 3 — Identity Core Completion Report v0.1

**Status:** Implementation and verification record  
**Base HEAD:** `ec9d2a050652bad1c0f8a698652ef880ba67064a`  
**Branch:** `phase-3-identity-core`  
**Evidence branch HEAD:** `c6a6b440bfab3cdd8e08cd7e2562e1b2ee5d5c26`  
**Pull request:** [#3](https://github.com/shili-chunfeng/Independent-Computing-Core/pull/3)  
**Review date:** 2026-09-12  
**Merge status:** **NOT MERGED**

The final PR HEAD and its latest required Actions run are recorded in PR #3.
They cannot be embedded in the commit that creates them without a
self-referential commit/run cycle. The exact evidence HEAD above is the last
successful full push run before this report-only commit.

---

# 1. Source-of-truth and milestone decision

GitHub merged `main` was re-read before development. At selection time:

- default branch `main` was
  `ec9d2a050652bad1c0f8a698652ef880ba67064a`;
- its latest required `phase2-ci` push run was successful;
- the execution contract was merged through PR #2;
- no open PR covered Phase 3;
- Phase 3 Identity Core was therefore the deterministic next mandatory
  milestone under `PROJECT_EXECUTION_CONTRACT.md`.

The branch was created from that exact commit. `main` was not modified.

Mandatory review covered README, SECURITY, the execution contract, all Phase 0,
0.2, 0.3, 1, and 2 specifications/parts, ADR-0001 through ADR-0006, every
workspace manifest and Rust source file, Cargo.lock, dependency policy, test
support, and CI.

---

# 2. Delivered scope

Phase 3 delivers a portable authority-side identity state machine:

- private root-domain ID and typed root authorization-key binding;
- typed key, device, enrollment, recovery-attempt, recovery-authority, and App
  pseudonym IDs;
- pending-to-active signed device enrollment;
- signed device-key rotation and cross-device revocation;
- random stored per-App pseudonyms and distinct App key bindings;
- signed App key rotation/reactivation and terminal revocation;
- canonical action-, domain-, generation-, actor-, and target-bound transcripts;
- sorted 2–8 authority recovery policy with threshold `M >= 2`;
- distinct recovery approvals over the exact target state;
- successful-recovery root rotation, old-device revocation, pending-enrollment
  cancellation, App suspension, and recovery-policy replacement;
- bounded collections and bounded non-zero random-ID retries;
- movable non-serialized state and invariant-checked restoration;
- removal of the CLI identity-core dependency and generic identity-ID output.

The implementation contains no private key bytes and performs verification only
through `CryptoProviderV1`.

---

# 3. Changed files

Specifications and governance:

```text
docs/Phase_3_Identity_Core_v0.1.md
docs/Phase_3_Identity_Core_Completion_Report_v0.1.md
docs/adr/ADR-0007-scoped-identity-and-recovery-authority.md
README.md
SECURITY.md
```

Domain implementation and composition:

```text
crates/core/icc-types/src/lib.rs
crates/core/icc-identity-core/Cargo.toml
crates/core/icc-identity-core/src/lib.rs
apps/indie-cli/Cargo.toml
apps/indie-cli/src/main.rs
Cargo.lock
```

Tests and enforcement:

```text
tests/architecture/Cargo.toml
tests/architecture/src/lib.rs
tests/architecture/src/identity_core_tests.rs
scripts/check_architecture.py
scripts/test_check_architecture.py
.github/workflows/ci.yml
```

---

# 4. Architecture consequences

`icc-identity-core` remains an L2 `no_std + alloc` crate with
`#![forbid(unsafe_code)]`.

Reviewed production edges are:

```text
icc-identity-core -> icc-types
icc-identity-core -> icc-error
icc-identity-core -> icc-platform-api (SecureRandom)
icc-identity-core -> icc-crypto-api (public values and verification)
```

It does not depend on `icc-crypto-rust`, Linux, a database/filesystem, a clock,
network/IPC, or a raw secret type. The concrete provider edge exists only in
the integration-test package.

The production App composition is narrower after this phase:

```text
removed: indie-cli -> icc-identity-core
forbidden: indie-cli -> icc-identity-core / icc-crypto-api / icc-crypto-rust
```

Domain state is deliberately not an A2 App API or A3 wire/persistence format.
A future service must bind the actual caller and choose trusted ports/provider.

---

# 5. Threat and invariant coverage

| ID | Implemented evidence |
|---|---|
| T-ID-001 | root fields private; no root getter; two compile-fail disclosure regressions; CLI ID output removed |
| T-ID-002 | independently random App pseudonyms; distinct public/key-ID bindings; reuse rejection tests |
| T-ID-003 | active-device signature required for enrollment; wrong/revoked/replayed proof tests |
| T-ID-004 | distinct M-of-N recovery proofs; exact attempt/target binding; root rotation and containment tests |
| T-PLT-004 | injected SecureRandom; entropy failure and repeated-zero exhaustion tests |
| T-IPC-001 | no claimed caller string/role/boolean; future authority-side caller binding documented |
| INV-007 | only typed key IDs and public keys enter Identity state/API |
| INV-011 | moved/restored state preserves device revocation; durable rollback explicitly not claimed |
| INV-012 | invalid proof/state, overflow, capacity, replay, revoked/suspended/missing state deny |
| INV-013 | App view contains pseudonym, public key, and generation only |
| INV-014 | identity transitions require no cloud/network service |

All commit paths reconstruct their transcript from current state and mutate only
after validation/signature verification. Recovery approvals are deduplicated by
current authority ID.

---

# 6. Dependencies

Added first-party production edge:

```text
icc-identity-core -> icc-crypto-api
```

Added first-party integration-test edges:

```text
icc-architecture-tests -> icc-crypto-api
icc-architecture-tests -> icc-crypto-rust
icc-architecture-tests -> icc-error
```

Removed first-party production edge:

```text
indie-cli -> icc-identity-core
```

No third-party dependency, version, source, or requested feature changed. Both
CI inventories contain the same 38 third-party packages reviewed in Phase 2.

---

# 7. ADR impact

Added proposed ADR-0007:

```text
Scoped Identity, Signed State Transitions, and Quorum Recovery
```

It selects private root authority, stored random pairwise App identities,
typed public key bindings, exact signed authorization transcripts, distinct
M-of-N recovery approvals, and separation of domain state from future
persistence/wire types. Alternatives and security/performance/portability/
migration consequences are recorded in the ADR.

ADR-0001 through ADR-0006 are unchanged. ADR-0007 remains proposed until owner
review and manual merge of PR #3.

---

# 8. Commands actually executed

Locally available checks:

```text
git status / git log / git diff --check
rg source, manifest, architecture, secret-boundary, and stale-API scans
Python tomllib parse of every Cargo.toml
python3 -m py_compile scripts/check_architecture.py scripts/test_check_architecture.py scripts/dependency_inventory.py
python3 -m unittest discover -s scripts -p 'test_*.py'
```

The local environment had no Rust toolchain, so no local Cargo result is
claimed. GitHub Actions run #99 actually executed the repository's complete
Rust 1.98.1 verification sequence:

```text
cargo metadata --locked (default and --all-features)
dependency inventories (default and --all-features)
architecture self/negative tests and production boundary checker
cargo fmt --all -- --check
cargo check --workspace --locked (default and --all-features)
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked (default and --all-features)
cargo test -p icc-crypto-api --doc --locked
cargo test -p icc-identity-core --doc --locked
thumbv7em-none-eabi checks for every portable crate
cargo install --locked --version 0.20.2 cargo-deny
cargo deny check advisories bans licenses sources
repeated default/all-features locked release builds
Cargo.lock SHA-256 stability check
```

---

# 9. CI evidence

Successful full push run:

- [icc-ci #99 / run 34706569222](https://github.com/shili-chunfeng/Independent-Computing-Core/actions/runs/34706569222)
- head: `c6a6b440bfab3cdd8e08cd7e2562e1b2ee5d5c26`
- conclusion: `success`

Run #98 stopped at formatting and was repaired by a rustfmt-only follow-up
commit. Its earlier metadata, dependency inventory, architecture self-tests,
and architecture production checks had passed. It is not used as final success
evidence.

The latest report/PR-head run belongs in PR #3 because adding its identifier to
this file would create another head and another required run.

---

# 10. Tests passed

Phase 3-specific evidence in run #99:

- 7 identity integration tests;
- 2 internal invariant/generation tests;
- 2 compiler-level root-disclosure `compile_fail` doctests;
- valid bootstrap and distinct App identity;
- public-key/key-ID reuse rejection;
- invalid-signature no-mutation path;
- signed enrollment and replay rejection;
- revoked-device authorization rejection and state restoration;
- device rotation with stale-proof and cross-action substitution rejection;
- App terminal revocation;
- exact 2-of-3 recovery, duplicate rejection, threshold rejection, invalid proof,
  root generation/epoch rotation, old-device revocation, pending cancellation,
  App suspension/reactivation, restart restoration, and stale recovery replay;
- recovery policy canonical ordering and transcript action separation;
- App and pending-enrollment capacity boundaries;
- entropy-unavailable and repeated-zero random-ID failure;
- wrong-purpose and invalid/duplicate recovery-policy rejection.

Repository-wide evidence also passed:

- 37 Python architecture checker self/negative tests;
- existing capability, platform, crypto API/provider, and known-answer tests;
- 15 existing secret-wrapper compiler trait regressions;
- default and all-features build/test/Clippy configurations;
- bare-metal portability, dependency policy, and release reproducibility gates.

---

# 11. Tests and properties NOT VERIFIED

- authenticated byte persistence and decoding: not implemented;
- crash/partial-write/atomic-commit behavior: not implemented;
- durable freshness, snapshot rollback detection, and multi-process restart:
  **NOT VERIFIED**;
- runtime caller/App/device binding and IPC spoof resistance: future service;
- KeyStore key-ID-to-secret/public correspondence: Phase 4;
- hardware-backed protection and hostile-root/kernel resistance: not claimed;
- formal verification/model checking: **NOT VERIFIED**;
- complete source-level third-party unsafe-code audit: **NOT VERIFIED**;
- recovery notification/audit delivery and rate limiting: not implemented;
- parser fuzzing: not applicable because Phase 3 introduces no parser/decoder or
  external wire format.

---

# 12. Remaining risks

- A compromised future Identity service/composition root can corrupt authority
  state until process/capability isolation is implemented.
- The Phase 3 domain trusts the injected crypto provider to implement its trait
  honestly.
- Loss of enough recovery authorities can cause permanent lockout.
- Apps can still correlate users through voluntarily shared data or external
  behavior despite ICC pairwise identifiers.
- Bounded capacity exhaustion denies new records until future lifecycle/retention
  policy exists; it does not weaken authorization.
- Durable rollback can restore old trust until authenticated monotonic security
  state is implemented.
- Project license, private vulnerability channel, and protected-branch
  governance remain owner decisions; this phase does not invent them.

---

# 13. Explicitly out of scope / not implemented

```text
private-key generation, storage, export, signing, or destruction
Phase 4 KeyStore / SecretStore lifecycle
identity persistence schema or wire decoder
IPC/network identity service and caller binding
cloud account or server master recovery
email/SMS/social recovery UI and proofing
recovery notification transport and durable audit log
Vault and Capability Authority expansion
Messaging and Wallet protocols
package/store protocol
Minimal OS work
hardware-backed identity
new cryptographic primitive or threshold-signature scheme
```

---

# 14. PR and merge status

- PR: [#3](https://github.com/shili-chunfeng/Independent-Computing-Core/pull/3)
- PR state: open; readiness is conditional on the latest PR HEAD required CI
  shown by GitHub.
- Owner review: required.
- Owner/manual merge: required.
- Merge status: **NOT MERGED**.
- This branch must not be treated as merged Phase 3 source of truth.

When the latest PR HEAD Actions run is successful, the correct handoff is:

```text
READY FOR OWNER REVIEW — DO NOT MERGE
```

Only owner review plus manual merge changes the milestone state to merged
complete.

---

**End of Phase 3 — Identity Core Completion Report v0.1**
