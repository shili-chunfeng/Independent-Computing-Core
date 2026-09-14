# Phase 5 — Personal Vault and Object Storage: completion evidence v0.1

**Status:** Implementation-head CI green; report/PR-head CI and owner review pending  
**Base main:** `ec7dbf2a7eba662fd56b8deee49274d805205bb6`  
**Branch:** `phase-5-vault`; do not merge automatically

## Scope and implementation

- Adds `icc-vault-core`, a portable `no_std + alloc` authority-owned logical
  object domain. Random IDs and content references are names, never grants;
  trusted `VaultAuthorizer` checks create/read/write/delete/list before record
  lookup or disclosure, with a separate owner match and List decision.
- Adds `VaultStateStore` and `VaultSeal` Ports. Snapshot v1 encodes sorted,
  bounded objects and metadata independent of Rust layout. The software
  sealer encrypts and authenticates the whole snapshot with the existing
  ClassicalV1 provider. A distinct test storage namespace models an atomic
  commit, exclusive lease, non-reused epochs and trusted freshness. A failed
  commit poisons the live instance until a trusted reopen.
- Updates fail-closed workspace/dependency declaration policy and negative
  tests so Apps cannot take direct Vault Core or crypto implementation edges.
  Adds bare-metal checks for both portable crates. No third-party dependency,
  cryptographic algorithm, unsafe exemption, Linux effect, or KeyStore
  state migration was added. `Cargo.lock` changes only for the new first-party
  packages and their dependency edges.
- Documents the format/storage split in the Phase 5 specification and
  proposed ADR-0010; updates README and SECURITY to distinguish the merged
  Phase 4 baseline from this proposed Phase 5 prototype.

## Threat coverage and tests

| Threat | Regression / observed behavior |
|---|---|
| T-VLT-001/002 | denied read, wrong owner, denied write/delete; real crypto adapter detects altered header, content and tag |
| T-VLT-003/004 | random IDs; knowledge of an ID cannot read/list metadata; encrypted metadata and content are absent as plaintext in integrated test snapshot |
| T-VLT-005 | old snapshot replacement conflicts with trusted committed epoch; wrong namespace/key/epoch rejected |
| T-VLT-006 | fail-before and ambiguous fail-after commit, poison/reopen, truncated/unknown-version/bad-length/extra-byte records, bounded decoder mutation harness |
| T-IPC-001 | caller authority is injected by trusted runtime boundary; current tests use a policy fixture, not an actual IPC caller proof |

The parser mutation harness is deterministic and bounded; coverage-guided
long-running fuzzing is **NOT VERIFIED**. Architecture self/negative checks are
conservative metadata/source checks, not a Rust visibility or security proof.

## Actual CI evidence

The implementation-head push [run 34800162542](https://github.com/shili-chunfeng/Independent-Computing-Core/actions/runs/34800162542)
targets `ad5f30a66041daec87dd3b11af59757c17172001`.
Its [verify job 103841075310](https://github.com/shili-chunfeng/Independent-Computing-Core/actions/runs/34800162542/job/103841075310)
completed **success**. The actual decoded logs and job-step results show:

| Gate | Result at this exact implementation head |
|---|---|
| default/all-features locked metadata, inventory, architecture policy | PASS — 40 Python self/negative tests |
| rustfmt, default/all-features check and strict Clippy | PASS |
| default/all-features tests and explicit compile-fail doctests | PASS — 7 Vault Core tests and 2 Vault crypto tests in each workspace pass |
| bare-metal no_std checks, including both new crates | PASS |
| all-features cargo-deny advisories, bans, licenses, sources | PASS — each reported `ok` |
| repeated default/all-features locked release builds, lockfile hash | PASS — `Cargo.lock: OK` |

Earlier runs at prior heads failed formatting or Clippy and are not completion
evidence. After this report commit, the exact report/PR HEAD push and PR CI
must also succeed; their links and conclusions belong in the PR.

## Remaining risks and boundaries

The in-memory `VaultStateStore` and deterministic test random source are test
fixtures, **not** a production Linux backend. No durable anti-rollback,
cross-process lease, crash-safe filesystem transaction, key provisioning or
binding to Phase 4 KeyStore exists. No real App caller authentication, formal
capability grant, revocation propagation, App sandbox, or permission UI exists.
The `VaultAuthorizer` implementation must not originate from an untrusted
request; Phase 6/7 must bind an actual caller and enforce authorization across
concurrency/revocation. No hostile-root/kernel, swap/dump, physical or side
channel resistance, third-party full source audit, or formal proof is claimed.
Data is capped at 64 objects and 16 KiB inline content per object. Cross-device
sync, streaming/chunk storage, production backups, safe migration of unknown
snapshot versions and destructive resets are out of scope. Actual user-data
backup rollback must not implicitly roll back security state. Any destructive
data-format migration or permanent key trust-root change requires separate
owner review.

## Gate

Only the latest branch and PR HEAD with successful required CI may be marked
**READY FOR OWNER REVIEW — DO NOT MERGE**. Until then this is a proposed
implementation and Phase 5 is **NOT MERGED COMPLETE**.
