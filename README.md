# Independent Computing Core — Phase 6 capability prototype review

Independent Computing Core (ICC) is a portable personal-computing core intended to move from a Linux/VM prototype toward a future minimal OS without making Linux part of the Domain Core contract.

The repository contains the Phase 0 architecture/security baselines, Phase 1
engineering skeleton, Phase 2 ClassicalV1 cryptographic foundation, Phase 3
portable identity core, and the merged Phase 4 non-exporting KeyStore. Merged
Phase 5 provides a portable, bounded Personal Vault reference model. Its object IDs
are names rather than access grants; authorization is checked before object
lookup or metadata disclosure, and sealed metadata and content commit as a
single snapshot. See `docs/Phase_5_Personal_Vault_and_Object_Storage_v0.1.md`.
Phase 6 proposes a separate capability security-state authority with session
handles, scoped explicit delegation, parent-child revocation and restart
semantics. See `docs/Phase_6_Capability_Authority_and_Revocation_v0.1.md`.
There is no production Linux trusted storage, cross-process lease,
security-state key/clock provisioning, caller-bound service or App permission
flow yet. The Vault's temporary authorizer is not wired to this service.

## Mandatory project execution contract

Before planning or implementing the next milestone, **every AI agent and engineer must read `docs/PROJECT_EXECUTION_CONTRACT.md` together with the current `main` source tree and the higher-priority Constitution / Threat Model / Architecture / accepted ADRs**.

That contract defines:

- the final product and system that ICC is intended to become;
- the mandatory Core and Minimal-OS development tracks;
- the deterministic algorithm for deciding the next unfinished milestone from merged `main` evidence;
- the required scope, non-scope, security evidence and exit gates for each future Phase;
- the branch / CI / PR workflow;
- the rule that an AI should normally continue autonomously through implementation and CI repair instead of asking the owner what to build next;
- the stop condition: **open a reviewed-ready PR with the latest PR-head CI green, then stop — never merge automatically**.

An unmerged branch or PR is not a completed milestone. The next milestone begins only after the preceding required PR has been manually reviewed and merged into `main`.

## Architecture baseline

- Domain/Core crates are `no_std` where required by Phase 0.3.
- OS effects enter through narrow Port traits.
- Linux-specific code is isolated in Linux adapters.
- Domain Core does not directly depend on crypto-provider implementation crates;
  Identity Core uses only the provider-neutral verification API.
- Local authorization remains authority-side; UI/CLI is not a security authority.
- Every workspace package has a fail-closed allowlist for all direct dependency declarations, including optional, dev, build, target-specific, path, registry, and renamed declarations.
- The policy validates the declared version requirement, source/path identity, default-feature setting, and requested features independently of whether Cargo activates the edge.
- Default and all-features locked graphs are checked separately; the all-features feature union must match the reviewed Phase 2 crypto feature policy.
- The repository dependency policy rejects direct production App dependencies
  on Identity Core, Vault Core, `icc-crypto-api`, `icc-crypto-rust`,
  `icc-keystore`, `icc-vault-crypto`, and `icc-capability-crypto`.
- Secret wrapper identifiers are additionally guarded by conservative source checks outside the crypto boundary.
- Fifteen independent `compile_fail` doctests provide compiler-level regression evidence that each of the five secret wrappers implements none of `Clone`, `Copy`, or `Debug`.
- Source-pattern checks do not expand arbitrary macros and are not Rust AST, compiler, visibility, runtime-sandbox, or formal proofs. The compile-fail tests are compiler checks, but not formal verification.
- Production dependency resolution is committed in the root `Cargo.lock`.

## Toolchain

Pinned by `rust-toolchain.toml`:

```text
Rust 1.98.1
Cargo 1.98.1
Edition 2024
```

## Phase 2 ClassicalV1

```text
Hash:          SHA-256
KDF:           HKDF-SHA-256
Signature:     Ed25519
Key agreement: X25519
AEAD:          ChaCha20-Poly1305
```

`Argon2idV13` currently has a stable algorithm identifier only; password-derived key handling is intentionally not implemented in Phase 2.

## Phase 3 identity model

- The root-domain identifier and root key reference are private authority state,
  not an App login identifier.
- Every App receives an independently random pseudonym and a distinct
  `AppAuthentication` public-key binding.
- Device enrollment, device/App key rotation, revocation, and recovery approval
  use versioned, domain-separated Ed25519 authorization transcripts.
- Device revocation requires a different active device. Recovery uses a bounded
  M-of-N authority policy with a minimum threshold of two.
- Successful recovery rotates the root binding, revokes old devices, cancels
  pending enrollments, and suspends active App identities until a new-device
  authorization rotates their keys.
- The crate is a `no_std + alloc` domain state machine. It does not yet provide
  private-key storage, caller-bound IPC, durable persistence, rollback defense,
  recovery notification transport, or a network identity protocol.

## Verification commands

The main verification sequence below mirrors `.github/workflows/ci.yml`.

```bash
# Pinned toolchain and bare-metal target
rustup toolchain install 1.98.1 --profile minimal --component rustfmt,clippy
rustup target add --toolchain 1.98.1 thumbv7em-none-eabi
rustc --version
cargo --version

# Committed locked dependency graph
test -f Cargo.lock
cargo metadata --locked --format-version 1 \
  > /tmp/icc-cargo-metadata-default.json
cargo metadata --locked --all-features --format-version 1 \
  > /tmp/icc-cargo-metadata-all-features.json
git diff --exit-code -- Cargo.lock

# Default/all-features inventory and architecture policy tests
python3 scripts/dependency_inventory.py /tmp/icc-cargo-metadata-default.json
python3 scripts/dependency_inventory.py /tmp/icc-cargo-metadata-all-features.json
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/check_architecture.py \
  --default-metadata /tmp/icc-cargo-metadata-default.json \
  --all-features-metadata /tmp/icc-cargo-metadata-all-features.json

# Rust checks
cargo fmt --all -- --check
cargo check --workspace --locked
cargo check --workspace --all-features --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo test -p icc-crypto-api --doc --locked
cargo test -p icc-identity-core --doc --locked
cargo test -p icc-vault-core --doc --locked
cargo test --workspace --all-features --locked

# Bare-metal no_std portability checks
cargo check -p icc-types --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-error --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-rights --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-platform-api --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-capability-core --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-identity-core --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-crypto-api --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-crypto-rust --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-vault-core --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-vault-crypto --target thumbv7em-none-eabi --no-default-features --locked

# Dependency policy tool; CI pins the exact version and uses the tool package lockfile
cargo install --locked --version 0.20.2 cargo-deny
cargo deny \
  --metadata-path /tmp/icc-cargo-metadata-all-features.json \
  check advisories bans licenses sources

# Repeated locked release build and lockfile stability
sha256sum Cargo.lock > /tmp/icc-cargo-lock.sha256
cargo build --workspace --release --locked
cargo build --workspace --release --locked
cargo build --workspace --release --all-features --locked
cargo build --workspace --release --all-features --locked
sha256sum --check /tmp/icc-cargo-lock.sha256
git diff --exit-code -- Cargo.lock
```

## Demo

```bash
cargo run -p indie-cli --locked -- doctor
cargo run -p indie-cli --locked -- demo
```

The CLI deliberately has no dependency on Identity Core or the internal crypto
API/provider, and prints no root identity identifier. The authority-side
identity state machine is exercised through integration tests until a later
caller-bound service/API exists.

## Security and design documents

- `docs/PROJECT_EXECUTION_CONTRACT.md` — mandatory master product roadmap and AI development/merge contract
- `SECURITY.md`
- `docs/Phase_0_System_Constitution_v0.1.md`
- `docs/Phase_0.2_Threat_Model_v0.1.md` (index to hash-verified split parts)
- `docs/Phase_0.3_Architecture_Boundaries_and_Dependency_Rules_v0.1.md` (index to hash-verified split parts)
- `docs/Phase_1_Project_Skeleton_and_Engineering_Baseline_v0.1.md`
- `docs/Phase_2_Cryptographic_Foundation_v0.1.md`
- `docs/security/Phase_2_Dependency_Review_v0.1.md`
- `docs/Phase_2_Cryptographic_Hardening_Report_v0.1.md`
- `docs/Phase_3_Identity_Core_v0.1.md`
- `docs/Phase_3_Identity_Core_Completion_Report_v0.1.md`
- `docs/Phase_4_KeyStore_and_Secret_Operations_v0.1.md`
- `docs/Phase_5_Personal_Vault_and_Object_Storage_v0.1.md`
- `docs/Phase_5_Personal_Vault_and_Object_Storage_Completion_Report_v0.1.md`
- `docs/Phase_6_Capability_Authority_and_Revocation_v0.1.md`
- `docs/Phase_6_Capability_Authority_and_Revocation_Completion_Report_v0.1.md`
- `docs/adr/ADR-0001` through `ADR-0009` (see individual status), proposed
  `ADR-0010` (Phase 5 storage separation) and `ADR-0011` (Phase 6 security state)

This is a prototype architecture/security baseline, not a production security product. See `SECURITY.md` for explicit non-claims and remaining reporting/governance risks.
