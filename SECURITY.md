# Security Baseline

Independent Computing Core is currently a **Phase 5 architecture/security
prototype**, not a production security product.

The A1-only KeyStore binds `IdentityKeyId`, purpose, and public key to
the signing seed, and commits an authenticated snapshot before key lifecycle
changes become visible. `KeyHandle` is a reference, **not** permission to sign:
a future trusted service must bind the actual caller before invoking it. Its
in-memory test Port models rollback-resistant atomic state, but no production
Linux anti-rollback adapter, seal-root provisioning, or App-facing permission
gate exists. Do not claim actual durable anti-rollback, host-root, physical,
swap, or crash-dump protection. Identity Core still lacks durable persistence.

Phase 4's v2 review remediation binds each descriptor to a trusted never-reused
issuance epoch and requires an exclusive, non-stealable Port lease for the
entire live signing instance. The memory test Port models
same-process exclusion only;
there is no production interprocess/hardware lease, so production revocation
consistency is not claimed. v1 snapshots are refused by v2 without implicit
migration or re-provisioning; old identities require a separately reviewed
rekey/reconciliation procedure. Decoder zero/duplicate-secret rejection is
likewise not evidenced by the historical CI run.

The security model is defined primarily by:

- `docs/Phase_0_System_Constitution_v0.1.md`
- `docs/Phase_0.2_Threat_Model_v0.1.md` and its hash-verified split parts
- `docs/Phase_0.3_Architecture_Boundaries_and_Dependency_Rules_v0.1.md` and its hash-verified split parts
- `docs/Phase_2_Cryptographic_Foundation_v0.1.md`
- `docs/security/Phase_2_Dependency_Review_v0.1.md`
- `docs/Phase_3_Identity_Core_v0.1.md`
- `docs/Phase_4_KeyStore_and_Secret_Operations_v0.1.md`
- `docs/Phase_5_Personal_Vault_and_Object_Storage_v0.1.md`

The Phase 5 Vault proposal keeps IDs separate from grants, gates reads,
listing and mutations through an injected authority decision, and encrypts
the complete bounded object snapshot (including metadata). A dedicated
`VaultStateStore` Port requires atomic commit, unique nonce epochs, trusted
freshness and a non-stealable lease. These properties have only a single-process
test model: there is **no production Linux implementation, provisioned Vault
root key, caller-bound service, or usable App-level access control**. Passing
tests does not establish real durability, rollback protection or application
isolation. A request-supplied authorization implementation would invalidate the
model; real caller verification and grant revocation remain later milestones.

## Explicit prototype limits

The current Linux/VM prototype does **not** claim to preserve software-only secrecy or integrity after compromise of the host kernel or a root-equivalent attacker. In that situation an attacker may be able to inspect or modify process memory, IPC state, software-held keys, runtime state, files, or executable code.

The project also does not currently claim protection against:

- extraction of sensitive values from process memory by a privileged attacker;
- malicious or compromised firmware;
- DMA or physical-memory attacks;
- alternate-boot / evil-maid attacks;
- CPU cache, speculative-execution, fine-grained timing, power, EM, or other microarchitectural/physical side channels;
- debugger/core-dump/swap/hibernation copies controlled by a hostile host;
- production-grade anti-tamper or hardware-backed key isolation;
- formal verification of the cryptographic composition or Rust implementation;
- complete elimination of all compiler-created or register/stack copies of secret material.

Passing `no_std`, known-answer vectors, cargo-deny, architecture source scans, or zeroization checks must not be interpreted as establishing any of the claims above.

## Phase 2 cryptographic rules

ClassicalV1 currently uses external, standardized primitives through the `icc-crypto-api` / `icc-crypto-rust` provider boundary:

- SHA-256
- HKDF-SHA-256
- Ed25519
- X25519
- ChaCha20-Poly1305

Security-critical rules include:

- Do not invent new cryptographic primitives.
- Do not enable `ed25519-dalek` `hazmat` or `legacy_compatibility` features.
- Do not reuse a ChaCha20-Poly1305 nonce with the same key.
- Do not expose raw private keys/seeds through Apps or ordinary Domain Core APIs.
- Secret wrapper types are internal crypto-boundary implementation types, not wire/persistent/App types.
- Each of the five secret wrappers has independent compiler-level `compile_fail` regressions for `Clone`, `Copy`, and `Debug`; these tests are regression evidence, not formal verification.
- `zeroize` is best-effort cleanup of owned storage; it is not a guarantee against hostile-kernel memory extraction, compiler-created copies, side channels, or physical attacks.
- Any new cryptographic profile/algorithm requires explicit architecture review and migration/downgrade analysis.

## Phase 3 identity rules and limits

- Root-domain identifiers and root/recovery key references are authority state.
  They must not enter normal App views or CLI output.
- App identity is pairwise: each App has an independently random pseudonym and
  a distinct App-purpose public-key binding. Reuse of key IDs or public keys
  across identity purposes/Apps is rejected.
- Security transitions are authorized by signatures over the state machine's
  exact versioned transcript. A caller-supplied role, name, or boolean is not
  authority.
- Revoked devices and stale-generation proofs fail closed. Device self-revocation
  is denied; a different active device or the recovery ceremony is required.
- Recovery requires at least two distinct current authorities. Success rotates
  root authority, revokes old devices, clears pending enrollments, and suspends
  active App identities.
- Collections and random-ID collision retries are explicitly bounded. Resource
  exhaustion and entropy failure deny the transition without weakening policy.
- Identity Core holds public verification values and stable key IDs only. The
  future Phase 4 KeyStore must bind those IDs to non-exported operations.
- The movable `IdentityState` is not a persistent/wire format. Phase 3 has no
  authenticated atomic storage, durable corruption recovery, freshness, or
  snapshot-rollback defense; those properties are **NOT VERIFIED**.
- Future service/runtime code must bind the real caller/App/device authority-side.
  Direct access to `IdentityCore` is not an App API.

## Architecture and supply-chain rules

- L0/L1/L2 portable crates must preserve the Phase 0.3 dependency direction and `no_std` contract.
- Linux-specific APIs remain in platform adapters.
- Domain Core must not directly depend on provider implementation crates.
- The per-package repository policy rejects direct production App dependencies
  on `icc-identity-core`, `icc-crypto-api`, `icc-crypto-rust`, and `icc-keystore`.
- `icc-identity-core -> icc-platform-api` is an explicit reviewed Phase 1 Port dependency-inversion edge; it does not authorize a general L2-to-Port dependency rule.
- `icc-identity-core -> icc-crypto-api` is the reviewed Phase 3 provider-neutral
  signature-verification edge; a Domain-Core dependency on `icc-crypto-rust`
  remains forbidden.
- Every non-root Cargo package manifest in the repository must name a formal workspace member. New or unclassified packages fail closed.
- Every workspace package has a complete allowlist for normal, dev, build, target-specific, optional, path, registry, and renamed direct dependency declarations. The checker validates actual package identity, local alias, kind, target condition, optional flag, source/path, exact version requirement, default-feature setting, and requested features even when the dependency is inactive.
- The reviewed external production dependencies require literal exact manifest pins (`=version`). A compatible Cargo resolution under a broader requirement is not accepted.
- Production dependency resolution is committed in `Cargo.lock` and CI uses `--locked`.
- CI keeps separate default and `--all-features` Cargo metadata. The default graph remains build/inventory evidence; the all-features graph is additionally checked for the reviewed direct feature union and is supplied to cargo-deny so inactive optional dependencies are not omitted by default.
- CI checks both default and all-features workspaces, the current locked graphs, advisories, license policy, source policy, banned crates/features, architecture boundaries, architecture negative fixtures, standards-based tests, and a bare-metal `thumbv7em-none-eabi` compile target.
- Secret-trait/source checks are conservative source-pattern analysis and do not expand arbitrary macros. They are not a Rust parser or AST, compiler proof, visibility proof, runtime sandbox, or formal proof. Separate compile-fail doctests provide compiler-level evidence only for the current `Clone`, `Copy`, and `Debug` regressions.
- Dependency and advisory checks are time-bounded evidence, not proof that dependencies have no vulnerabilities, unsafe code, or future maintenance risk.

## Vulnerability reporting

There is currently **no owner-approved private vulnerability reporting email, form, or security advisory workflow documented in this repository**.

Do not invent or infer a private reporting address from commit metadata or account details.

Until the repository owner explicitly selects a private reporting channel, this is a **Remaining Risk**. Sensitive vulnerability details should not be posted publicly merely because no private channel is documented.

## Project license

No owner-approved repository `LICENSE` has been selected. Dependency-license
policy does not assign a license to ICC itself. Project licensing remains an
owner decision.

## Repository governance

At the time of this hardening review, `main` is not protected by a GitHub branch-protection rule/ruleset. Therefore direct-push prevention is **not enforced by GitHub**. This hardening task does not change repository governance settings; owner action is required if protected-branch enforcement is desired.
