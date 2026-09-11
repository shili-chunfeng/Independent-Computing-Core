# Security Baseline

Independent Computing Core is currently a **Phase 2 architecture/security prototype**, not a production security product.

The security model is defined primarily by:

- `docs/Phase_0_System_Constitution_v0.1.md`
- `docs/Phase_0.2_Threat_Model_v0.1.md` and its hash-verified split parts
- `docs/Phase_0.3_Architecture_Boundaries_and_Dependency_Rules_v0.1.md` and its hash-verified split parts
- `docs/Phase_2_Cryptographic_Foundation_v0.1.md`
- `docs/security/Phase_2_Dependency_Review_v0.1.md`

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

Passing `no_std`, known-answer vectors, cargo-deny, or zeroization checks must not be interpreted as establishing any of the claims above.

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
- `zeroize` is best-effort cleanup of owned storage; it is not a guarantee against hostile-kernel memory extraction, compiler-created copies, side channels, or physical attacks.
- Any new cryptographic profile/algorithm requires explicit architecture review and migration/downgrade analysis.

## Architecture and supply-chain rules

- L0/L1/L2 portable crates must preserve the Phase 0.3 dependency direction and `no_std` contract.
- Linux-specific APIs remain in platform adapters.
- Domain Core must not directly depend on provider implementation crates.
- Production dependency resolution is committed in `Cargo.lock` and CI uses `--locked`.
- CI checks the current locked graph for advisories, license policy, source policy, banned crates/features, architecture boundaries, standards-based tests, and a bare-metal `thumbv7em-none-eabi` compile target.
- These checks are time-bounded evidence, not proof that dependencies have no vulnerabilities or unsafe code.

## Vulnerability reporting

There is currently **no owner-approved private vulnerability reporting email, form, or security advisory workflow documented in this repository**.

Do not invent or infer a private reporting address from commit metadata or account details.

Until the repository owner explicitly selects a private reporting channel, this is a **Remaining Risk**. Sensitive vulnerability details should not be posted publicly merely because no private channel is documented.

## Project license

No owner-approved repository `LICENSE` has been selected in this Phase 2 hardening work. Dependency-license policy does not assign a license to ICC itself. Project licensing remains an owner decision.
