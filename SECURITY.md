# Security Baseline

This Phase 1 repository is an architecture and engineering skeleton, not a production security product.

## Security claims intentionally not made

The project does not claim protection against:

- a compromised Linux kernel or root account;
- physical attacks;
- malicious firmware;
- side-channel attacks;
- production-grade key extraction resistance.

## Baseline rules

- Domain Core crates forbid unsafe Rust.
- Domain Core crates must not directly use OS APIs.
- Authorization is decided by domain/runtime authority, not by UI or caller-supplied labels.
- Randomness, time and persistence are explicit injected dependencies.
- Third-party runtime dependencies are intentionally absent in Phase 1.

Threat identifiers and security invariants are defined in the Phase 0.2 Threat Model.


## Phase 2 cryptography

ClassicalV1 uses reviewed external cryptographic primitives through `icc-crypto-api`. Secret wrapper types are not application APIs. Do not enable `ed25519-dalek` `legacy_compatibility` or `hazmat` features. Do not reuse ChaCha20-Poly1305 nonces under a key. Any new crypto profile or algorithm requires an ADR and migration analysis.
