# Independent Computing Core
## Phase 2 — Cryptographic Hardening Report v0.1

**Status:** Hardening verification record  
**Scope:** Phase 2 only — no Phase 3 implementation  
**Base:** `main` at `1289214008c0e0c58cef340b322aa5d50131937e`  
**Branch:** `phase-2-cryptographic-hardening`  
**Review date:** 2026-09-11

---

# 1. Scope

This hardening task repairs deficiencies in the existing Phase 2 — Cryptographic Foundation. It does not implement Root Identity, Device Enrollment, Identity Rotation, Recovery Protocol, or any other Phase 3 functionality.

The work addresses:

- Phase 0 C-009 and C-010;
- Phase 0.2 Threat `T-PKG-007` and Security Gate S2;
- Phase 0.3 §§44–50, 79–81, 88 and D-ARCH-004;
- Phase 2 cryptographic test, dependency, secret-material, and verification requirements;
- ADR-0005 secret-material boundary.

---

# 2. Source-of-truth audit

Before editing, GitHub was re-read as the sole source of truth.

Verified:

- default branch: `main`;
- actual base HEAD: `1289214008c0e0c58cef340b322aa5d50131937e`;
- the provided last-known HEAD had not changed;
- repository tree, README, SECURITY, Phase 0, all Phase 0.2 parts, all Phase 0.3 parts, Phase 1, Phase 2, ADR-0001 through ADR-0006, CI, architecture checker, every workspace manifest, and all current Core/Crypto/Platform/CLI/architecture-test source were reviewed;
- no existing pull request covered this work at audit time;
- `phase-2-cryptographic-hardening` already existed, was based exactly on current `main`, and contained only task-aligned Phase 2 commits, so it was continued without force-push or overwrite.

Phase 0.2 and Phase 0.3 split documents were not destructively reorganized.

Verified index hashes remain:

```text
Phase 0.2 SHA-256
6e36ae32c162f65208a4317a84e0083e8d7c361f03df903d3c5ff5d8b05e0ff2

Phase 0.3 SHA-256
7e17f376ed8c7940bee5d9ba3da2be64a4a110ec80205372c19a4cf9aff32b3a
```

---

# 3. Reproducible dependency resolution

A root `Cargo.lock` is committed and contains the resolved Rust 1.98.1 / Cargo 1.98.1 dependency graph.

The locked graph contains 38 third-party packages plus workspace packages. CI now uses `--locked` for:

```text
cargo metadata
cargo check
cargo clippy
cargo test
portable cross-target cargo check
cargo build --release
```

CI checks that `Cargo.lock` exists, resolves with `cargo metadata --locked`, remains unchanged, and has the same SHA-256 after two identical locked release builds.

No existing direct production dependency version was updated by this hardening task.

See:

`docs/security/Phase_2_Dependency_Review_v0.1.md`

---

# 4. Dependency security policy

`deny.toml` and pinned `cargo-deny 0.20.2` enforce:

- advisory checks;
- yanked dependency rejection;
- license policy;
- registry/source policy;
- wildcard dependency rejection;
- duplicate-version rejection;
- banned dependency policy;
- banned `ed25519-dalek` `hazmat` and `legacy_compatibility` features.

The CI tool is installed as:

```bash
cargo install --locked --version 0.20.2 cargo-deny
```

It is D2 tooling, not a production ICC dependency.

GitHub Actions run #65 reported:

```text
advisories ok, bans ok, licenses ok, sources ok
```

This is time-bounded evidence for the locked graph, not a claim that the graph can never receive a future advisory.

---

# 5. Standards-based cryptographic tests

No new primitive was invented.

## HKDF-SHA-256 — RFC 5869

Tests include:

- RFC 5869 Appendix A Test Case 1;
- the ICC API returns 32 bytes, therefore the test compares exactly the **first 32 octets of the official 42-octet OKM**;
- RFC 5869 Test Case 3 zero-length salt/info boundary case, again comparing the first 32 OKM octets;
- salt mutation changes output;
- IKM mutation changes output;
- info mutation changes output.

Reference: <https://www.rfc-editor.org/rfc/rfc5869>

## Ed25519 — RFC 8032

Tests include RFC 8032 §7.1 Test 1 and negative cases for:

- exact public key;
- exact signature;
- successful verification;
- tampered message;
- tampered signature;
- invalid public-key material rejection;
- invalid signature encoding/value rejection.

`hazmat` and `legacy_compatibility` are not enabled and are blocked by policy.

Reference: <https://www.rfc-editor.org/rfc/rfc8032>

## X25519 — RFC 7748

Tests verify official known answers for:

- Alice private → public key;
- Bob private → public key;
- Alice/Bob shared secret;
- all-zero/non-contributory peer rejection.

Reference: <https://www.rfc-editor.org/rfc/rfc7748>

## ChaCha20-Poly1305 — RFC 8439

Tests verify the RFC 8439 AEAD vector including exact ciphertext and tag, plus rejection of:

- wrong key;
- wrong nonce;
- wrong AAD;
- tampered ciphertext;
- tampered tag;
- truncated authenticated input.

An empty-plaintext/empty-AAD boundary round trip is also tested.

Reference: <https://www.rfc-editor.org/rfc/rfc8439>

## Algorithm identifiers

`algorithm_ids_are_stable_for_v1` now includes:

```text
KdfAlgorithmId::HkdfSha256
KdfAlgorithmId::Argon2idV13
```

Argon2id remains an identifier/reserved future password-KDF choice; no Phase 4 KeyStore/password lifecycle was implemented here.

---

# 6. Secret material boundary

The CLI previously constructed an `Ed25519SigningSeed` from a raw `[u8; 32]` buffer for `crypto-demo`. That crossed the intended secret boundary and left a raw temporary seed buffer outside the wrapper's Drop ownership.

The hardening branch removes that behavior.

Current `crypto-demo` demonstrates only non-secret operations:

```text
profile identification
SHA-256
```

Signing, X25519 and AEAD secret-material validation remains inside provider tests.

The CLI no longer imports or constructs:

```text
Ed25519SigningSeed
X25519Secret
SharedSecret32
AeadKey32
DerivedKey32
```

No Phase 4 KeyStore was invented early to preserve the demo.

Architecture enforcement rejects these wrapper identifiers in Apps, ordinary Domain Core, Ports, platform adapters, and future protocol source directories.

### Zeroization limitation

Secret wrappers zeroize their owned `[u8; 32]` storage on Drop. This does **not** prove elimination of:

- compiler-created copies;
- register/stack spills;
- temporary values inside third-party provider code;
- kernel/root memory reads;
- swap, hibernation or crash-dump copies;
- physical or microarchitectural side channels.

Those limitations are now explicit in `SECURITY.md` and ADR-0005.

---

# 7. Architecture enforcement

`scripts/check_architecture.py` now validates more than path dependencies.

It uses `cargo metadata --locked` and enforces the current workspace layer policy for resolved direct dependency edges.

It also checks:

- required `Cargo.lock`;
- Core OS/filesystem/network/runtime implementation token exclusions;
- Domain Core/provider direction;
- crypto API/provider direction;
- provider/Linux-adapter separation;
- portable `#![no_std]` declarations;
- secret-wrapper boundary exclusions;
- secret wrappers do not gain Clone/Copy/Debug/Serialize/Deserialize through the current macro definition;
- `ed25519-dalek` hazardous/legacy features are not enabled;
- first-party production unsafe syntax is absent under the checked source roots.

The script explicitly states:

> this checker is conservative source/metadata analysis, not a Rust AST proof.

It must not be represented as formal/compiler AST verification.

---

# 8. Real no_std verification

Host-only `--no-default-features` checking was replaced/supplemented with a real cross-target gate using:

```text
thumbv7em-none-eabi
```

Rust documents this as a bare Armv7E-M target. It does not provide a Linux/POSIX host environment, so it materially tests freestanding/no_std portability.

CI cross-checks:

```text
icc-types
icc-error
icc-rights
icc-platform-api
icc-capability-core
icc-identity-core
icc-crypto-api
icc-crypto-rust
```

The Linux adapter, CLI, and test-support crates are intentionally not forced through this no_std target.

Passing one bare-metal target is not proof of universal future-OS portability.

---

# 9. Verification evidence

GitHub Actions run #65:

- Workflow: `phase2-ci`
- Run ID: `34603564948`
- Commit: `4fed67d332d656b6c788ef87a8e3a19736c3d380`
- URL: <https://github.com/shili-chunfeng/Independent-Computing-Core/actions/runs/34603564948>
- Result: **SUCCESS**

Actual successful steps included:

```text
Rust 1.98.1 / Cargo 1.98.1 install
Cargo.lock presence
cargo metadata --locked
resolved dependency inventory
architecture checks
cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
thumbv7em-none-eabi portable checks
cargo-deny 0.20.2 install using --locked
advisory/bans/licenses/sources checks
cargo build --workspace --release --locked (twice)
Cargo.lock SHA stability check
```

The provider suite executed 16 tests and all 16 passed, including the RFC known-answer and negative tests listed above. `icc-crypto-api` algorithm-ID test also passed.

A final CI run must still be evaluated on the latest documentation/PR head before declaring the hardening complete.

---

# 10. Phase 2 v0.1 documentation erratum

The original `docs/Phase_2_Cryptographic_Foundation_v0.1.md` is retained as a historical baseline rather than silently rewritten.

Its §52 wording implied that a secret Clone/Debug scan had already been implemented/passed at initial Phase 2 delivery. The original delivery did not have sufficient compiler/CI evidence for that claim.

**Correction:** secret-wrapper trait scanning and secret-boundary enforcement were added during this Phase 2 hardening work. The strengthened checker produced real PASS evidence in hardening CI (including runs #61 and #65). This report is the authoritative verification-status addendum to Phase 2 v0.1.

No checkbox or completion claim should be interpreted as complete without the CI evidence documented here and on the final PR head.

---

# 11. ADR impact

ADR-0005 was expanded to include the full Phase 0 ADR structure:

- Status
- Context
- Decision
- Alternatives
- Security consequences
- Performance consequences
- Portability consequences
- Migration consequences

Its original conclusion was not changed.

No new ADR was required because this hardening task enforces already-accepted Phase 2 decisions rather than introducing a new cryptographic architecture.

---

# 12. Remaining risks

- Third-party dependency unsafe-code footprint: **NOT VERIFIED** by a source-level audit.
- Individual maintenance health of every transitive crate: **NOT VERIFIED**.
- cargo-deny's full transitive unsafe/source audit: **NOT VERIFIED**; the exact tool/version/packaged lock are pinned, and it remains D2 CI tooling.
- ICC project license: owner decision; no `LICENSE` selected here.
- Private vulnerability reporting channel: owner decision; no approved private channel exists in repository documentation.
- Formal cryptographic verification: not performed.
- Host-root/kernel secrecy: not claimed.
- Memory-residual/side-channel resistance beyond owned-wrapper best-effort zeroization: not established.
- Future hardware-backed key protection: intentionally outside Phase 2.

---

# 13. Phase boundary

This hardening task deliberately did **not** start Phase 3.

Not implemented:

```text
Root Identity
Device Enrollment
Identity Rotation
Recovery Protocol
Phase 3 identity state machines
```

Phase 3 remains blocked until the final hardening PR head has successful required GitHub Actions evidence and the PR remains unmerged pending owner review.

---

**End of Phase 2 — Cryptographic Hardening Report v0.1**
