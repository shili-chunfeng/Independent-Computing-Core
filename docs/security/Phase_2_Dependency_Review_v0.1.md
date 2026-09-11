# Independent Computing Core
## Phase 2 — Dependency Security Review v0.1

**Review date:** 2026-09-11  
**Scope:** Phase 2 locked production/workspace dependency graph  
**Base branch:** `main` at `1289214008c0e0c58cef340b322aa5d50131937e`  
**Hardening branch evidence:** GitHub Actions `phase2-ci` run #65, commit `4fed67d332d656b6c788ef87a8e3a19736c3d380`

---

## 1. Purpose

This review addresses Phase 0.3 §§44–50, 79–81 and 88, Phase 2 §32, and Threat `T-PKG-007`.

The repository now commits a root `Cargo.lock` and resolves the graph using Rust/Cargo 1.98.1 with `cargo metadata --locked`. CI fails if the lockfile is missing, cannot resolve with `--locked`, or changes during repeated locked release builds.

This document does **not** claim that dependency source code has been exhaustively audited. In particular, upstream unsafe-code footprint is marked `NOT VERIFIED` unless there is direct evidence in this review. `cargo-deny` advisory/license/source results are not treated as an unsafe-code audit.

---

## 2. Evidence and tools

The review uses:

- Rust 1.98.1 / Cargo 1.98.1 from the repository `rust-toolchain.toml`.
- `Cargo.lock` format v4 committed in the repository.
- `cargo metadata --locked --format-version 1` for exact versions, source, declared license expression, target kinds, and resolved features.
- `scripts/dependency_inventory.py` to render Cargo metadata without inventing missing facts.
- `cargo-deny 0.20.2`, installed with `cargo install --locked --version 0.20.2 cargo-deny`.
- `deny.toml` for advisory, license, source, duplicate/wildcard, banned crate, and banned feature policy.
- GitHub Actions run #65: `advisories ok, bans ok, licenses ok, sources ok`.
- Rust bare-metal target `thumbv7em-none-eabi` to validate the selected portable dependency configuration for L0/L1/L2 and crypto portable crates.

Authoritative upstream references used for direct dependencies include the published crate metadata/docs and upstream project repositories. `cargo-deny 0.20.2` identifies itself as actively developed, MIT OR Apache-2.0, with Rust 1.88 minimum in its upstream `Cargo.toml`.

### Tooling limitation

`cargo-deny` is D2 build/CI tooling, not a production dependency. Its own transitive graph is isolated to installation/execution in CI and is not added to the ICC `Cargo.lock`. The tool is installed using its packaged lockfile. A manual line-by-line unsafe audit of cargo-deny and all of its transitive dependencies is **NOT VERIFIED**.

---

## 3. Direct dependencies

| Dependency | Exact version | Purpose / necessity | Upstream / source | License | build.rs / proc macro | Default features / actual enabled features | no_std compatibility | Maintenance status | Unsafe footprint | Supply-chain risk | Replaceability / production TCB |
|---|---:|---|---|---|---|---|---|---|---|---|---|
| `sha2` | 0.11.0 | SHA-256 implementation for ClassicalV1 and HKDF hash | RustCrypto/hashes; crates.io | MIT OR Apache-2.0 | no / no | defaults disabled; actual `(none)` | **VERIFIED for selected configuration** by `icc-crypto-rust` on `thumbv7em-none-eabi` | Recent 0.11.0 release observed in 2026; active upstream project | **NOT VERIFIED** | High: cryptographic primitive in provider TCB | Replaceable only behind provider/API and protocol migration rules; runtime crypto TCB |
| `hkdf` | 0.13.0 | RFC 5869 HKDF orchestration using SHA-256 | RustCrypto/KDFs; crates.io | MIT OR Apache-2.0 | no / no | defaults disabled; actual `(none)` | **VERIFIED for selected configuration** | Recent 0.13.0 release observed in 2026; active upstream project | **NOT VERIFIED** | High: key-derivation primitive path | Provider-replaceable subject to protocol compatibility; runtime crypto TCB |
| `ed25519-dalek` | 3.0.0 | Ed25519 signing and strict verification | dalek-cryptography/curve25519-dalek; crates.io | BSD-3-Clause | no / no | defaults disabled; actual `zeroize`; `hazmat`/`legacy_compatibility` forbidden | **VERIFIED for selected configuration** | 3.0.0 published in 2026; upstream actively maintained | **NOT VERIFIED** | High: signature primitive and key material handling | Provider-replaceable with explicit migration; runtime crypto TCB |
| `x25519-dalek` | 3.0.0 | X25519 key agreement and contributory check | dalek-cryptography/x25519-dalek; crates.io | BSD-3-Clause | no / no | defaults disabled; actual `static_secrets, zeroize` | **VERIFIED for selected configuration** | 3.0.0 published in 2026; upstream active | **NOT VERIFIED** | High: key-agreement primitive and secret material | Provider-replaceable with protocol migration; runtime crypto TCB |
| `chacha20poly1305` | 0.11.0 | RFC 8439 AEAD | RustCrypto/AEADs; crates.io | Apache-2.0 OR MIT | no / no | defaults disabled; actual `alloc, zeroize` | **VERIFIED for selected configuration** | 0.11.0 published in 2026; upstream active | **NOT VERIFIED** | High: AEAD primitive | Provider-replaceable with profile migration; runtime crypto TCB |
| `zeroize` | 1.9.0 | Best-effort destruction of typed secret wrapper storage | RustCrypto/utils; crates.io | Apache-2.0 OR MIT | no / no | defaults disabled in ICC; actual `(none)` | **VERIFIED** through `icc-crypto-api` bare-metal check | 1.9.0 published in 2026; upstream active | Upstream implementation details not independently audited: **NOT VERIFIED** | High: secret cleanup semantics; does not guarantee removal of compiler-created copies or hostile-kernel memory extraction | Directly coupled to secret wrapper implementation; crypto API TCB |
| `getrandom` | 0.4.3 | Linux/platform CSPRNG adapter | rust-random/getrandom; crates.io | MIT OR Apache-2.0 | yes / no | default features not explicitly disabled; resolved feature set `(none)` | **N/A to portable Core**; Linux adapter intentionally excluded from bare-metal gate | 0.4.3 published in 2026; upstream active | **NOT VERIFIED** | High: entropy source and OS FFI path | Replaceable via `SecureRandom` Port; Linux platform TCB only |

No direct production dependency version was changed by this hardening task.

---

## 4. Complete locked third-party graph

Facts below come from the actual `cargo metadata --locked` output in CI run #65. `Default active` means the resolved feature list explicitly includes a feature named `default`; it does not infer the crate's declared default set when that feature is absent.

For every row:

- **Known advisories:** `cargo-deny 0.20.2` reported `advisories ok` for the graph on 2026-09-11. This is a time-bounded database result, not a claim that future advisories cannot appear.
- **Maintenance:** direct dependencies were reviewed above. For transitive dependencies, individual maintainer activity is **NOT VERIFIED** in this review.
- **Unsafe footprint:** **NOT VERIFIED** for third-party source code. The repository's first-party unsafe scan is a separate check and does not cover dependencies.
- **Source policy:** all resolved packages came from `registry+https://github.com/rust-lang/crates.io-index`; cargo-deny reported `sources ok`.
- **License policy:** cargo-deny reported `licenses ok`; the exact Cargo license expression is retained below.

| Dependency | Version | Direct / transitive | License expression | build.rs | Proc macro | Default active | Actual enabled features | Purpose / TCB relevance | no_std status | Replaceability / risk |
|---|---:|---|---|---|---|---|---|---|---|---|
| aead | 0.6.1 | transitive | MIT OR Apache-2.0 | no | no | no | alloc | AEAD traits used by ChaCha20-Poly1305; runtime crypto path | Selected portable graph PASS | Indirect via direct AEAD crate; medium/high supply-chain relevance |
| block-buffer | 0.12.1 | transitive | MIT OR Apache-2.0 | no | no | no | none | Hash buffering | Selected portable graph PASS | Indirect; medium |
| cfg-if | 1.0.4 | transitive | MIT OR Apache-2.0 | no | no | no | none | Target configuration | Selected portable graph PASS where applicable | Indirect; medium |
| chacha20 | 0.10.2 | transitive | MIT OR Apache-2.0 | no | no | no | cipher, xchacha, zeroize | ChaCha stream cipher behind AEAD | Selected portable graph PASS | Runtime crypto TCB; high |
| chacha20poly1305 | 0.11.0 | **direct** | Apache-2.0 OR MIT | no | no | no | alloc, zeroize | ClassicalV1 AEAD | VERIFIED selected target | Runtime crypto TCB; high |
| cipher | 0.5.2 | transitive | MIT OR Apache-2.0 | no | no | no | block-buffer, stream-wrapper | Cipher traits/buffering | Selected portable graph PASS | Runtime crypto path; medium/high |
| cmov | 0.5.4 | transitive | Apache-2.0 OR MIT | no | no | no | none | Constant-time conditional move utility | Selected portable graph PASS | Runtime crypto path; high relevance |
| cpufeatures | 0.3.1 | transitive | MIT OR Apache-2.0 | no | no | no | none | CPU feature selection | Selected portable graph PASS where applicable | Indirect; medium |
| crypto-common | 0.2.2 | transitive | MIT OR Apache-2.0 | no | no | no | none | Shared cryptographic types/traits | Selected portable graph PASS | Runtime crypto path; medium/high |
| ctutils | 0.4.2 | transitive | Apache-2.0 OR MIT | no | no | no | none | Constant-time utility | Selected portable graph PASS | Runtime crypto path; high relevance |
| curve25519-dalek | 5.0.0 | transitive | BSD-3-Clause | **yes** | no | no | digest, zeroize | Curve25519 arithmetic for Ed25519/X25519 | Selected portable graph PASS | Runtime crypto TCB plus build script; high |
| curve25519-dalek-derive | 0.1.1 | transitive | MIT/Apache-2.0 | no | **yes** | no | none | Build-time derive support | Build path executed during cross-target build | Build supply-chain TCB; high |
| digest | 0.11.3 | transitive | MIT OR Apache-2.0 | no | no | **yes** | block-api, default, mac | Hash/MAC traits | Selected portable graph PASS | Runtime crypto path; medium/high |
| ed25519 | 3.0.0 | transitive | Apache-2.0 OR MIT | no | no | no | none | Signature type/trait support | Selected portable graph PASS | Runtime crypto path; high |
| ed25519-dalek | 3.0.0 | **direct** | BSD-3-Clause | no | no | no | zeroize | ClassicalV1 signature implementation | VERIFIED selected target | Runtime crypto TCB; high |
| fiat-crypto | 0.3.0 | transitive | MIT OR Apache-2.0 OR BSD-1-Clause | no | no | no | none | Generated arithmetic backend used by curve stack | Selected portable graph PASS | Runtime crypto TCB; high |
| getrandom | 0.4.3 | **direct** | MIT OR Apache-2.0 | **yes** | no | no | none | Linux/platform entropy adapter | Not part of portable Core target gate | Platform TCB; high |
| hkdf | 0.13.0 | **direct** | MIT OR Apache-2.0 | no | no | no | none | ClassicalV1 HKDF | VERIFIED selected target | Runtime crypto TCB; high |
| hmac | 0.13.0 | transitive | MIT OR Apache-2.0 | no | no | no | none | HKDF extract/expand dependency | Selected portable graph PASS | Runtime crypto path; high |
| hybrid-array | 0.4.15 | transitive | MIT OR Apache-2.0 | no | no | no | none | Fixed-size generic array support | Selected portable graph PASS | Indirect; medium |
| inout | 0.2.2 | transitive | MIT OR Apache-2.0 | no | no | no | none | Cipher input/output buffering | Selected portable graph PASS | Runtime crypto path; medium/high |
| libc | 0.2.189 | transitive | MIT OR Apache-2.0 | **yes** | no | no | none | Target-specific OS FFI for getrandom | N/A to portable crypto target; Linux/platform path | Platform supply-chain/FFI relevance; high |
| poly1305 | 0.9.1 | transitive | Apache-2.0 OR MIT | no | no | no | none | RFC 8439 authenticator | Selected portable graph PASS | Runtime crypto TCB; high |
| proc-macro2 | 1.0.107 | transitive | MIT OR Apache-2.0 | **yes** | no | **yes** | default, proc-macro | Build-time proc-macro infrastructure | Build host, not runtime no_std code | Build supply-chain TCB; high |
| quote | 1.0.47 | transitive | MIT OR Apache-2.0 | **yes** | no | **yes** | default, proc-macro | Build-time proc-macro infrastructure | Build host | Build supply-chain TCB; high |
| r-efi | 6.0.0 | transitive | MIT OR Apache-2.0 OR LGPL-2.1-or-later | no | no | no | none | Target-specific getrandom support | Not exercised as portable ICC runtime on selected target | Platform transitive; medium |
| rand_core | 0.10.1 | transitive | MIT OR Apache-2.0 | no | no | no | none | Randomness traits used by curve stack | Selected portable graph PASS | Runtime crypto path; medium/high |
| rustc_version | 0.4.1 | transitive | MIT OR Apache-2.0 | no | no | no | none | Build-time compiler-version detection | Build host | Build supply-chain; medium |
| semver | 1.0.28 | transitive | MIT OR Apache-2.0 | no | no | **yes** | default, std | Build-time version parsing | Build host | Build supply-chain; medium |
| sha2 | 0.11.0 | **direct** | MIT OR Apache-2.0 | no | no | no | none | ClassicalV1 SHA-256 | VERIFIED selected target | Runtime crypto TCB; high |
| signature | 3.0.0 | transitive | Apache-2.0 OR MIT | no | no | no | none | Signature traits | Selected portable graph PASS | Runtime crypto path; high |
| subtle | 2.6.1 | transitive | BSD-3-Clause | no | no | no | const-generics | Constant-time primitive support | Selected portable graph PASS | Runtime crypto path; high relevance |
| syn | 2.0.119 | transitive | MIT OR Apache-2.0 | no | no | **yes** | clone-impls, default, derive, full, parsing, printing, proc-macro | Proc-macro parser | Build host | Build supply-chain TCB; high |
| typenum | 1.20.1 | transitive | MIT OR Apache-2.0 | no | no | no | const-generics | Type-level sizes | Selected portable graph PASS | Indirect; medium |
| unicode-ident | 1.0.24 | transitive | (MIT OR Apache-2.0) AND Unicode-3.0 | no | no | no | none | Rust identifier parsing for proc macros | Build host | Build supply-chain; medium |
| universal-hash | 0.6.1 | transitive | MIT OR Apache-2.0 | no | no | no | none | Poly1305 hash trait | Selected portable graph PASS | Runtime crypto path; medium/high |
| x25519-dalek | 3.0.0 | **direct** | BSD-3-Clause | no | no | no | static_secrets, zeroize | ClassicalV1 X25519 | VERIFIED selected target | Runtime crypto TCB; high |
| zeroize | 1.9.0 | **direct** | Apache-2.0 OR MIT | no | no | no | none | Secret wrapper cleanup | VERIFIED selected target | Crypto API TCB; high |

**Resolved third-party package count: 38.**

---

## 5. Advisory, license, source, and banned-feature policy

`deny.toml` enforces:

- RustSec-backed advisory checking through cargo-deny.
- yanked dependencies denied.
- unknown registries denied.
- unknown Git dependencies denied.
- only the crates.io registry is permitted for the locked production graph.
- wildcard dependencies denied.
- duplicate third-party package versions denied.
- `ed25519-dalek` features `hazmat` and `legacy_compatibility` denied.
- `openssl`, `openssl-sys`, `reqwest`, `rusqlite`, and `tokio` denied because they are outside the Phase 2 dependency boundary.
- third-party license expressions must be satisfiable by the documented dependency allow-policy.

The license allow-policy is **not** a project license decision. The ICC workspace remains private/non-published Cargo packages with no owner-approved repository `LICENSE`. Selecting the ICC project license remains an owner decision and is recorded as a Remaining Risk.

### Current evidence

GitHub Actions run #65 on 2026-09-11 reported:

```text
advisories ok, bans ok, licenses ok, sources ok
```

This proves only the policy result for the locked graph and advisory database available to that run.

---

## 6. no_std / portability evidence

CI installs Rust's `thumbv7em-none-eabi` target and checks the following with `--no-default-features --locked`:

- `icc-types`
- `icc-error`
- `icc-rights`
- `icc-platform-api`
- `icc-capability-core`
- `icc-identity-core`
- `icc-crypto-api`
- `icc-crypto-rust`

Rust documents `thumbv7em-none-eabi` as a bare Armv7E-M target. It has no Linux/POSIX host environment and is therefore a stronger portability check than a host-only `cargo check --no-default-features`.

Limitation: passing one bare-metal target does not prove portability to every future ICC kernel, allocator, architecture, timing model, or hardware platform.

---

## 7. Secret material / zeroization review

The production App/CLI boundary no longer imports or constructs ICC secret wrapper types. Architecture checks reject the secret-wrapper identifiers in `apps/`, ordinary Domain Core, Ports, platform adapters, and future protocol source trees.

Secret wrappers still use `zeroize` on their owned wrapper storage. This review does **not** claim that zeroization removes every compiler-created copy, register value, stack spill, allocator copy, kernel snapshot, swap copy, crash dump, or physical-memory remanence. Provider implementation code can create temporary internal values while adapting to third-party APIs; exhaustive residual-copy analysis is **NOT VERIFIED**.

Linux root/kernel compromise, memory extraction, and microarchitectural/physical side channels remain outside the Phase 2 prototype guarantee.

---

## 8. Remaining risks

1. **Third-party unsafe footprint:** NOT VERIFIED by a source-level unsafe audit. cargo-deny does not provide this guarantee.
2. **Per-transitive maintenance health:** NOT VERIFIED individually; only direct dependency upstream recency was reviewed.
3. **cargo-deny tool supply chain:** exact tool version and packaged lock graph are pinned, but its full transitive source/unsafe review is NOT VERIFIED. It is D2 CI tooling, not production TCB.
4. **ICC repository license:** no owner-approved project `LICENSE` exists. This review does not choose one.
5. **Private vulnerability reporting channel:** no owner-approved private security email/form is present in the repository. Do not invent one.
6. **Hardware-backed key isolation:** intentionally not implemented in Phase 2; belongs to later KeyStore/hardware phases.
7. **Side-channel resistance:** not established by these tests.
8. **Formal verification:** not performed.

---

## 9. Authoritative references

- Cargo / Rust toolchain: repository `rust-toolchain.toml` and `Cargo.lock`.
- Rust platform support: <https://doc.rust-lang.org/rustc/platform-support.html>
- Bare Arm target details: <https://doc.rust-lang.org/rustc/platform-support/arm-none-eabi.html>
- cargo-deny upstream: <https://github.com/EmbarkStudios/cargo-deny>
- cargo-deny checks/config: <https://embarkstudios.github.io/cargo-deny/>
- RustSec advisory database: <https://github.com/RustSec/advisory-db>
- SHA-2 crate: <https://docs.rs/crate/sha2/0.11.0>
- HKDF crate: <https://docs.rs/crate/hkdf/0.13.0>
- Ed25519 dalek: <https://docs.rs/crate/ed25519-dalek/3.0.0>
- X25519 dalek: <https://docs.rs/crate/x25519-dalek/3.0.0>
- ChaCha20-Poly1305: <https://docs.rs/crate/chacha20poly1305/0.11.0>
- zeroize: <https://docs.rs/crate/zeroize/1.9.0>
- getrandom: <https://docs.rs/crate/getrandom/0.4.3>

---

**End of Phase 2 — Dependency Security Review v0.1**
