# Independent Computing Core — Phase 2 Skeleton

This repository is the first executable engineering baseline for the Independent Computing Core project.

It proves the architectural direction established in Phase 0.3:

- domain crates are portable and `no_std` where practical;
- OS effects enter through narrow Port traits;
- Linux-specific code lives only in Linux adapters;
- tests can replace platform effects with deterministic adapters;
- the CLI is a composition root, not a security authority;
- no third-party runtime dependency is required by the baseline.

## Toolchain

Pinned by `rust-toolchain.toml`:

```text
Rust 1.98.1
Edition 2024
```

## Expected checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check_architecture.py

cargo check -p icc-types --no-default-features
cargo check -p icc-error --no-default-features
cargo check -p icc-rights --no-default-features
cargo check -p icc-platform-api --no-default-features
cargo check -p icc-capability-core --no-default-features
cargo check -p icc-identity-core --no-default-features
```

## Demo

```bash
cargo run -p indie-cli -- doctor
cargo run -p indie-cli -- demo
```

The demo does **not** claim to be a secure production runtime. It only proves dependency inversion and pure authorization semantics.

See `docs/Phase_1_Project_Skeleton_and_Engineering_Baseline_v0.1.md` for the complete engineering specification.


## Phase 2 crypto baseline

`icc-crypto-api` defines the no_std typed ClassicalV1 crypto boundary. `icc-crypto-rust` implements it with pinned RustCrypto/dalek dependencies. Run `indie-cli crypto-demo` after compiler validation to exercise SHA-256 and Ed25519 through the provider boundary.
