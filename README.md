# Independent Computing Core — Phase 2 Cryptographic Foundation

Independent Computing Core (ICC) is a portable personal-computing core intended to move from a Linux/VM prototype toward a future minimal OS without making Linux part of the Domain Core contract.

The repository currently contains the Phase 0 architecture/security baselines, Phase 1 engineering skeleton, and Phase 2 ClassicalV1 cryptographic foundation. **Phase 3 has not started.**

## Architecture baseline

- Domain/Core crates are `no_std` where required by Phase 0.3.
- OS effects enter through narrow Port traits.
- Linux-specific code is isolated in Linux adapters.
- Domain Core does not directly depend on crypto-provider implementation crates.
- Local authorization remains authority-side; UI/CLI is not a security authority.
- Secret wrapper types remain inside the crypto boundary and are not App/wire/persistent APIs.
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

## Verification commands

The commands below match `.github/workflows/ci.yml`.

```bash
# Locked dependency graph
cargo metadata --locked --format-version 1

# Architecture / supply-chain inventory
python3 scripts/dependency_inventory.py /tmp/icc-cargo-metadata.json   # CI writes metadata here
python3 scripts/check_architecture.py

# Rust checks
cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

# Bare-metal portability target installed by CI
rustup target add --toolchain 1.98.1 thumbv7em-none-eabi
cargo check -p icc-types --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-error --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-rights --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-platform-api --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-capability-core --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-identity-core --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-crypto-api --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-crypto-rust --target thumbv7em-none-eabi --no-default-features --locked

# Dependency policy tool (CI pins the exact tool version and uses its packaged lockfile)
cargo install --locked --version 0.20.2 cargo-deny
cargo deny check advisories bans licenses sources

# Release build uses the committed graph
cargo build --workspace --release --locked
```

When reproducing the CI inventory locally, first save metadata:

```bash
cargo metadata --locked --format-version 1 > /tmp/icc-cargo-metadata.json
python3 scripts/dependency_inventory.py /tmp/icc-cargo-metadata.json
```

## Demo

```bash
cargo run -p indie-cli --locked -- doctor
cargo run -p indie-cli --locked -- demo
cargo run -p indie-cli --locked -- crypto-demo
```

`crypto-demo` intentionally demonstrates only non-secret operations (profile and SHA-256). Signing/key-agreement/AEAD secret-material tests live inside the crypto provider test boundary. The project does not introduce a Phase 4 KeyStore early merely to preserve a CLI demo.

## Security and design documents

- `SECURITY.md`
- `docs/Phase_0_System_Constitution_v0.1.md`
- `docs/Phase_0.2_Threat_Model_v0.1.md` (index to hash-verified split parts)
- `docs/Phase_0.3_Architecture_Boundaries_and_Dependency_Rules_v0.1.md` (index to hash-verified split parts)
- `docs/Phase_1_Project_Skeleton_and_Engineering_Baseline_v0.1.md`
- `docs/Phase_2_Cryptographic_Foundation_v0.1.md`
- `docs/security/Phase_2_Dependency_Review_v0.1.md`
- `docs/Phase_2_Cryptographic_Hardening_Report_v0.1.md` (added by the hardening branch)
- `docs/adr/ADR-0001` through `ADR-0006`

This is a prototype architecture/security baseline, not a production security product. See `SECURITY.md` for explicit non-claims and remaining reporting/governance risks.
