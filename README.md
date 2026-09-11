# Independent Computing Core — Phase 2 Cryptographic Foundation

Independent Computing Core (ICC) is a portable personal-computing core intended to move from a Linux/VM prototype toward a future minimal OS without making Linux part of the Domain Core contract.

The repository currently contains the Phase 0 architecture/security baselines, Phase 1 engineering skeleton, and Phase 2 ClassicalV1 cryptographic foundation. **Phase 3 has not started.**

## Architecture baseline

- Domain/Core crates are `no_std` where required by Phase 0.3.
- OS effects enter through narrow Port traits.
- Linux-specific code is isolated in Linux adapters.
- Domain Core does not directly depend on crypto-provider implementation crates.
- Local authorization remains authority-side; UI/CLI is not a security authority.
- The current repository dependency policy rejects direct production App dependencies on `icc-crypto-api` and `icc-crypto-rust`.
- Secret wrapper identifiers are additionally guarded by conservative source checks outside the crypto boundary.
- These repository/CI checks are not Rust visibility guarantees, runtime sandboxing, or formal proofs.
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

The main verification sequence below mirrors `.github/workflows/ci.yml`.

```bash
# Pinned toolchain and bare-metal target
rustup toolchain install 1.98.1 --profile minimal --component rustfmt,clippy
rustup target add --toolchain 1.98.1 thumbv7em-none-eabi
rustc --version
cargo --version

# Committed locked dependency graph
test -f Cargo.lock
cargo metadata --locked --format-version 1 > /tmp/icc-cargo-metadata.json
git diff --exit-code -- Cargo.lock

# Resolved dependency inventory and architecture policy tests
python3 scripts/dependency_inventory.py /tmp/icc-cargo-metadata.json
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/check_architecture.py

# Rust checks
cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

# Bare-metal no_std portability checks
cargo check -p icc-types --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-error --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-rights --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-platform-api --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-capability-core --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-identity-core --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-crypto-api --target thumbv7em-none-eabi --no-default-features --locked
cargo check -p icc-crypto-rust --target thumbv7em-none-eabi --no-default-features --locked

# Dependency policy tool; CI pins the exact version and uses the tool package lockfile
cargo install --locked --version 0.20.2 cargo-deny
cargo deny --metadata-path /tmp/icc-cargo-metadata.json check advisories bans licenses sources

# Repeated locked release build and lockfile stability
sha256sum Cargo.lock > /tmp/icc-cargo-lock.sha256
cargo build --workspace --release --locked
cargo build --workspace --release --locked
sha256sum --check /tmp/icc-cargo-lock.sha256
git diff --exit-code -- Cargo.lock
```

## Demo

```bash
cargo run -p indie-cli --locked -- doctor
cargo run -p indie-cli --locked -- demo
```

The CLI deliberately does not depend directly on the internal crypto API/provider. Secret cryptographic operations remain exercised in provider tests; this Phase 2 hardening work does not invent a facade, service, Identity feature, or Phase 4 KeyStore merely to preserve a crypto CLI demo.

## Security and design documents

- `SECURITY.md`
- `docs/Phase_0_System_Constitution_v0.1.md`
- `docs/Phase_0.2_Threat_Model_v0.1.md` (index to hash-verified split parts)
- `docs/Phase_0.3_Architecture_Boundaries_and_Dependency_Rules_v0.1.md` (index to hash-verified split parts)
- `docs/Phase_1_Project_Skeleton_and_Engineering_Baseline_v0.1.md`
- `docs/Phase_2_Cryptographic_Foundation_v0.1.md`
- `docs/security/Phase_2_Dependency_Review_v0.1.md`
- `docs/Phase_2_Cryptographic_Hardening_Report_v0.1.md`
- `docs/adr/ADR-0001` through `ADR-0006`

This is a prototype architecture/security baseline, not a production security product. See `SECURITY.md` for explicit non-claims and remaining reporting/governance risks.
