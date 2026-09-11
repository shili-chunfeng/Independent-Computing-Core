# ADR-0002 — Pin Phase 1 to Rust 1.98.1

**Status:** Accepted  
**Phase:** 1

## Context

Phase 1 needs a reproducible toolchain baseline while adopting Edition 2024 and workspace lint inheritance.

## Decision

Pin `rust-toolchain.toml` to Rust 1.98.1 with the minimal profile plus `rustfmt` and `clippy`.

## Consequences

- Local development and CI target the same compiler release.
- Toolchain updates are explicit engineering events.
- A future upgrade requires the full Phase 1 verification suite.
