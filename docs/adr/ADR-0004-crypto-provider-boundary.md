# ADR-0004 — Crypto Provider Boundary

Status: Accepted

Decision: Domain crates depend only on `icc-crypto-api`. Vetted implementation crates such as `icc-crypto-rust` implement that interface and must not leak concrete RustCrypto/dalek types into domain APIs.
