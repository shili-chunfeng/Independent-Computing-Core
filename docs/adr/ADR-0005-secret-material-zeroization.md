# ADR-0005 — Secret Material and Zeroization

## Status

Accepted.

This hardening update expands the rationale and consequences required by the Phase 0 ADR format. It does **not** change the original decision.

## Context

Phase 0 C-009 requires private-key material to remain inside an appropriate key/crypto boundary rather than being exposed to ordinary applications. Phase 2 needs typed secret values internally so the provider can implement standardized primitives, but exposing those values to Apps, ordinary Domain Core, wire formats, persistent formats, or platform adapters would create ambient copying/export paths before a proper KeyStore exists.

Rust byte arrays are value types and third-party crypto APIs may internally create temporary values. Therefore software zeroization can reduce persistence of owned secret storage but cannot prove elimination of every compiler-created copy, register value, stack spill, allocator copy, core dump, swap/hibernation image, kernel snapshot, or physical-memory remanence.

The Linux prototype also explicitly treats a compromised root/kernel as outside the software-only secrecy guarantee.

## Decision

1. In-memory ICC secret wrappers are typed and internal to the crypto boundary.
2. Secret wrapper types are not `Copy`, `Clone`, `Debug`, or serializable types.
3. Owned wrapper storage is zeroized on `Drop` using the vetted `zeroize` dependency.
4. Secret wrappers must not cross IPC, become wire/persistent formats, or appear in ordinary App/Domain/Platform APIs.
5. Phase 2 CLI/demo code must not construct or retain raw private-key/seed wrappers.
6. Phase 2 does not invent an early KeyStore only to preserve a demo. Future normal callers will use opaque `KeyHandle`-style operations when the KeyStore phase is designed.
7. Provider-internal temporary secret values are permitted only inside the crypto implementation boundary and remain subject to documented residual-copy limitations.
8. Architecture checks enforce the wrapper boundary and forbidden traits, but those checks are conservative source/metadata checks rather than a formal Rust AST proof.

## Alternatives Considered

### Expose raw secret byte arrays to callers

Rejected. It makes key export/copying the default API and violates Phase 0 C-009.

### Make secret wrappers `Clone`/`Copy`/`Debug` for ergonomics

Rejected. It increases accidental copying/logging and weakens the ownership model.

### Serialize secret wrappers for IPC/persistence

Rejected. Local in-memory secret wrappers are implementation values, not stable authority or persistence formats.

### Implement the future KeyStore during Phase 2

Rejected. That would pull Phase 4 design into Phase 2 without its threat model and lifecycle design.

### Claim `zeroize` provides complete memory erasure

Rejected. Zeroization can protect owned storage from ordinary compiler dead-store elimination, but it does not establish hostile-kernel, side-channel, physical-memory, or compiler-copy guarantees.

## Security Consequences

Positive:

- App/CLI code cannot legitimately obtain ICC secret wrapper values.
- Accidental `Debug` logging and implicit cloning/copying are reduced.
- Owned secret wrapper storage receives best-effort cleanup on destruction.
- The future KeyStore can replace raw-secret calling patterns without first undoing an App-facing API.

Limitations / remaining risks:

- Third-party crypto implementation internals and compiler-created temporary copies are not proven to be zeroized.
- Root/kernel compromise, memory extraction, crash dumps, swap/hibernation, and physical/side-channel attacks remain outside the Phase 2 guarantee.
- No formal verification or source-level third-party unsafe audit is implied.

## Performance Consequences

- Avoiding `Clone`/`Copy` may require explicit ownership transfers inside the provider.
- Zeroization adds a small destruction cost proportional to secret storage size.
- The design intentionally accepts this small cost for clearer secret ownership.
- No extra IPC/process boundary is introduced by this ADR in Phase 2.

## Portability Consequences

- Secret wrappers remain `no_std` compatible under the selected provider/dependency configuration.
- No Linux-specific API is introduced into the secret type model.
- The future OS/KeyStore implementation can replace storage/execution internals without exposing provider-specific secret representations to callers.

## Migration Consequences

- Existing App code that imported `Ed25519SigningSeed` or other secret wrappers must be removed rather than grandfathered.
- Future callers migrate to opaque handle operations when the KeyStore API exists.
- Wire and persistent schemas must never depend on these wrapper layouts, so no schema migration is required when internal representation changes.
- Any future request to export raw secret material requires a new explicit architecture/security decision; it is not implicitly allowed by this ADR.
