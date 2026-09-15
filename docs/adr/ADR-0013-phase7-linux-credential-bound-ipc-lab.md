# ADR-0013 — Linux credential-bound IPC laboratory before Vault wiring

**Status:** Proposed; Phase 7 partial scope for owner review

## Context

ICC Domain Core stays `no_std`; Phase 6 requires trusted caller binding and
non-rollbackable storage before an App can use its authority. Linux Unix
streams provide a concrete process boundary but Rust stable 1.98.1 does not
expose `UnixStream::peer_cred` as a stable API; introducing a security FFI or
new Rust dependency would require separate unsafe/dependency review. A
request-supplied App ID is not an acceptable substitute.

## Decision

Use Python standard-library `socket.SO_PEERCRED` **only** inside a small Linux
laboratory adapter, with a transport-independent versioned parser and a
separate service-owned ephemeral sample resource. Map kernel UID to a trusted
App identity, fail closed on unknown UID, enforce per-session reference and
endpoint policy at every effect, and mediate transfer through a one-use
recipient-bound offer. Put live Unix socket and restart tests in an independent
CI job. Keep all Rust Domain Core crates and existing architecture allowlists
unchanged. This makes the security boundary observable while durable ICC
service composition is designed and reviewed.

## Alternatives and limits

Rust `std` peer credentials: rejected for this stage because the API remains
nightly-only. Unreviewed `unsafe`/raw FFI or a new third-party dependency:
deferred until its security footprint and lockfile are explicitly reviewed.
Using a claimed App ID: rejected because it allows direct spoofing. A
filesystem-only socket mode: insufficient for per-App authorization.

This decision does **not** claim Python is the permanent runtime, that sample
state is a Vault, that UID equality separates same-UID adversaries, that
SO_PEERCRED survives a hostile root/kernel, or that Phase 7 is complete.
The eventual ICC authority service must replace the sample policy/resource
and enforce the Phase 6 trusted-store and operation-level guarantees.

Relevant upstream references: [Rust UnixStream::peer_cred](https://doc.rust-lang.org/std/os/unix/net/struct.UnixStream.html#method.peer_cred)
and [Linux SO_PEERCRED](https://man7.org/linux/man-pages/man7/unix.7.html).
