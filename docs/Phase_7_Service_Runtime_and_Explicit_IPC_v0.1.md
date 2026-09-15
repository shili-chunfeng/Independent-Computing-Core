# Phase 7 — Service Runtime & Explicit IPC v0.1

**Status:** Linux service laboratory slice; Phase 7 exit gate **NOT COMPLETE**  
**Base:** merged `main` `d8e323cd2cd0d686c0e45e61aefe59ad5912855f`  
**Decision:** proposed ADR-0013; no trust-root or persistent-format migration

## Goal and scope

Phase 7 is to move an important security domain behind an actual service
boundary with independently bound callers, explicit IPC, and revocation-safe
resource effects. This PR implements the *transport and authority-boundary
laboratory* first: a separate Linux process owns one volatile test resource,
checks kernel-supplied peer credentials, and never accepts a claimed AppId.
It supplies executable parser, caller, endpoint, transfer, restart and
exhaustion regressions. The service deliberately **does not** expose or claim
protection for ICC Vault, KeyStore, or Phase 6 grants yet. It cannot pass the
full Phase 7 exit gate without the missing composition described below.

Out of scope: production persistence, recovery of durable grants, secrets,
network IPC, TLS, user process sandboxing, OS-1 memory/task foundations,
OS-2 kernel handles, installed Apps and customer data.

## Architecture boundaries and trusted configuration

`services/phase7/protocol.py` describes a bounded transport-independent byte
frame. `services/phase7/runtime.py` owns the sample resource, peer-to-App
binding, policy, sessions and one-use recipient offers under one lock.
`services/phase7/linux.py` is the only Linux socket/`SO_PEERCRED` adapter.
The sample CLI entry point is an explicit laboratory composition root: its
UID and socket path parameters must be supplied by a trusted launcher; a
caller who controls those parameters is already part of the TCB. No Rust
Domain Core, Port, KeyStore or Vault depends on Python or Linux IPC.

The socket parent must be an owner-owned private directory (mode 0700), the
service refuses any pre-existing socket path, and the socket is mode 0600.
Under that configuration only a different *process of the same UID* can
connect. The runtime unit tests model two distinct provisioned UIDs for the
recipient transfer rule, but the sample CLI does **not** provision or live-test
separate UID Apps. One UID is one App here; a malicious same-UID process is
outside this laboratory's isolation claim. A production design must provide
distinct OS credentials and appropriately reachable protected socket paths.

The UID→App map, resource IDs and allowed rights are trusted service state,
not wire fields. Neither socket name, sender-provided UID/App, resource name,
session ID, handle, nor offer ID authorizes an operation alone. The server
checks the kernel peer UID, live session, handle ownership and effective
rights *at operation time*. Linux host root/kernel and service-owner
compromise are outside the software prototype's protection scope.

## Wire and API plan

Each request/response uses exactly a 20-byte header plus at most 4096 payload
bytes: `ICC7` magic (4), version `1` (u8), operation or status (u8), zero
reserved flags (u16), payload length (u32), positive request ID (u64), all
integers big-endian. Connections enforce strictly increasing request IDs,
32 requests maximum and a one-second read deadline. Unknown version, flags,
operation, invalid length or a truncated message fail closed and close the
connection. A single write transmits at most 1024 value bytes.

| Opcode | Request payload | Successful response | Required authority |
|---|---|---|---|
| PING 1 | empty | `PONG` | known kernel UID |
| STATUS 2 | empty | live session/offer counts | configured admin UID |
| OPEN 3 | resource name (16) + rights (1) | session-local reference (16) | UID→App pre-provisioned rights |
| READ 4 | local reference (16) | volatile value | live session and READ |
| WRITE 5 | local reference (16) + value (0–1024) | empty | live session and WRITE |
| CLOSE 6 | local reference (16) | empty | owning session |
| TRANSFER 7 | parent reference (16) + recipient App (16) + attenuated rights (1) | offer ID (16) | source DELEGATE, source/recipient rights |
| ACCEPT 8 | offer ID (16) | new recipient session-local reference (16) | recipient kernel UID→App binding and live source |

Statuses: OK 0, BAD_REQUEST 1, DENIED 2, BUSY 3, UNAVAILABLE 4, NOT_FOUND 5,
CAPACITY 6. The 16-byte resource name and local reference are lookup keys,
not independent capabilities. TRANSFER creates a server-side offer bound to
an explicit recipient App for at most 60 seconds; ACCEPT consumes it once and
rechecks the source and recipient policy. This is explicitly an **attenuated
copy**: the sender intentionally retains its parent reference while the
recipient gets only the requested subset. A handle sent directly to another
connection is denied. This is an **in-memory attachment model**, not serialization or
transfer of Phase 6 `LocalHandle`/durable grant authority. No protocol
compatibility beyond version 1 is implied; unknown versions fail closed.

## Persistence, lifecycle, failure and migration

No persistence format is created. Restart clears resources back to trusted
launcher defaults, sessions, handles and offers. SIGTERM requests a graceful
stop and the service removes only the socket inode that it itself bound; a
crash may leave a stale socket path, which a trusted launcher must inspect
and remove **after verifying the old process is dead**. The service never
silently adopts an existing endpoint. Any uncertainty fails closed.

Four active connections, eight handles per session, sixteen global offers,
1024 bytes per value, 4096 bytes per frame, 32 requests per connection and
short I/O deadlines bound the prototype. The listener rejects an over-limit
connection with BUSY without allocating a session. This bounds internal
state; a hostile local process can still exhaust CPU/connection opportunities.
No schema or cross-service migration is introduced.

## Threat IDs, invariants and tests

| Threat | Invariant | Evidence required |
|---|---|---|
| T-IPC-001 | kernel `SO_PEERCRED`, never request-supplied caller | live socket and unit spoof/other-session tests |
| T-IPC-002 | fixed header, strict sizes/opcodes/version, no recursive data | malformed corpus + 10,000 deterministic random byte strings |
| T-IPC-003 | known socket path or resource name cannot call STATUS/WRITE | unauthorized endpoint and mismatched-rights tests |
| T-IPC-004 | parent handle does not cross sessions; offer is one-use and recipient-bound | transfer, wrong recipient, expiry, close and restart tests |
| T-IPC-005 | bounded connections, messages, handles, offers and value | queue exhaustion, capacity and oversized-frame tests |

Tests: `python3 -m unittest -v services.phase7.test_phase7`. CI sets
`ICC_REQUIRE_UNIX_SOCKET=1` so Linux live socket and separate-process restart
tests cannot silently skip. Where local sandbox policy denies socket creation,
those live tests are recorded as **NOT VERIFIED LOCALLY**; CI must run them.
The deterministic corpus is a parser regression target, not sustained
coverage-guided fuzzing; a long-running fuzz target and wider concurrency
stress are outstanding for the full exit gate.

## Explicit Phase 7 completion blockers

Phase 6 `CapabilityAuthority` still has only in-memory test `StateStore`,
non-production trusted clock, key provision and lease; Phase 5 Vault still
uses an injected temporary authorizer. This service never instantiates them.
Before the *milestone* is ready, a trusted production composition root must
bind distinct App identities, provision a durable/non-rollbackable authority
store/clock and cryptographic sealer, and route **all** Vault/KeyStore effects
through the correctly bound authority and its exclusive operation lease.
It must test service crash/restart/revocation across real processes, malicious
same-UID/bypass paths, cross-UID recipient transfer, and resource backpressure
under contention. No CI result for this laboratory alone removes these
blockers. See the completion evidence report for tested versus unverified
claims; the PR stays draft rather than READY FOR OWNER REVIEW as Phase 7.
