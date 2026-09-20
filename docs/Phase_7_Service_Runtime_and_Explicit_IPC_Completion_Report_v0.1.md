# Phase 7 — Service Runtime & Explicit IPC: partial implementation evidence v0.1

**Milestone status:** NOT COMPLETE; laboratory slice proposed in a draft PR.  
**Base main HEAD:** `d8e323cd2cd0d686c0e45e61aefe59ad5912855f`  
**Branch:** `phase-7-service-runtime`  
**Branch HEAD / PR / CI:** pending initial push; see PR checks for exact HEAD.  
**Merge status:** NOT MERGED.

## Changed files and architecture consequences

The new `services/phase7/` package separates a bounded binary protocol,
service-owned volatile authority model, and Linux `SO_PEERCRED` transport.
The `phase7-ipc` GitHub Actions job requires real Unix-socket tests; README
and SECURITY state the scope and limitations. Proposed ADR-0013 records the
Python standard-library Linux adapter decision. No Rust workspace package,
`no_std` Core API, Cargo lockfile, third-party dependency, persistent format,
or ICC crypto provider was changed. This **does not** bind Phase 6's authority
to Phase 5's Vault or add a protected ICC App endpoint.

## Threat IDs and observations

| Threat | Tested laboratory property | Status |
|---|---|---|
| T-IPC-001 | Unknown UID rejected, live kernel credentials, cross-session reference denied | protocol/model pass; live CI pending |
| T-IPC-002 | Truncated/oversized/unknown-version/enum/flags/id rejected; deterministic 10,000-input corpus | local pass |
| T-IPC-003 | STATUS and WRITE denied without provisioned endpoint rights | local pass; live CI pending |
| T-IPC-004 | Recipient-bound one-use offers, denied rights expansion/expiry/source loss/restart | local model pass; live restart CI pending |
| T-IPC-005 | Four connections, eight handles/session, sixteen offers, max 4096 frame/1024 value, deadline/32 requests | model pass; live backpressure CI pending |

Local commands actually run: `python3 -m unittest -v
services.phase7.test_phase7` (seven protocol/model tests passed; two live
Linux tests **skipped because the local sandbox forbids socket creation**),
`python3 -m unittest discover -s scripts -p 'test_*.py'` (42 passed),
`python3 -m compileall -q services/phase7`, `git diff --check` (passed).
No local Rust or QEMU claim is made; existing required CI jobs must run at
the exact branch HEAD. CI run IDs/URLs, live test results and branch SHA are
**pending** until the initial push and checks complete.

## NOT VERIFIED / remaining risks

No durable, cross-process Phase 6 state/lease, stable clock, root provisioning
or Vault/KeyStore operation routing is implemented. The sample CLI supports
one UID; same-UID malicious processes and actual cross-UID transfer are not
isolated/tested. Crash-stale socket cleanup needs a trusted supervisor;
availability under hostile local resource exhaustion is not guaranteed. The
deterministic corpus is not coverage-guided fuzzing. No real App caller flow,
secret access, production IPC security or full Phase 7 exit gate is claimed.
OS-1, OS-2, networking, user processes and packaging remain out of scope.

The draft PR must remain **NOT READY for Phase 7 milestone review** until a
later implementation closes the integration blockers and latest-head push/PR
CI logs are read. No automatic merge.
