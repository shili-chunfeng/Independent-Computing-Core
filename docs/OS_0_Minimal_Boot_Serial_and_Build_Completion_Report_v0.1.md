# OS-0 — Boot, Serial and Build: completion evidence v0.1

**Status:** Implementation and actual CI boot evidence pending; owner review required
**Base main:** `5f9bc9c7ed90ca09ba12dd0b40359e4a0462c6db`
**Branch:** `os-0-boot-serial-baseline`; do not merge automatically

## Delivered prototype

- Proposed ADR-0012 records the choice of i386 PC BIOS over x86_64 UEFI and
  AArch64 `virt`, with tooling/debug and portability tradeoffs.
- One real-mode boot sector creates a normal VM image and two deliberate
  fatal-path images. COM1 reports boot, READY, manual panic and actual #UD
  exception with a fixed protocol. A #DE exception handler also reports a
  fatal line. The guest halts; no Linux code is part of its boot path.
- A deterministic build produces a 1.44 MiB raw floppy, enforces boot
  signature/length/zero padding, and compares two fresh builds byte-for-byte.
- Negative protocol/artifact tests and a separate CI QEMU job require two
  actual VM boots per mode; existing Rust/architecture jobs remain required.

## Local evidence

`make os0-test`: 3 negative-test groups passed. `make os0-repro` passed twice
with identical SHA-256 across fresh builds for each variant:

| Mode | SHA-256 of 1.44 MiB image |
|---|---|
| normal | `4547b6ade1a487fb294a0e1e97c417c88803e234237d1c7427cc1fcb867689b2` |
| panic | `8c19c091b48959b7bde6c8e87dd19cd133ad89946cfad5053b87f6927e02ce3f` |
| fault | `07369fb6d877c88ba41031f1fc540b76a8ed0c9f4579c3e06a635ca13fa7bb8d` |

QEMU is unavailable in this local environment. No VM boot claim follows from
these local-only checks; the exact-head CI job must supply the real boot log.

## Actual CI and final gate

Pending exact-head push and PR CI. The PR must link successful `verify` and
`os0-boot` jobs from both events before READY FOR OWNER REVIEW. A successful
image build without actual normal/panic/fault serial observations is not a
passing OS-0 milestone. Do not merge automatically.

## Remaining limits

The sector runs in 16-bit BIOS real mode, without a real isolation boundary,
secure boot, memory allocator, scheduler or ICC integration. Emulator and
firmware may be trusted in this laboratory; there is no physical-hardware,
hostile-firmware, cross-version bit-reproducibility or production security
claim. OS-1/OS-2 require separate architecture and threat work.
