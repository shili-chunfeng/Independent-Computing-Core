# OS-0 — Boot, Serial and Build: completion evidence v0.1

**Status:** Implementation-head push CI green; report/PR HEAD verification pending
**Base main:** `5f9bc9c7ed90ca09ba12dd0b40359e4a0462c6db`
**Branch:** `os-0-boot-serial-baseline`; do not merge automatically

## Delivered prototype

- Proposed ADR-0012 records the choice of i386 PC BIOS over x86_64 UEFI and
  AArch64 `virt`, with tooling/debug and portability tradeoffs.
- The OS-0 threat delta records the BIOS/image/debug trust boundaries and
  defers kernel memory, IPC and device threats until their primitives exist.
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

The implementation-head [push run 34843871972](https://github.com/shili-chunfeng/Independent-Computing-Core/actions/runs/34843871972)
at `b9bd63144d49569f6514eb97e808ea8773bb53f5` completed **success**.
Its [OS-0 boot job 103974969182](https://github.com/shili-chunfeng/Independent-Computing-Core/actions/runs/34843871972/job/103974969182)
installed QEMU 8.2.2, rebuilt all three images to the **same local hashes**,
ran three negative-test groups and actually booted each mode **twice**. The
decoded UART lines were exactly:

| VM mode | Serial bytes from each boot |
|---|---|
| normal | `ICC OS0 BOOT\r\nICC OS0 READY\r\n` |
| panic | `ICC OS0 BOOT\r\nICC OS0 PANIC MANUAL\r\n` |
| fault | `ICC OS0 BOOT\r\nICC OS0 FAULT UD\r\n` |

The same run's [verify job 103974968857](https://github.com/shili-chunfeng/Independent-Computing-Core/actions/runs/34843871972/job/103974968857)
completed **success** for the locked workspace metadata, architecture
negative tests, Rust formatting, default/all-feature check, Clippy and tests,
bare-metal checks, cargo-deny and repeated release builds. The OS-0 threat
delta and this report are later documentation changes: their exact final push
and PR HEAD must also pass **both** jobs before READY FOR OWNER REVIEW. An
image build without normal/panic/fault VM observations is insufficient.
Do not merge automatically.

## Remaining limits

The sector runs in 16-bit BIOS real mode, without a real isolation boundary,
secure boot, memory allocator, scheduler or ICC integration. Emulator and
firmware may be trusted in this laboratory; there is no physical-hardware,
hostile-firmware, cross-version bit-reproducibility or production security
claim. OS-1/OS-2 require separate architecture and threat work.
