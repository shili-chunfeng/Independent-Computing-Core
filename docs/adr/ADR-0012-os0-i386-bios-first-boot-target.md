# ADR-0012 — i386 PC BIOS as the First OS-0 Boot Target

**Status:** Proposed (OS-0; owner review required)
**Date:** 2026-09-14

## Context and alternatives

The execution contract requires a real VM boot, deterministic serial
observations, a fault/panic path and a CI-built image before the Linux service
runtime proceeds. The first architecture must be chosen for available tools,
debuggability and future portability, rather than silently becoming the final
hardware architecture.

| Candidate | OS-0 tooling and diagnostic tradeoff |
|---|---|
| i386 PC BIOS | GNU `as`/`ld` already build a 512-byte real-mode sector locally; QEMU `pc` accepts a raw floppy and exposes COM1 on host stdio. The 16-bit entry, IVT and polled 16550 UART fit the OS-0 boundary. Legacy BIOS is not a modern secure-boot path. |
| x86_64 UEFI | Promising long-mode destination but requires UEFI firmware and a PE/COFF loader or bootloader before the very first serial byte; more tool and firmware provenance must be reviewed. |
| AArch64 `virt` | A useful future portability port with a simple machine model, but requires an additional cross-assembler and board-specific UART entry. Starting here does not immediately exercise the already available PC assembler/debug path. |

## Decision proposed

Start Track B on the **i386 PC BIOS bootstrap architecture** using QEMU TCG.
This is a 16-bit real-mode execution target, not a claim that the OS has
entered x86_64 long mode. Keep all instruction-set, IVT, serial-register and
BIOS image code under `os/os0/`, with no dependency from ICC Domain Core or
Ports to this target. A single sector at physical `0000:7c00` initializes
COM1, reports a fixed boot message, installs real-mode handlers for divide and
invalid-opcode faults, then reports READY or a tested fatal diagnostic and
halts. Three images share one source, differing only by an assembler-defined
boot diagnostic mode. The primary `normal` image is a 1.44 MiB raw floppy.

Build with `as --32` and `ld -m elf_i386`, verify the boot signature, pad
unwritten sectors with zero, and compare separate builds byte-for-byte. Run
normal, deliberate panic and actual `ud2` CPU fault variants twice in QEMU;
read only strict COM1 transcripts and treat missing/extra/out-of-order output
as failure. The [GNU assembler `.code16` documentation](https://sourceware.org/binutils/docs/as/i386_002d16bit.html)
describes 16-bit instruction emission. The [QEMU system invocation reference](https://www.qemu.org/docs/master/system/invocation.html)
documents `-drive`, raw format, `-display none` and `-serial stdio` used by the
smoke test. The runner installs QEMU explicitly and prints its version;
image construction itself uses no network or QEMU runtime.

## Consequences and limits

This choice gives a small, observable non-Linux boot path now and leaves a
separate OS-1 decision for memory mode, kernel language/runtime and timer.
BIOS firmware is trusted by this lab and is not measured or verified. Nothing
here proves secure boot, kernel/user isolation, 32/64-bit transition,
hardware portability, physical-machine support, protected debug transport or
integration with ICC secrets. No boot image is a production trust root.
Reproducibility is demonstrated within a specified CI runner/toolchain and by
its recorded tool versions; bit-identical output across arbitrary compiler
versions or machines is not claimed. A later architecture port should re-use
the diagnostic contract, not copy the PC firmware or COM1 dependency into ICC.
