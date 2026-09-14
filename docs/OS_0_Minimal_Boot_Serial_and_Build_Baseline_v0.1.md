# OS-0 — Minimal Boot, Serial and Build Baseline v0.1

**Status:** Proposed for owner review
**Base main:** `5f9bc9c7ed90ca09ba12dd0b40359e4a0462c6db`
**Target:** i386 PC BIOS bootstrap in QEMU TCG; no Rust/Core dependency

## Build and boot

From the repository root on a host with GNU `as`, `ld`, Python 3 and QEMU
`qemu-system-i386`:

```sh
make os0-test
make os0-repro
make os0-smoke
```

`make os0-repro` assembles and links three independent diagnostic variants,
checks each 512-byte sector and BIOS signature `55 aa`, pads to 1,474,560
bytes, then compares each image with two fresh builds. Its primary output is
`build/os0/icc-os0-normal.img`. The `panic` and `fault` images are test
fixtures and are not committed. `make os0-smoke` boots each image twice under
QEMU with `-machine pc,accel=tcg`, a read-only raw floppy, no graphical display
or monitor, and COM1 connected to host stdio. The guest halts deliberately;
the smoke runner bounds each boot to five seconds, stops the VM and insists on
exact diagnostics in the expected order. It fails if QEMU exits unexpectedly,
reports an error or silently fails to emit the required line.

## Execution path and diagnostic protocol

1. BIOS loads the boot sector at physical `0000:7c00`. The entry clears
   interrupts and direction flag, sets real-mode data/stack segments and an
   isolated stack, installs fatal #DE (vector 0) and #UD (vector 6) handlers.
2. COM1 16550-compatible UART is initialized for 115200 8N1, polling the
   transmit-ready bit without enabling interrupts. This stage needs no Linux,
   filesystem, network, heap, clocks or ICC secret.
3. Each mode emits `ICC OS0 BOOT\r\n`. Normal emits `ICC OS0 READY\r\n`;
   the manual panic variant emits `ICC OS0 PANIC MANUAL\r\n` and the CPU `ud2`
   variant reaches the IVT handler and emits `ICC OS0 FAULT UD\r\n`.
4. Fatal and normal paths disable interrupts and halt. The unexpected #DE
   handler reports `ICC OS0 FAULT DE\r\n`; no handler returns to a corrupt
   context. There is no interactive debug shell or hidden success fallback.

The image and its UART output are deterministic test artifacts, not authority
or persistence formats. Host-side negative tests reject truncated/bad-signature
images, nonzero extra sectors, missing/out-of-order/duplicate UART lines. The
CI job builds twice and boots the VM twice per mode; static image inspection
alone cannot satisfy this milestone.

## Boundaries

No protected/long mode, memory manager, allocator, scheduler, process, driver
framework, storage/filesystem, network, GUI, package loader or ICC platform
adapter is present. Firmware, BIOS load, COM1 emulation and the host QEMU
binary are trusted for this early laboratory test; no secure/measured boot,
malicious-firmware resistance, dedicated hardware or user isolation is
claimed. Assembly is isolated in this OS-specific directory and reviewed
under proposed ADR-0012. Future OS-1/OS-2 work must define additional kernel
TCB threats and avoid accidentally treating a BIOS diagnostic as a stable ABI.
