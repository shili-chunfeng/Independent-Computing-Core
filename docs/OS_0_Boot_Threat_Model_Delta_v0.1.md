# OS-0 — Initial Boot Threat Model Delta v0.1

**Status:** Proposed OS-0 lab boundary; review with ADR-0012

## Assets, actors and boundaries

The OS-0 image contains only fixed boot code and public diagnostic strings.
It has no ICC identity, private key, capability state, Vault data, storage
parser or App. The trusted laboratory path is the local GNU assembler/linker,
CI runner, installed QEMU, emulated PC BIOS, RAM and 16550 COM1. The image
crosses a host-file → virtual floppy → BIOS boot sector → real-mode code
boundary; serial text crosses guest COM1 → QEMU stdio → CI logs. The VM and
CI logs are not a confidentiality boundary.

| Threat | OS-0 observation and present boundary |
|---|---|
| T-OS0-001 Image replacement or malicious firmware | The 55aa signature and repeat-build hashes detect malformed artifacts and build drift; they **do not authenticate** the image or firmware. BIOS loads whatever sector it selects. Secure/measured boot and provenance policy are future work. |
| T-OS0-002 Fault, hang or silent success | QEMU must emit exact ordered BOOT/READY, BOOT/PANIC or BOOT/FAULT UD from an actual `ud2`. Missing, duplicate or unexpected output and premature VM exit fail CI. A five-second bound detects hangs in this lab, but not all CPU faults; #DE handler is installed but not independently triggered by smoke. |
| T-OS0-003 Debug/serial disclosure | COM1 only prints fixed public strings. CI checks exact bytes; no keys, IDs, request content or dynamic addresses exist in this image. Future kernel logs need redaction/authority before holding secrets. |
| T-OS0-004 Tool, firmware or emulator compromise | The first target's GNU tools and QEMU/SeaBIOS remain trusted test dependencies. Versions are printed in CI and separate builds are compared, but no third-party reproducible-build attestation or malicious-runner protection is claimed. |

The Phase 0.2 [future kernel threat checklist](phase-0.2/part-03.md)
includes kernel-object authority, address spaces, scheduler, IPC, mapping
rights, DMA, drivers, interrupt authority, boot trust, debug interface,
firmware, secure time, entropy and persistent monotonic state. OS-0 addresses
only the boot/debug observations above. The rest require explicit model
expansion when OS-1/OS-2 introduce corresponding primitives; no isolation or
secure-time guarantee can be inferred from a real-mode diagnostic sector.
