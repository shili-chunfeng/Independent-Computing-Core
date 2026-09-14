#!/usr/bin/env python3
"""Observe real VM serial diagnostics from each OS-0 boot image."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import subprocess

from build import VARIANTS, inspect_image

BOOT = b"ICC OS0 BOOT\r\n"
EXPECTED = {
    "normal": b"ICC OS0 READY\r\n",
    "panic": b"ICC OS0 PANIC MANUAL\r\n",
    "fault": b"ICC OS0 FAULT UD\r\n",
}
TIMEOUT_SECONDS = 5


def check_trace(raw: bytes, variant: str) -> None:
    expected = BOOT + EXPECTED[variant]
    if raw != expected:
        raise ValueError(f"{variant}: unexpected UART transcript {raw!r}; expected {expected!r}")


def boot_once(image: Path) -> bytes:
    cmd = [
        "qemu-system-i386", "-machine", "pc,accel=tcg", "-m", "32M",
        "-drive", f"file={image},if=floppy,format=raw,readonly=on", "-boot", "a",
        "-display", "none", "-monitor", "none", "-serial", "stdio",
        "-no-reboot", "-no-shutdown",
    ]
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
    )
    try:
        stdout, stderr = process.communicate(timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        if stderr:
            raise RuntimeError(f"QEMU reported a boot error: {stderr.decode(errors='replace')}")
        return stdout
    raise RuntimeError(
        f"QEMU unexpectedly exited ({process.returncode}): {stdout!r} {stderr!r}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", type=Path, required=True)
    args = parser.parse_args()
    images = args.images.resolve()
    for variant in VARIANTS:
        image = images / f"icc-os0-{variant}.img"
        inspect_image(image.read_bytes())
        first = boot_once(image)
        second = boot_once(image)
        check_trace(first, variant)
        check_trace(second, variant)
        print(f"{variant}: {first!r} (two VM boots)")


if __name__ == "__main__":
    main()
