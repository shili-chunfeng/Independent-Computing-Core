#!/usr/bin/env python3
"""Build and inspect deterministic OS-0 BIOS floppy images."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "os/os0/boot.S"
LINKER = ROOT / "os/os0/linker.ld"
IMAGE_BYTES = 1_474_560
SECTOR_BYTES = 512
VARIANTS = {"normal": 0, "panic": 1, "fault": 2}


def inspect_sector(sector: bytes) -> None:
    if len(sector) != SECTOR_BYTES or sector[-2:] != b"\x55\xaa":
        raise ValueError("expected one BIOS boot sector with a 55aa signature")


def inspect_image(image: bytes) -> None:
    if len(image) != IMAGE_BYTES:
        raise ValueError("wrong 1.44 MiB floppy image length")
    inspect_sector(image[:SECTOR_BYTES])
    if any(image[SECTOR_BYTES:]):
        raise ValueError("OS-0 has no sectors after the boot sector")


def build(output: Path) -> dict[str, bytes]:
    output.mkdir(parents=True, exist_ok=True)
    images: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="icc-os0-build-") as temporary:
        temp = Path(temporary)
        for variant, mode in VARIANTS.items():
            obj = temp / f"{variant}.o"
            sector_file = temp / f"{variant}.bin"
            subprocess.run(
                ["as", "--32", "--defsym", f"OS0_MODE={mode}", "-o", str(obj), str(SOURCE)],
                check=True,
            )
            subprocess.run(
                ["ld", "-m", "elf_i386", "-T", str(LINKER), "--oformat", "binary",
                 "-o", str(sector_file), str(obj)],
                check=True,
            )
            sector = sector_file.read_bytes()
            inspect_sector(sector)
            image = sector + bytes(IMAGE_BYTES - SECTOR_BYTES)
            inspect_image(image)
            (output / f"icc-os0-{variant}.img").write_bytes(image)
            images[variant] = image
    return images


def verify_reproducibility(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="icc-os0-repro-") as temporary:
        first = build(Path(temporary) / "first")
        second = build(Path(temporary) / "second")
        if len(set(first.values())) != len(VARIANTS):
            raise ValueError("diagnostic variants unexpectedly share the same image")
        for variant in VARIANTS:
            committed = (output / f"icc-os0-{variant}.img").read_bytes()
            inspect_image(committed)
            if committed != first[variant] or committed != second[variant]:
                raise ValueError(f"{variant} image is not byte-reproducible")
            print(f"{variant}: sha256={hashlib.sha256(committed).hexdigest()}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/os0")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    build(output)
    if args.verify:
        verify_reproducibility(output)
    else:
        print(f"OS-0 boot images: {output}")


if __name__ == "__main__":
    main()
