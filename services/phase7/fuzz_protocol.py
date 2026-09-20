"""Dependency-free byte-oriented fuzz target for the Phase 7 frame parser."""

from __future__ import annotations

import sys

from . import protocol


def fuzz_one(data: bytes) -> None:
    try:
        protocol.decode(data)
    except protocol.ProtocolError:
        pass


def main() -> None:
    fuzz_one(sys.stdin.buffer.read(protocol.MAX_FRAME + 1))


if __name__ == "__main__":
    main()
