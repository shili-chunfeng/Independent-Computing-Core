"""Transport-independent, bounded ICC service frame v1.

All integers are unsigned network byte order. Wire names are never authority.
The parser never attempts to allocate the advertised payload length until the
fixed header has been validated against the protocol limit.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

MAGIC = b"ICC7"
VERSION = 1
MAX_PAYLOAD = 4096
HEADER = struct.Struct("!4sBBHIQ")  # magic, version, operation/status, flags, size, request ID
MAX_FRAME = HEADER.size + MAX_PAYLOAD

PING = 1
STATUS = 2
OPEN = 3
READ = 4
WRITE = 5
CLOSE = 6
TRANSFER = 7
ACCEPT = 8

OK = 0
BAD_REQUEST = 1
DENIED = 2
BUSY = 3
UNAVAILABLE = 4
NOT_FOUND = 5
CAPACITY = 6

REQUEST_OPS = frozenset({PING, STATUS, OPEN, READ, WRITE, CLOSE, TRANSFER, ACCEPT})
RESPONSE_CODES = frozenset({OK, BAD_REQUEST, DENIED, BUSY, UNAVAILABLE, NOT_FOUND, CAPACITY})


class ProtocolError(ValueError):
    """Untrusted bytes violate the framing contract."""


@dataclass(frozen=True)
class Frame:
    code: int
    request_id: int
    payload: bytes = b""


def header(data: bytes, *, response: bool = False) -> tuple[int, int, int]:
    if len(data) != HEADER.size:
        raise ProtocolError("header length")
    magic, version, code, flags, length, request_id = HEADER.unpack(data)
    if (
        magic != MAGIC
        or version != VERSION
        or flags != 0
        or length > MAX_PAYLOAD
        or request_id == 0
        or code not in (RESPONSE_CODES if response else REQUEST_OPS)
    ):
        raise ProtocolError("header fields")
    return code, length, request_id


def decode(data: bytes, *, response: bool = False) -> Frame:
    code, length, request_id = header(data[: HEADER.size], response=response)
    if len(data) != HEADER.size + length:
        raise ProtocolError("frame length")
    return Frame(code, request_id, data[HEADER.size :])


def encode(frame: Frame, *, response: bool = False) -> bytes:
    payload = bytes(frame.payload)
    if (
        frame.request_id <= 0
        or frame.request_id >= 2**64
        or len(payload) > MAX_PAYLOAD
        or frame.code not in (RESPONSE_CODES if response else REQUEST_OPS)
    ):
        raise ProtocolError("invalid outgoing frame")
    return HEADER.pack(MAGIC, VERSION, frame.code, 0, len(payload), frame.request_id) + payload
