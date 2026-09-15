"""Malformed input, caller binding, transfer, backpressure and live Linux tests."""

from __future__ import annotations

import errno
import os
from pathlib import Path
import random
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from . import protocol as p
from .fuzz_protocol import fuzz_one
from .linux import LinuxService, _read_exact
from .runtime import DELEGATE, READ, WRITE, Peer, Runtime

APP_A = b"a" * 16
APP_B = b"b" * 16
RESOURCE = b"r" * 16


def frame(conn: socket.socket, code: int, request_id: int, payload: bytes = b"") -> p.Frame:
    conn.sendall(p.encode(p.Frame(code, request_id, payload)))
    head = _read_exact(conn, p.HEADER.size)
    _, length, _ = p.header(head, response=True)
    return p.decode(head + _read_exact(conn, length), response=True)


class ProtocolTests(unittest.TestCase):
    def test_rejects_malformed_and_oversized_before_payload_allocation(self) -> None:
        good = p.encode(p.Frame(p.PING, 1))
        for bad in (
            b"",
            good[:-1],
            b"BAD!" + good[4:],
            good[:4] + b"\x02" + good[5:],
            good[:5] + b"\xff" + good[6:],
            good[:6] + b"\x00\x01" + good[8:],
            good[:8] + struct.pack("!I", p.MAX_PAYLOAD + 1) + good[12:],
            good[:12] + bytes(8),
            good + b"trailing",
            p.encode(p.Frame(p.WRITE, 4, b"data"))[:-1],
        ):
            with self.subTest(bad=bad[:20]), self.assertRaises(p.ProtocolError):
                p.decode(bad)

    def test_deterministic_fuzz_corpus_never_crashes_decoder(self) -> None:
        rng = random.Random(11)
        for _ in range(10_000):
            data = rng.randbytes(rng.randrange(0, p.MAX_FRAME + 30))
            try:
                fuzz_one(data)
            except Exception as error:  # pragma: no cover - reports target escapes
                self.fail(f"fuzz target escaped on {data[:20]!r}: {error}")


class RuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1.0
        self.runtime = Runtime(
            {100: APP_A, 101: APP_B},
            {APP_A: {RESOURCE: READ | WRITE | DELEGATE}, APP_B: {RESOURCE: READ}},
            {RESOURCE: b"initial"},
            admin_uid=900,
            clock=lambda: self.now,
        )
        self.a = self.runtime.connect(Peer(1001, 100, 100))
        self.b = self.runtime.connect(Peer(1002, 101, 101))
        self.assertIsNotNone(self.a)
        self.assertIsNotNone(self.b)

    def call(self, session: bytes, op: int, payload: bytes = b"") -> p.Frame:
        return self.runtime.request(session, p.Frame(op, 1, payload))

    def test_caller_spoofing_endpoint_denial_and_session_binding(self) -> None:
        self.assertIsNone(self.runtime.connect(Peer(1003, 999, 999)))
        self.assertEqual(self.call(self.a, p.STATUS).code, p.DENIED)
        self.assertEqual(self.call(self.b, p.OPEN, RESOURCE + bytes([WRITE])).code, p.DENIED)
        handle = self.call(self.a, p.OPEN, RESOURCE + bytes([READ | WRITE])).payload
        self.assertEqual(len(handle), 16)
        self.assertEqual(self.call(self.b, p.READ, handle).code, p.DENIED)
        self.assertEqual(self.call(self.a, p.READ, handle + APP_B).code, p.BAD_REQUEST)
        self.assertEqual(self.call(self.a, p.WRITE, handle + b"safe").code, p.OK)
        self.assertEqual(self.call(self.a, p.READ, handle).payload, b"safe")
        self.assertEqual(self.call(self.a, p.CLOSE, handle).code, p.OK)
        self.assertEqual(self.call(self.a, p.READ, handle).code, p.DENIED)

    def test_recipient_bound_one_use_transfer_and_restart(self) -> None:
        parent = self.call(self.a, p.OPEN, RESOURCE + bytes([READ | DELEGATE])).payload
        self.assertEqual(self.call(self.a, p.TRANSFER, parent + APP_B + bytes([WRITE])).code, p.DENIED)
        offer = self.call(self.a, p.TRANSFER, parent + APP_B + bytes([READ])).payload
        self.assertEqual(self.call(self.a, p.ACCEPT, offer).code, p.DENIED)
        child = self.call(self.b, p.ACCEPT, offer).payload
        self.assertEqual(len(child), 16)
        self.assertEqual(self.call(self.b, p.ACCEPT, offer).code, p.DENIED)
        self.assertEqual(self.call(self.b, p.READ, child).payload, b"initial")
        self.assertEqual(self.call(self.b, p.WRITE, child + b"bad").code, p.DENIED)
        # TRANSFER is explicitly an attenuated copy; the sender retains its
        # parent authority until it chooses CLOSE.
        self.assertEqual(self.call(self.a, p.READ, parent).payload, b"initial")
        self.runtime.disconnect(self.a)
        self.assertEqual(self.call(self.b, p.READ, parent).code, p.DENIED)
        self.runtime.disconnect(self.b)
        next_runtime = Runtime({101: APP_B}, {APP_B: {RESOURCE: READ}}, {RESOURCE: b"initial"}, admin_uid=900)
        fresh = next_runtime.connect(Peer(1002, 101, 101))
        self.assertEqual(next_runtime.request(fresh, p.Frame(p.READ, 1, child)).code, p.DENIED)

    def test_offer_expires_source_disappears_and_capacity(self) -> None:
        parent = self.call(self.a, p.OPEN, RESOURCE + bytes([READ | DELEGATE])).payload
        offer = self.call(self.a, p.TRANSFER, parent + APP_B + bytes([READ])).payload
        self.now = 62.0
        self.assertEqual(self.call(self.b, p.ACCEPT, offer).code, p.DENIED)
        offer = self.call(self.a, p.TRANSFER, parent + APP_B + bytes([READ])).payload
        self.runtime.disconnect(self.a)
        self.assertEqual(self.call(self.b, p.ACCEPT, offer).code, p.DENIED)
        for _ in range(8):
            self.assertEqual(self.call(self.b, p.OPEN, RESOURCE + bytes([READ])).code, p.OK)
        self.assertEqual(self.call(self.b, p.OPEN, RESOURCE + bytes([READ])).code, p.CAPACITY)

    def test_admin_endpoint_and_closed_parent_offer(self) -> None:
        admin = Runtime({900: APP_A}, {}, {RESOURCE: b"x"}, admin_uid=900)
        session = admin.connect(Peer(9001, 900, 900))
        self.assertEqual(admin.request(session, p.Frame(p.STATUS, 1)).payload, struct.pack("!HH", 1, 0))
        parent = self.call(self.a, p.OPEN, RESOURCE + bytes([READ | DELEGATE])).payload
        offer = self.call(self.a, p.TRANSFER, parent + APP_B + bytes([READ])).payload
        self.assertEqual(self.call(self.a, p.CLOSE, parent).code, p.OK)
        self.assertEqual(self.call(self.b, p.ACCEPT, offer).code, p.DENIED)

    def test_expired_offers_are_reclaimed_and_entropy_fails_closed(self) -> None:
        parent = self.call(
            self.a,
            p.OPEN,
            RESOURCE + bytes([READ | DELEGATE]),
        ).payload
        for _ in range(16):
            self.assertEqual(
                self.call(
                    self.a,
                    p.TRANSFER,
                    parent + APP_B + bytes([READ]),
                ).code,
                p.OK,
            )
        self.assertEqual(
            self.call(
                self.a,
                p.TRANSFER,
                parent + APP_B + bytes([READ]),
            ).code,
            p.CAPACITY,
        )
        self.now = 62.0
        self.assertEqual(
            self.call(
                self.a,
                p.TRANSFER,
                parent + APP_B + bytes([READ]),
            ).code,
            p.OK,
        )
        with patch(
            "services.phase7.runtime.secrets.token_bytes",
            return_value=bytes(16),
        ):
            self.assertEqual(
                self.call(self.a, p.OPEN, RESOURCE + bytes([READ])).code,
                p.UNAVAILABLE,
            )


class LinuxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM):
                pass
        except OSError as error:
            if error.errno == errno.EPERM and os.environ.get("ICC_REQUIRE_UNIX_SOCKET") != "1":
                raise unittest.SkipTest("local sandbox denies Unix socket creation; CI must require it") from error
            raise

    def test_live_peer_credentials_and_queue_exhaustion(self) -> None:
        uid = os.getuid()
        runtime = Runtime(
            {uid: APP_A},
            {APP_A: {RESOURCE: READ}},
            {RESOURCE: b"ok"},
            admin_uid=uid + 1,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "service.sock"
            service = LinuxService(path, runtime, max_connections=1)
            ready = threading.Event()
            worker = threading.Thread(target=service.serve, kwargs={"ready": ready})
            worker.start()
            try:
                self.assertTrue(ready.wait(2))
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as first:
                    first.connect(str(path))
                    first.settimeout(2)
                    self.assertEqual(frame(first, p.PING, 1).payload, b"PONG")
                    self.assertEqual(frame(first, p.STATUS, 2).code, p.DENIED)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as second:
                        second.connect(str(path))
                        second.settimeout(2)
                        self.assertEqual(
                            p.decode(second.recv(p.MAX_FRAME), response=True).code,
                            p.BUSY,
                        )
                    first.sendall(p.HEADER.pack(p.MAGIC, p.VERSION, p.READ, 0, p.MAX_PAYLOAD + 1, 3))
                    self.assertEqual(
                        p.decode(first.recv(p.MAX_FRAME), response=True).code,
                        p.BAD_REQUEST,
                    )
            finally:
                service.stop()
                worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertFalse(path.exists())

    def test_separate_process_restart_drops_local_handles(self) -> None:
        uid = os.getuid()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "service.sock"

            def launch() -> subprocess.Popen[bytes]:
                proc = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "services.phase7.linux",
                        "--socket",
                        str(path),
                        "--peer-uid",
                        str(uid),
                        "--admin-uid",
                        str(uid + 1),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                for _ in range(100):
                    if path.exists():
                        return proc
                    if proc.poll() is not None:
                        _, error = proc.communicate()
                        raise AssertionError(f"service exited: {error!r}")
                    time.sleep(0.02)
                proc.terminate()
                _, error = proc.communicate(timeout=3)
                raise AssertionError(f"service did not create socket: {error!r}")

            process = launch()
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                    conn.connect(str(path))
                    conn.settimeout(2)
                    self.assertEqual(frame(conn, p.PING, 1).payload, b"PONG")
                    old = frame(conn, p.OPEN, 2, b"\x02" * 16 + bytes([READ])).payload
                    self.assertEqual(frame(conn, p.READ, 3, old).payload, b"lab")
                process.terminate()
                _, error = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, error)
                self.assertFalse(path.exists())
                process = launch()
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                    conn.connect(str(path))
                    conn.settimeout(2)
                    self.assertEqual(frame(conn, p.READ, 1, old).code, p.DENIED)
            finally:
                if process.poll() is None:
                    process.terminate()
                _, error = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, error)
                if path.exists():
                    path.unlink()
