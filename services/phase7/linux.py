"""Linux-only SO_PEERCRED Unix-stream adapter and service composition root."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import sys
import threading

from . import protocol as p
from .runtime import Peer, Runtime

MAX_CONNECTIONS = 4
MAX_REQUESTS = 32
IO_TIMEOUT = 1.0
_CREDENTIALS = struct.Struct("3i")  # Linux struct ucred: pid, uid, gid


def peer_credentials(conn: socket.socket) -> Peer:
    if not sys.platform.startswith("linux"):
        raise OSError("SO_PEERCRED is Linux-only")
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size)
    pid, uid, gid = _CREDENTIALS.unpack(raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise OSError("invalid kernel peer credentials")
    return Peer(pid, uid, gid)


def _read_exact(conn: socket.socket, length: int) -> bytes | None:
    value = bytearray()
    while len(value) < length:
        chunk = conn.recv(length - len(value))
        if not chunk:
            if not value:
                return None
            raise p.ProtocolError("truncated frame")
        value.extend(chunk)
    return bytes(value)


def read_frame(conn: socket.socket) -> p.Frame | None:
    raw = _read_exact(conn, p.HEADER.size)
    if raw is None:
        return None
    code, length, request_id = p.header(raw)
    payload = _read_exact(conn, length) if length else b""
    if payload is None:
        raise p.ProtocolError("truncated frame")
    return p.Frame(code, request_id, payload)


class LinuxService:
    """One bounded service process; fail closed if its socket path exists."""

    def __init__(self, path: Path, runtime: Runtime, *, max_connections: int = MAX_CONNECTIONS):
        if max_connections < 1 or max_connections > 64:
            raise ValueError("connection limit")
        self.path = path
        self.runtime = runtime
        self._slots = threading.BoundedSemaphore(max_connections)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def stop(self) -> None:
        self._stop.set()

    def _connection(self, conn: socket.socket, peer: Peer) -> None:
        session: bytes | None = None
        try:
            with conn:
                conn.settimeout(IO_TIMEOUT)
                try:
                    session = self.runtime.connect(peer)
                except RuntimeError:
                    conn.sendall(p.encode(p.Frame(p.UNAVAILABLE, 1), response=True))
                    return
                if session is None:
                    conn.sendall(p.encode(p.Frame(p.DENIED, 1), response=True))
                    return
                previous = 0
                for _ in range(MAX_REQUESTS):
                    try:
                        frame = read_frame(conn)
                    except (p.ProtocolError, TimeoutError):
                        conn.sendall(p.encode(p.Frame(p.BAD_REQUEST, 1), response=True))
                        return
                    if frame is None:
                        return
                    if frame.request_id <= previous:
                        conn.sendall(p.encode(p.Frame(p.BAD_REQUEST, frame.request_id), response=True))
                        return
                    previous = frame.request_id
                    conn.sendall(p.encode(self.runtime.request(session, frame), response=True))
                if previous < 2**64 - 1:
                    conn.sendall(p.encode(p.Frame(p.CAPACITY, previous + 1), response=True))
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            pass
        finally:
            if session is not None:
                self.runtime.disconnect(session)
            self._slots.release()

    def serve(self, *, ready: threading.Event | None = None) -> None:
        parent = self.path.parent
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError("socket directory must be owned and mode 0700")
        if self.path.exists() or self.path.is_symlink():
            raise FileExistsError("refuse existing socket path")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.path))
            created_inode = self.path.stat().st_ino
            try:
                os.chmod(self.path, 0o600)
                listener.listen(MAX_CONNECTIONS)
                listener.settimeout(0.1)
                if ready is not None:
                    ready.set()
                while not self._stop.is_set():
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        continue
                    try:
                        peer = peer_credentials(conn)
                    except OSError:
                        conn.close()
                        continue
                    if not self._slots.acquire(blocking=False):
                        try:
                            conn.settimeout(IO_TIMEOUT)
                            conn.sendall(p.encode(p.Frame(p.BUSY, 1), response=True))
                        except OSError:
                            pass
                        finally:
                            conn.close()
                        continue
                    self._threads = [thread for thread in self._threads if thread.is_alive()]
                    worker = threading.Thread(
                        target=self._connection,
                        args=(conn, peer),
                        daemon=True,
                    )
                    self._threads.append(worker)
                    worker.start()
            finally:
                for worker in self._threads:
                    worker.join(timeout=IO_TIMEOUT * 2)
                # The service creates this path only after rejecting preexisting
                # entries. Do not remove a path replaced by another process.
                try:
                    if self.path.is_socket() and self.path.stat().st_ino == created_inode:
                        self.path.unlink()
                except FileNotFoundError:
                    pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 7 volatile Linux IPC laboratory service"
    )
    parser.add_argument(
        "--socket",
        type=Path,
        required=True,
        help="path under an owner-only 0700 directory",
    )
    parser.add_argument(
        "--peer-uid",
        type=int,
        required=True,
        help="trusted launcher-provisioned client UID",
    )
    parser.add_argument(
        "--admin-uid",
        type=int,
        required=True,
        help="trusted launcher-provisioned admin UID",
    )
    args = parser.parse_args()
    app = b"\x01" * 16
    resource = b"\x02" * 16
    runtime = Runtime(
        {args.peer_uid: app},
        {app: {resource: 3}},
        {resource: b"lab"},
        admin_uid=args.admin_uid,
    )
    service = LinuxService(args.socket, runtime)
    signal.signal(signal.SIGTERM, lambda _signum, _frame: service.stop())
    try:
        service.serve()
    except KeyboardInterrupt:
        service.stop()


if __name__ == "__main__":
    main()
