"""Service-owned endpoint authority, separate from framing and Linux I/O.

This volatile sample resource is deliberately not a Vault/KeyStore backend.
An opaque handle on the wire is only a reference into one live, peer-bound
session. Transferring authority uses a recipient-bound, one-use offer; sending
a local handle to another connection never transfers any rights.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import secrets
import struct
import threading
import time
from typing import Callable

from . import protocol as p

READ = 1
WRITE = 2
DELEGATE = 4
KNOWN_RIGHTS = READ | WRITE | DELEGATE
MAX_HANDLES = 8
MAX_OFFERS = 16
MAX_VALUE = 1024
OFFER_LIFETIME = 60


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int


@dataclass(frozen=True)
class Grant:
    resource: bytes
    rights: int


@dataclass
class Session:
    peer: Peer
    app: bytes
    handles: dict[bytes, Grant] = field(default_factory=dict)


@dataclass(frozen=True)
class Offer:
    source: bytes
    parent: bytes
    recipient: bytes
    rights: int
    expiry: float


class Runtime:
    """Trusted composition for one service, using pre-provisioned UID policy.

    Each UID maps to exactly one App in this prototype; different Apps must
    run under different UIDs. Linux root/host kernel and same-UID attackers are
    outside this prototype's isolation claim. No request can set its own App.
    """

    def __init__(
        self,
        principals: dict[int, bytes],
        grants: dict[bytes, dict[bytes, int]],
        resources: dict[bytes, bytes],
        *,
        admin_uid: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            any(uid < 0 or len(app) != 16 or app == bytes(16) for uid, app in principals.items())
            or len(set(principals.values())) != len(principals)
            or admin_uid < 0
            or any(len(r) != 16 or r == bytes(16) or len(v) > MAX_VALUE for r, v in resources.items())
            or any(
                app not in principals.values()
                or any(r not in resources or rights <= 0 or rights & ~KNOWN_RIGHTS for r, rights in allowed.items())
                for app, allowed in grants.items()
            )
        ):
            raise ValueError("invalid trusted service configuration")
        self._principals = dict(principals)
        self._grants = {app: dict(allowed) for app, allowed in grants.items()}
        self._resources = dict(resources)
        self._admin_uid = admin_uid
        self._clock = clock
        self._sessions: dict[bytes, Session] = {}
        self._offers: dict[bytes, Offer] = {}
        self._lock = threading.Lock()

    def connect(self, peer: Peer) -> bytes | None:
        app = self._principals.get(peer.uid)
        if app is None or peer.pid <= 0 or peer.gid < 0:
            return None
        with self._lock:
            session = self._fresh(self._sessions)
            self._sessions[session] = Session(peer, app)
            return session

    def disconnect(self, session: bytes) -> None:
        with self._lock:
            self._sessions.pop(session, None)
            self._offers = {key: offer for key, offer in self._offers.items() if offer.source != session}

    @staticmethod
    def _fresh(entries: dict[bytes, object]) -> bytes:
        for _ in range(8):
            name = secrets.token_bytes(16)
            if name != bytes(16) and name not in entries:
                return name
        raise RuntimeError("random identifier unavailable")

    def _allowed(self, entry: Session, grant: Grant, rights: int) -> bool:
        return (
            rights > 0
            and not rights & ~KNOWN_RIGHTS
            and grant.rights & rights == rights
            and self._grants.get(entry.app, {}).get(grant.resource, 0) & rights == rights
        )

    def request(self, session: bytes, frame: p.Frame) -> p.Frame:
        with self._lock:
            entry = self._sessions.get(session)
            if entry is None:
                return p.Frame(p.UNAVAILABLE, frame.request_id)
            try:
                return self._execute(session, entry, frame)
            except (ValueError, struct.error):
                return p.Frame(p.BAD_REQUEST, frame.request_id)
            except RuntimeError:
                return p.Frame(p.UNAVAILABLE, frame.request_id)

    def _execute(self, session: bytes, entry: Session, frame: p.Frame) -> p.Frame:
        op, data, rid = frame.code, frame.payload, frame.request_id
        if op == p.PING and not data:
            return p.Frame(p.OK, rid, b"PONG")
        if op == p.STATUS and not data:
            if entry.peer.uid != self._admin_uid:
                return p.Frame(p.DENIED, rid)
            self._discard_expired_offers()
            return p.Frame(
                p.OK,
                rid,
                struct.pack("!HH", len(self._sessions), len(self._offers)),
            )
        if op == p.OPEN:
            if len(data) != 17 or not data[16] or data[16] & ~KNOWN_RIGHTS:
                raise ValueError("open")
            resource, rights = data[:16], data[16]
            if self._grants.get(entry.app, {}).get(resource, 0) & rights != rights:
                return p.Frame(p.DENIED, rid)
            if len(entry.handles) >= MAX_HANDLES:
                return p.Frame(p.CAPACITY, rid)
            handle = self._fresh(entry.handles)
            entry.handles[handle] = Grant(resource, rights)
            return p.Frame(p.OK, rid, handle)
        if op == p.CLOSE:
            if len(data) != 16:
                raise ValueError("close")
            if entry.handles.pop(data, None) is None:
                return p.Frame(p.DENIED, rid)
            return p.Frame(p.OK, rid)
        if op in (p.READ, p.WRITE):
            if len(data) < 16 or (op == p.READ and len(data) != 16):
                raise ValueError("access")
            grant = entry.handles.get(data[:16])
            required = READ if op == p.READ else WRITE
            if grant is None or not self._allowed(entry, grant, required):
                return p.Frame(p.DENIED, rid)
            if op == p.READ:
                return p.Frame(p.OK, rid, self._resources[grant.resource])
            value = data[16:]
            if len(value) > MAX_VALUE:
                return p.Frame(p.CAPACITY, rid)
            self._resources[grant.resource] = value
            return p.Frame(p.OK, rid)
        if op == p.TRANSFER:
            if len(data) != 33 or not data[-1] or data[-1] & ~KNOWN_RIGHTS:
                raise ValueError("transfer")
            parent, recipient, rights = data[:16], data[16:32], data[32]
            grant = entry.handles.get(parent)
            if (
                grant is None
                or recipient not in self._principals.values()
                or not self._allowed(entry, grant, DELEGATE | rights)
                or self._grants.get(recipient, {}).get(grant.resource, 0) & rights != rights
            ):
                return p.Frame(p.DENIED, rid)
            now = self._clock()
            self._discard_expired_offers(now)
            if len(self._offers) >= MAX_OFFERS:
                return p.Frame(p.CAPACITY, rid)
            offer_id = self._fresh(self._offers)
            self._offers[offer_id] = Offer(
                session,
                parent,
                recipient,
                rights,
                now + OFFER_LIFETIME,
            )
            return p.Frame(p.OK, rid, offer_id)
        if op == p.ACCEPT:
            if len(data) != 16:
                raise ValueError("accept")
            offer = self._offers.get(data)
            if offer is None or offer.recipient != entry.app:
                return p.Frame(p.DENIED, rid)
            # One-use even on expiry or failed source authorization.
            del self._offers[data]
            source = self._sessions.get(offer.source)
            parent = source.handles.get(offer.parent) if source else None
            if (
                self._clock() >= offer.expiry
                or source is None
                or parent is None
                or not self._allowed(source, parent, DELEGATE | offer.rights)
                or self._grants.get(entry.app, {}).get(parent.resource, 0) & offer.rights != offer.rights
            ):
                return p.Frame(p.DENIED, rid)
            if len(entry.handles) >= MAX_HANDLES:
                return p.Frame(p.CAPACITY, rid)
            handle = self._fresh(entry.handles)
            entry.handles[handle] = Grant(parent.resource, offer.rights)
            return p.Frame(p.OK, rid, handle)
        raise ValueError("unknown operation or payload")

    def _discard_expired_offers(self, now: float | None = None) -> None:
        current = self._clock() if now is None else now
        self._offers = {
            key: offer for key, offer in self._offers.items() if current < offer.expiry
        }
