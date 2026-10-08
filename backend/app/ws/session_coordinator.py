import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional

from app.crypto.dh import validate_public
from app.db import base
from app.db.models import ChatSession, utc_now
from app.services.audit import log_event
from app.ws.manager import UserConnection, manager

logger = logging.getLogger(__name__)

HANDSHAKE_TIMEOUT_SECONDS = 15


class SessionCoordinator:
    def __init__(self):
        self._lock = asyncio.Lock()
        self.active_session_id: Optional[str] = None
        self.initiator: Optional[UserConnection] = None
        self.responder: Optional[UserConnection] = None
        self.status: str = "none"  # "none" | "negotiating" | "established" | "terminated"
        self.started_at: Optional[datetime] = None
        self.established_at: Optional[datetime] = None
        self.pub_a: Optional[str] = None
        self.pub_b: Optional[str] = None
        self.fingerprint_a: Optional[str] = None
        self.fingerprint_b: Optional[str] = None
        self.timings_a: Optional[Dict[str, Any]] = None
        self.timings_b: Optional[Dict[str, Any]] = None
        self._timeout_task: Optional[asyncio.Task] = None

    def is_established(self) -> bool:
        return self.status == "established"

    async def on_user_joined(self, new_user: UserConnection) -> None:
        """
        Called when an authenticated user connects.
        If alone: send status waiting & audit SESSION_WAITING.
        If second user connects and no active session: start negotiating session.
        """
        async with self._lock:
            joined = manager.joined_users()
            if len(joined) == 1:
                log_event(
                    "SESSION_WAITING",
                    severity="info",
                    user_id=int(new_user.user_id),
                    username_attempted=new_user.username,
                    details={"state": "waiting_for_peer"},
                )
                return

            if len(joined) == 2 and self.status in ("none", "terminated"):
                # Identify initiator (the earlier connected user) and responder
                earlier = [u for u in joined if u.user_id != new_user.user_id][0]
                await self._start_session_locked(initiator=earlier, responder=new_user)

    async def request_session(self, requester: UserConnection) -> None:
        """
        Triggered when a user sends request_session.
        If two users are connected and no active session is negotiating/established, start one.
        """
        async with self._lock:
            joined = manager.joined_users()
            if len(joined) == 2 and self.status in ("none", "terminated"):
                # Arbitrary role assignment: requester is initiator, peer is responder
                peer = [u for u in joined if u.user_id != requester.user_id][0]
                await self._start_session_locked(initiator=requester, responder=peer)

    async def _start_session_locked(
        self, initiator: UserConnection, responder: UserConnection
    ) -> None:
        from uuid import uuid4

        session_id = str(uuid4())
        self.active_session_id = session_id
        self.initiator = initiator
        self.responder = responder
        self.status = "negotiating"
        self.started_at = utc_now()
        self.established_at = None
        self.pub_a = None
        self.pub_b = None
        self.fingerprint_a = None
        self.fingerprint_b = None
        self.timings_a = None
        self.timings_b = None

        if self._timeout_task and not self._timeout_task.done():
            self._timeout_task.cancel()

        # Insert DB record
        with base.SessionLocal() as db:
            db_session = ChatSession(
                id=session_id,
                user_a_id=int(initiator.user_id),
                user_b_id=int(responder.user_id),
                status="negotiating",
                started_at=self.started_at,
            )
            db.add(db_session)
            db.commit()

        log_event(
            "SESSION_STARTED",
            severity="info",
            session_id=session_id,
            details={
                "initiator": initiator.username,
                "responder": responder.username,
            },
        )

        dh_info = {"group": "modp2048-rfc3526-14", "g": 2}

        # Send session_start to initiator
        await manager.send_json(
            initiator.websocket,
            {
                "v": 1,
                "type": "session_start",
                "session_id": session_id,
                "role": "initiator",
                "peer": {"user_id": responder.user_id, "username": responder.username},
                "dh": dh_info,
            },
        )

        # Send session_start to responder
        await manager.send_json(
            responder.websocket,
            {
                "v": 1,
                "type": "session_start",
                "session_id": session_id,
                "role": "responder",
                "peer": {"user_id": initiator.user_id, "username": initiator.username},
                "dh": dh_info,
            },
        )

        # Spawn timeout task
        self._timeout_task = asyncio.create_task(
            self._handshake_timeout_watcher(session_id)
        )

    async def _handshake_timeout_watcher(self, session_id: str) -> None:
        try:
            await asyncio.sleep(HANDSHAKE_TIMEOUT_SECONDS)
            async with self._lock:
                if self.active_session_id == session_id and self.status == "negotiating":
                    log_event(
                        "KEY_EXCHANGE_FAILED",
                        severity="alert",
                        session_id=session_id,
                        details={"reason": "handshake_timeout"},
                    )
                    await self._terminate_locked(session_id, "handshake_timeout")
        except asyncio.CancelledError:
            pass

    async def handle_dh_public(
        self, user: UserConnection, data: Dict[str, Any]
    ) -> bool:
        session_id = data.get("session_id")
        pub_hex = data.get("public")

        async with self._lock:
            if not self._validate_participant(user, session_id):
                await manager.send_json(
                    user.websocket,
                    {"v": 1, "type": "error", "code": "BAD_SESSION", "message": "Invalid session"},
                )
                return False

            if self.status != "negotiating":
                return False

            is_init = user.user_id == self.initiator.user_id
            sender_role = "initiator" if is_init else "responder"
            peer = self.responder if is_init else self.initiator

            # Check duplicate public from same side
            if (is_init and self.pub_a is not None) or (not is_init and self.pub_b is not None):
                await manager.send_json(
                    user.websocket,
                    {"v": 1, "type": "error", "code": "BAD_FRAME", "message": "Duplicate dh_public"},
                )
                return False

            # Server range validation
            ok, reason = validate_public(pub_hex)
            if not ok:
                log_event(
                    "KEY_EXCHANGE_FAILED",
                    severity="alert",
                    session_id=session_id,
                    details={"reason": "bad_public", "role": sender_role},
                )
                await self._terminate_locked(session_id, "bad_public")
                return False

            if is_init:
                self.pub_a = pub_hex
            else:
                self.pub_b = pub_hex

            # Update DB with public key
            with base.SessionLocal() as db:
                row = db.query(ChatSession).filter(ChatSession.id == session_id).first()
                if row:
                    if is_init:
                        row.pub_a = pub_hex
                    else:
                        row.pub_b = pub_hex
                    db.commit()

            # Blind relay to peer
            await manager.send_json(
                peer.websocket,
                {
                    "v": 1,
                    "type": "dh_public",
                    "session_id": session_id,
                    "from_role": sender_role,
                    "public": pub_hex,
                },
            )
            return True

    async def handle_key_confirm(
        self, user: UserConnection, data: Dict[str, Any]
    ) -> bool:
        session_id = data.get("session_id")
        tag = data.get("tag")

        async with self._lock:
            if not self._validate_participant(user, session_id):
                await manager.send_json(
                    user.websocket,
                    {"v": 1, "type": "error", "code": "BAD_SESSION", "message": "Invalid session"},
                )
                return False

            if self.status != "negotiating" or not isinstance(tag, str):
                return False

            is_init = user.user_id == self.initiator.user_id
            sender_role = "initiator" if is_init else "responder"
            peer = self.responder if is_init else self.initiator

            # Blind relay to peer
            await manager.send_json(
                peer.websocket,
                {
                    "v": 1,
                    "type": "key_confirm",
                    "session_id": session_id,
                    "from_role": sender_role,
                    "tag": tag,
                },
            )
            return True

    async def handle_key_verified(
        self, user: UserConnection, data: Dict[str, Any]
    ) -> bool:
        session_id = data.get("session_id")
        fingerprint = data.get("fingerprint")
        timings = data.get("timings") or {}

        async with self._lock:
            if not self._validate_participant(user, session_id):
                await manager.send_json(
                    user.websocket,
                    {"v": 1, "type": "error", "code": "BAD_SESSION", "message": "Invalid session"},
                )
                return False

            if self.status != "negotiating" or not isinstance(fingerprint, str):
                return False

            is_init = user.user_id == self.initiator.user_id
            if (is_init and self.fingerprint_a is not None) or (not is_init and self.fingerprint_b is not None):
                return True

            if is_init:
                self.fingerprint_a = fingerprint
                self.timings_a = timings
            else:
                self.fingerprint_b = fingerprint
                self.timings_b = timings

            # When BOTH sides have sent key_verified
            if self.fingerprint_a is not None and self.fingerprint_b is not None:
                if self._timeout_task and not self._timeout_task.done():
                    self._timeout_task.cancel()

                if self.fingerprint_a != self.fingerprint_b:
                    log_event(
                        "KEY_EXCHANGE_FAILED",
                        severity="alert",
                        session_id=session_id,
                        details={"reason": "fingerprint_mismatch"},
                    )
                    await self._terminate_locked(session_id, "fingerprint_mismatch")
                    return False

                # Established!
                self.status = "established"
                self.established_at = utc_now()
                duration_ms = (
                    (self.established_at - self.started_at).total_seconds() * 1000.0
                    if self.started_at
                    else 0.0
                )

                with base.SessionLocal() as db:
                    row = db.query(ChatSession).filter(ChatSession.id == session_id).first()
                    if row:
                        row.status = "established"
                        row.established_at = self.established_at
                        row.fingerprint_a = self.fingerprint_a
                        row.fingerprint_b = self.fingerprint_b
                        db.commit()

                log_event(
                    "KEY_EXCHANGE_OK",
                    severity="info",
                    session_id=session_id,
                    details={
                        "fingerprint": self.fingerprint_a,
                        "timings_initiator": self.timings_a,
                        "timings_responder": self.timings_b,
                        "duration_ms": duration_ms,
                    },
                )

                payload = {
                    "v": 1,
                    "type": "session_established",
                    "session_id": session_id,
                    "fingerprint": self.fingerprint_a,
                }
                await manager.send_json(self.initiator.websocket, payload)
                await manager.send_json(self.responder.websocket, payload)
                return True

            return True

    async def handle_key_failed(
        self, user: UserConnection, data: Dict[str, Any]
    ) -> None:
        session_id = data.get("session_id")
        raw_reason = data.get("reason")
        reason = "bad_public" if raw_reason == "bad_public" else "key_confirm_failed"

        async with self._lock:
            if not self._validate_participant(user, session_id):
                return
            log_event(
                "KEY_EXCHANGE_FAILED",
                severity="alert",
                session_id=session_id,
                details={"reason": reason, "reported_by": user.username},
            )
            await self._terminate_locked(session_id, reason)

    async def terminate_session(self, session_id: Optional[str], reason: str) -> None:
        """External termination trigger (e.g. logout, disconnect, superseded)."""
        async with self._lock:
            target_id = session_id or self.active_session_id
            if target_id and (target_id == self.active_session_id or self.status != "terminated"):
                await self._terminate_locked(target_id, reason)

    async def _terminate_locked(self, session_id: str, reason: str) -> None:
        """Idempotent session termination."""
        if self.status == "terminated" and self.active_session_id != session_id:
            return

        if (
            self._timeout_task
            and self._timeout_task is not asyncio.current_task()
            and not self._timeout_task.done()
        ):
            self._timeout_task.cancel()

        was_established = self.status == "established"
        ended_at = utc_now()
        duration_sec = (
            (ended_at - self.started_at).total_seconds() if self.started_at else 0.0
        )

        self.status = "terminated"
        self.active_session_id = None

        with base.SessionLocal() as db:
            row = db.query(ChatSession).filter(ChatSession.id == session_id).first()
            if row and row.status != "terminated":
                row.status = "terminated"
                row.ended_at = ended_at
                row.end_reason = reason
                db.commit()

        log_event(
            "SESSION_ENDED",
            severity="info",
            session_id=session_id,
            details={
                "reason": reason,
                "duration_seconds": duration_sec,
                "was_established": was_established,
            },
        )

        term_payload = {
            "v": 1,
            "type": "session_terminated",
            "session_id": session_id,
            "reason": reason,
        }

        # Send to all participants still connected
        for participant in (self.initiator, self.responder):
            if participant and manager.is_joined(participant.websocket):
                await manager.send_json(participant.websocket, term_payload)

    def _validate_participant(
        self, user: UserConnection, session_id: Optional[str]
    ) -> bool:
        if not session_id or session_id != self.active_session_id:
            return False
        if not self.initiator or not self.responder:
            return False
        return user.user_id in (self.initiator.user_id, self.responder.user_id)


coordinator = SessionCoordinator()

