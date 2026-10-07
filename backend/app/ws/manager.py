import logging
from dataclasses import dataclass, field
from typing import Optional

from fastapi import WebSocket

from app.config import MAX_USERS

logger = logging.getLogger(__name__)


@dataclass
class UserConnection:
    websocket: WebSocket
    user_id: str
    username: str


@dataclass
class ConnectionManager:
    """In-memory registry for the two-user chat room."""

    # user_id -> UserConnection
    _users: dict[str, UserConnection] = field(default_factory=dict)
    # websocket id() -> user_id
    _ws_to_user: dict[int, str] = field(default_factory=dict)

    @property
    def online_users(self) -> int:
        return len(self._users)

    def joined_users(self) -> list[UserConnection]:
        return list(self._users.values())

    def is_joined(self, websocket: WebSocket) -> bool:
        return id(websocket) in self._ws_to_user

    def get_user(self, websocket: WebSocket) -> Optional[UserConnection]:
        user_id = self._ws_to_user.get(id(websocket))
        if user_id is None:
            return None
        return self._users.get(user_id)

    def get_user_by_id(self, user_id: str) -> Optional[UserConnection]:
        return self._users.get(user_id)

    def room_full(self) -> bool:
        return len(self._users) >= MAX_USERS

    def add_user(
        self, websocket: WebSocket, user_id: str, username: str
    ) -> UserConnection:
        user = UserConnection(
            websocket=websocket,
            user_id=user_id,
            username=username,
        )
        self._users[user_id] = user
        self._ws_to_user[id(websocket)] = user_id
        logger.info("user registered user_id=%s username=%s", user_id, username)
        return user

    def peer_of(self, user: UserConnection) -> Optional[UserConnection]:
        for other in self._users.values():
            if other.user_id != user.user_id:
                return other
        return None

    def status_payload(self, user: UserConnection) -> dict:
        peer = self.peer_of(user)
        if peer is None:
            return {"state": "waiting", "peer": None}
        return {
            "state": "paired",
            "peer": {"username": peer.username},
        }

    async def broadcast_json(self, payload: dict) -> None:
        dead: list[WebSocket] = []
        for user in list(self._users.values()):
            try:
                await user.websocket.send_json(payload)
            except Exception:
                logger.exception("failed to send to user_id=%s", user.user_id)
                dead.append(user.websocket)
        for ws in dead:
            self.disconnect(ws)

    async def send_json(self, websocket: WebSocket, payload: dict) -> None:
        try:
            await websocket.send_json(payload)
        except Exception:
            logger.exception("failed to send on websocket")

    def disconnect(self, websocket: WebSocket) -> Optional[UserConnection]:
        """Remove connection from registry. Returns the departed user if they had joined."""
        ws_id = id(websocket)
        user_id = self._ws_to_user.pop(ws_id, None)
        if user_id is None:
            return None
        user = self._users.pop(user_id, None)
        if user:
            logger.info(
                "user disconnected user_id=%s username=%s",
                user.user_id,
                user.username,
            )
        return user

    async def close_user(self, user_id: str, reason: str = "User logged out") -> None:
        user = self._users.get(user_id)
        if not user:
            return
        ws = user.websocket
        self.disconnect(ws)
        try:
            await ws.close()
        except Exception:
            pass

        remaining = self.joined_users()
        if remaining:
            left_payload = {"v": 1, "type": "peer_left", "username": user.username}
            for u in remaining:
                await self.send_json(u.websocket, left_payload)
                status = self.status_payload(u)
                await self.send_json(
                    u.websocket,
                    {"v": 1, "type": "status", "state": status["state"], "peer": status["peer"]},
                )


manager = ConnectionManager()
