import logging
from dataclasses import dataclass, field
from typing import Optional
from uuid import uuid4

from fastapi import WebSocket

from app.config import MAX_USERS

logger = logging.getLogger(__name__)


@dataclass
class UserConnection:
    websocket: WebSocket
    user_id: str
    display_name: str


@dataclass
class ConnectionManager:
    """In-memory registry for the two-user chat room."""

    _users: dict[str, UserConnection] = field(default_factory=dict)
    # websocket id() -> user_id once joined
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

    def name_taken(self, display_name: str) -> bool:
        key = display_name.casefold()
        return any(u.display_name.casefold() == key for u in self._users.values())

    def room_full(self) -> bool:
        return len(self._users) >= MAX_USERS

    async def join(
        self, websocket: WebSocket, display_name: str
    ) -> tuple[Optional[UserConnection], Optional[str]]:
        """
        Register a joined user.
        Returns (user, error_code) where error_code is ROOM_FULL or NAME_TAKEN.
        """
        if self.room_full():
            return None, "ROOM_FULL"
        if self.name_taken(display_name):
            return None, "NAME_TAKEN"

        user = UserConnection(
            websocket=websocket,
            user_id=str(uuid4()),
            display_name=display_name,
        )
        self._users[user.user_id] = user
        self._ws_to_user[id(websocket)] = user.user_id
        logger.info("user joined user_id=%s name=%s", user.user_id, display_name)
        return user, None

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
            "peer": {"display_name": peer.display_name},
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
                "user disconnected user_id=%s name=%s",
                user.user_id,
                user.display_name,
            )
        return user


manager = ConnectionManager()
