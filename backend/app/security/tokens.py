from datetime import datetime
from typing import Any, Dict

import jwt

from app.config import get_jwt_secret

ALGORITHM = "HS256"


def create_token(
    user_id: int,
    role: str,
    jti: str,
    issued_at: datetime,
    expires_at: datetime,
) -> str:
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "role": role,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """
    Decodes and validates JWT signature and expiration.
    May raise jwt.ExpiredSignatureError, jwt.InvalidTokenError, or ValueError.
    """
    return jwt.decode(token, get_jwt_secret(), algorithms=[ALGORITHM])
