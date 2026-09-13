from fastapi import APIRouter
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta

from database.database import get_db
from security.password import hash_password, verify_password

router = APIRouter()

SECRET_KEY = "cipherchat-secret-key"
ALGORITHM = "HS256"


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register")
def register(data: RegisterRequest):

    conn = get_db()

    existing = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (data.username,)
    ).fetchone()

    if existing:
        conn.close()
        return {
            "success": False,
            "message": "Username already exists"
        }

    password_hash = hash_password(data.password)

    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (data.username, password_hash)
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "User registered successfully"
    }


@router.post("/login")
def login(data: LoginRequest):

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (data.username,)
    ).fetchone()

    if not user:
        conn.close()
        return {
            "success": False,
            "message": "Username not found"
        }

    if not verify_password(data.password, user["password_hash"]):
        conn.close()
        return {
            "success": False,
            "message": "Invalid password"
        }

    payload = {
        "username": data.username,
        "exp": datetime.utcnow() + timedelta(hours=2)
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    conn.execute(
        "INSERT INTO audit_logs (username, action) VALUES (?, ?)",
        (data.username, "LOGIN_SUCCESS")
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Login successful",
        "token": token
    }