from fastapi import APIRouter
from pydantic import BaseModel
import jwt
import os
from dotenv import load_dotenv

from datetime import datetime, timedelta, timezone

from database.database import get_db
from security.password import hash_password, verify_password


load_dotenv()

router = APIRouter()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"


# Pydantic automatically validates incoming JSON data.
class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str

class LogoutRequest(BaseModel):
    username: str

# =========================================================
# REGISTER
# =========================================================

@router.post("/register")
def register(data: RegisterRequest):

    conn = get_db()

    existing = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (data.username,)
    ).fetchone()

    # Registration failed - username already exists
    if existing:
        conn.execute(
            "INSERT INTO audit_logs (username, action) VALUES (?, ?)",
            (data.username, "REGISTER_FAILURE")
        )

        conn.commit()
        conn.close()

        return {
            "success": False,
            "message": "Username already exists"
        }

    # Hash password before storing
    password_hash = hash_password(data.password)

    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (data.username, password_hash)
    )

    # Registration succeeded
    conn.execute(
        "INSERT INTO audit_logs (username, action) VALUES (?, ?)",
        (data.username, "REGISTER_SUCCESS")
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "User registered successfully"
    }


# =========================================================
# LOGIN
# =========================================================

@router.post("/login")
def login(data: LoginRequest):

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (data.username,)
    ).fetchone()

    # Login failed - username does not exist
    if not user:

        conn.execute(
            "INSERT INTO audit_logs (username, action) VALUES (?, ?)",
            (data.username, "LOGIN_FAILURE")
        )

        conn.commit()
        conn.close()

        return {
            "success": False,
            "message": "Username not found"
        }

    # Login failed - incorrect password
    if not verify_password(data.password, user["password_hash"]):

        conn.execute(
            "INSERT INTO audit_logs (username, action) VALUES (?, ?)",
            (data.username, "LOGIN_FAILURE")
        )

        conn.commit()
        conn.close()

        return {
            "success": False,
            "message": "Invalid password"
        }

    # =====================================================
    # LOGIN SUCCESSFUL
    # =====================================================

    payload = {
        "username": data.username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=2)
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    # Store successful login in audit log
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

@router.post("/logout")
def logout(data: LogoutRequest):
    conn = get_db()
    # Store logout event in audit log
    conn.execute(
        "INSERT INTO audit_logs (username, action) VALUES (?, ?)",
        (data.username, "LOGOUT_SUCCESS")
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Logout successful",
    }