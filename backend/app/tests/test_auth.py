from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import config
from app.db import base
from app.db.base import Base, set_engine_and_session
from app.db.models import AuditLog, AuthSession, User
from app.main import create_app
from app.security.tokens import create_token
from app.services.audit import verify_chain


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path: Path):
    test_db_path = tmp_path / "test_app.db"
    test_engine = create_engine(
        f"sqlite:///{test_db_path}",
        connect_args={"check_same_thread": False},
    )
    set_engine_and_session(test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


def test_register_ok(client: TestClient):
    res = client.post(
        "/api/auth/register",
        json={"username": "alice", "password": "Password123"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["username"] == "alice"
    assert data["role"] == "user"
    assert "id" in data

    with base.SessionLocal() as db:
        logs = db.query(AuditLog).filter(AuditLog.event_type == "REGISTER").all()
        assert len(logs) == 1
        assert logs[0].success is True
        assert logs[0].username_attempted == "alice"


def test_register_duplicate(client: TestClient):
    client.post(
        "/api/auth/register",
        json={"username": "alice", "password": "Password123"},
    )
    # Duplicate with different casing
    res2 = client.post(
        "/api/auth/register",
        json={"username": "ALICE", "password": "Password456"},
    )
    assert res2.status_code == 409
    assert "already taken" in res2.json()["detail"].lower()

    with base.SessionLocal() as db:
        logs = (
            db.query(AuditLog)
            .filter(AuditLog.event_type == "REGISTER_FAILED")
            .all()
        )
        assert len(logs) == 1
        assert logs[0].details["reason"] == "username_taken"


def test_register_weak_password(client: TestClient):
    # Too short (< 8 chars)
    res_short = client.post(
        "/api/auth/register",
        json={"username": "bob", "password": "short1"},
    )
    assert res_short.status_code == 422

    # No digits
    res_no_digit = client.post(
        "/api/auth/register",
        json={"username": "bob", "password": "onlylettershere"},
    )
    assert res_no_digit.status_code == 422

    # No letters
    res_no_letter = client.post(
        "/api/auth/register",
        json={"username": "bob", "password": "1234567890"},
    )
    assert res_no_letter.status_code == 422


def test_login_ok(client: TestClient):
    client.post(
        "/api/auth/register",
        json={"username": "alice", "password": "Password123"},
    )

    res = client.post(
        "/api/auth/login",
        json={"username": "alice", "password": "Password123"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "alice"

    with base.SessionLocal() as db:
        logs = db.query(AuditLog).filter(AuditLog.event_type == "LOGIN_SUCCESS").all()
        assert len(logs) == 1
        assert logs[0].success is True


def test_generic_401_for_bad_password_and_unknown_user(client: TestClient):
    client.post(
        "/api/auth/register",
        json={"username": "alice", "password": "Password123"},
    )

    # Unknown user
    res1 = client.post(
        "/api/auth/login",
        json={"username": "unknown_user", "password": "Password123"},
    )
    assert res1.status_code == 401
    assert res1.json() == {"detail": "Invalid username or password"}

    # Bad password
    res2 = client.post(
        "/api/auth/login",
        json={"username": "alice", "password": "WrongPassword123"},
    )
    assert res2.status_code == 401
    assert res2.json() == {"detail": "Invalid username or password"}

    with base.SessionLocal() as db:
        failed_logs = (
            db.query(AuditLog)
            .filter(AuditLog.event_type == "LOGIN_FAILED")
            .order_by(AuditLog.id.asc())
            .all()
        )
        assert len(failed_logs) == 2
        assert failed_logs[0].details["reason"] == "unknown_user"
        assert failed_logs[0].details["unauthorized_access_attempt"] is True
        assert failed_logs[1].details["reason"] == "bad_password"
        assert failed_logs[1].details["unauthorized_access_attempt"] is True


def test_lockout_after_5_failures(client: TestClient):
    client.post(
        "/api/auth/register",
        json={"username": "lockout_user", "password": "Password123"},
    )

    # 5 wrong attempts
    for _ in range(5):
        res = client.post(
            "/api/auth/login",
            json={"username": "lockout_user", "password": "WrongPassword1"},
        )
        assert res.status_code == 401

    # 6th attempt should be locked out (429)
    res_lock = client.post(
        "/api/auth/login",
        json={"username": "lockout_user", "password": "Password123"},
    )
    assert res_lock.status_code == 429
    data = res_lock.json()
    assert data["detail"] == "Too many failed attempts"
    assert "retry_after_seconds" in data
    assert data["retry_after_seconds"] > 0

    with base.SessionLocal() as db:
        locked_logs = db.query(AuditLog).filter(AuditLog.event_type == "LOGIN_LOCKED").all()
        assert len(locked_logs) == 1
        assert locked_logs[0].severity == "alert"


def test_logout_revokes_token(client: TestClient):
    client.post(
        "/api/auth/register",
        json={"username": "logout_user", "password": "Password123"},
    )

    login_res = client.post(
        "/api/auth/login",
        json={"username": "logout_user", "password": "Password123"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify /me works
    me_res = client.get("/api/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "logout_user"

    # Logout
    logout_res = client.post("/api/auth/logout", headers=headers)
    assert logout_res.status_code == 204

    # Subsequent /me must fail with 401
    me_after = client.get("/api/auth/me", headers=headers)
    assert me_after.status_code == 401

    with base.SessionLocal() as db:
        logout_logs = db.query(AuditLog).filter(AuditLog.event_type == "LOGOUT").all()
        assert len(logout_logs) == 1


def test_expired_token_rejected(client: TestClient):
    client.post(
        "/api/auth/register",
        json={"username": "exp_user", "password": "Password123"},
    )

    with base.SessionLocal() as db:
        user = db.query(User).filter(User.username == "exp_user").first()
        assert user is not None
        past = datetime.now(timezone.utc) - timedelta(hours=10)
        expired_token = create_token(
            user_id=user.id,
            role=user.role,
            jti="expired-jti-test",
            issued_at=past - timedelta(hours=1),
            expires_at=past,
        )
        expired_session = AuthSession(
            jti="expired-jti-test",
            user_id=user.id,
            issued_at=past - timedelta(hours=1),
            expires_at=past,
            ip="127.0.0.1",
        )
        db.add(expired_session)
        db.commit()

    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401

    with base.SessionLocal() as db:
        token_rejected_logs = (
            db.query(AuditLog)
            .filter(AuditLog.event_type == "TOKEN_REJECTED")
            .all()
        )
        assert len(token_rejected_logs) >= 1
        assert token_rejected_logs[-1].details["reason"] == "expired"


def test_verify_chain_ok_and_tampered(client: TestClient):
    client.post(
        "/api/auth/register",
        json={"username": "chain_user", "password": "Password123"},
    )
    client.post(
        "/api/auth/login",
        json={"username": "chain_user", "password": "Password123"},
    )

    # Chain should be valid
    ok, bad_id = verify_chain()
    assert ok is True
    assert bad_id is None

    # Tamper with an audit record
    with base.SessionLocal() as db:
        first_row = db.query(AuditLog).order_by(AuditLog.id.asc()).first()
        assert first_row is not None
        tampered_id = first_row.id
        first_row.username_attempted = "tampered_name"
        db.commit()

    ok, bad_id = verify_chain()
    assert ok is False
    assert bad_id == tampered_id
