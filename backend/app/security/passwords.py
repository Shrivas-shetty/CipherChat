import bcrypt

from app.config import PASSWORD_MAX_BYTES, PASSWORD_MIN_BYTES

# Pre-computed dummy hash so unknown user lookups execute a bcrypt check in similar time
_DUMMY_HASH = bcrypt.hashpw(b"timing_attack_mitigation_dummy_value", bcrypt.gensalt()).decode("utf-8")


def validate_password(password: str) -> tuple[bool, str]:
    raw_bytes = password.encode("utf-8")
    if len(raw_bytes) < PASSWORD_MIN_BYTES or len(raw_bytes) > PASSWORD_MAX_BYTES:
        return False, f"Password must be {PASSWORD_MIN_BYTES}–{PASSWORD_MAX_BYTES} bytes."
    if not any(c.isalpha() for c in password):
        return False, "Password must contain at least one letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    return True, ""


def hash_password(password: str) -> str:
    raw_bytes = password.encode("utf-8")
    return bcrypt.hashpw(raw_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


def verify_dummy(plain_password: str) -> bool:
    verify_password(plain_password, _DUMMY_HASH)
    return False

