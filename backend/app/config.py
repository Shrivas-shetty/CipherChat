import os
from pathlib import Path
import secrets

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))
MAX_USERS = 2
CHAT_TEXT_MIN = 1
CHAT_TEXT_MAX = 2000
PROTOCOL_VERSION = 1

# Database and Authentication settings
DB_PATH = os.getenv("DB_PATH", "data/app.db")
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", 8))
LOGIN_MAX_FAILS = int(os.getenv("LOGIN_MAX_FAILS", 5))
LOGIN_FAIL_WINDOW_MIN = int(os.getenv("LOGIN_FAIL_WINDOW_MIN", 5))

USERNAME_MIN = 3
USERNAME_MAX = 20
PASSWORD_MIN_BYTES = 8
PASSWORD_MAX_BYTES = 72

# Phase 4 Message & Tamper Demo settings
TAMPER_DEMO_ENABLED = os.getenv("TAMPER_DEMO_ENABLED", "true").lower() in ("1", "true", "yes")
MESSAGE_PLAINTEXT_MAX_CHARS = 2000
MESSAGE_PLAINTEXT_MAX_BYTES = 8000
MESSAGE_CIPHERTEXT_MAX_BYTES = 8192


def get_jwt_secret() -> str:
    env_secret = os.getenv("JWT_SECRET")
    if env_secret:
        return env_secret
    secret_file = DATA_DIR / "jwt_secret"
    if secret_file.is_file():
        content = secret_file.read_text(encoding="utf-8").strip()
        if content:
            return content
    new_secret = secrets.token_hex(32)
    secret_file.write_text(new_secret, encoding="utf-8")
    return new_secret


JWT_SECRET = get_jwt_secret()


def get_db_file_path() -> Path:
    p = Path(DB_PATH)
    if not p.is_absolute():
        p = BASE_DIR / p
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


# localhost + RFC1918 private ranges, any port
CORS_ORIGIN_REGEX = (
    r"^https?://("
    r"localhost"
    r"|127\.0\.0\.1"
    r"|10(?:\.\d{1,3}){3}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r"|192\.168(?:\.\d{1,3}){2}"
    r")(:\d+)?$"
)
