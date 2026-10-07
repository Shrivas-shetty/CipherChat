import argparse
import getpass
import re
import sys

from app.db.base import SessionLocal, init_db
from app.db.models import User, utc_now
from app.security.passwords import hash_password, validate_password
from app.services.audit import log_event

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,20}$")


def main():
    parser = argparse.ArgumentParser(description="Create a user with the 'analyst' role.")
    parser.add_argument("--username", required=True, help="Username for the analyst")
    parser.add_argument("--password", required=False, help="Password (prompted if omitted)")
    args = parser.parse_args()

    init_db()

    username = args.username.strip()
    if not USERNAME_REGEX.match(username):
        print("Error: Username must be 3–20 characters and contain only letters, numbers, and underscores.")
        sys.exit(1)

    password = args.password
    if not password:
        pw1 = getpass.getpass("Enter password: ")
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("Error: Passwords do not match.")
            sys.exit(1)
        password = pw1

    valid, err_msg = validate_password(password)
    if not valid:
        print(f"Error: {err_msg}")
        sys.exit(1)

    norm_username = username.lower()
    with SessionLocal() as db:
        existing = db.query(User).filter(User.username_norm == norm_username).first()
        if existing:
            print(f"Error: Username '{username}' already exists.")
            sys.exit(1)

        pw_hash = hash_password(password)
        analyst = User(
            username=username,
            username_norm=norm_username,
            password_hash=pw_hash,
            role="analyst",
            created_at=utc_now(),
        )
        db.add(analyst)
        db.commit()
        db.refresh(analyst)

        log_event(
            "REGISTER",
            severity="info",
            user_id=analyst.id,
            username_attempted=analyst.username,
            success=True,
            details={"seeded_analyst": True},
        )

        print(f"Success: Analyst '{analyst.username}' (id={analyst.id}) created.")


if __name__ == "__main__":
    main()

