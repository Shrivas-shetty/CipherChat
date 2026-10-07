import sys

from app.db.base import init_db
from app.services.audit import verify_chain


def main():
    init_db()
    ok, bad_id = verify_chain()
    if ok:
        print("OK")
        sys.exit(0)
    else:
        print(f"Corrupted at row id: {bad_id}")
        sys.exit(1)


if __name__ == "__main__":
    main()

