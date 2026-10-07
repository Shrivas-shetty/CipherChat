import argparse
import json

from app.db.base import SessionLocal, init_db
from app.db.models import AuditLog, to_iso_z


def main():
    parser = argparse.ArgumentParser(description="Display audit log entries in a readable table.")
    parser.add_argument("--tail", type=int, default=50, help="Number of entries to show (default: 50)")
    parser.add_argument("--type", type=str, default=None, help="Filter by event_type")
    args = parser.parse_args()

    init_db()

    with SessionLocal() as db:
        query = db.query(AuditLog)
        if args.type:
            query = query.filter(AuditLog.event_type == args.type.strip())
        rows = query.order_by(AuditLog.id.desc()).limit(args.tail).all()

    if not rows:
        print("No audit log records found.")
        return

    rows.reverse()

    header = f"{'ID':<6} {'Timestamp':<25} {'Event':<16} {'Sev':<8} {'OK':<6} {'User':<15} {'IP':<16} {'Details'}"
    separator = "-" * len(header)
    print(header)
    print(separator)

    for r in rows:
        ts_str = to_iso_z(r.ts) or ""
        user_str = str(r.username_attempted or r.user_id or "-")
        ok_str = "Yes" if r.success else "No"
        ip_str = r.ip or "-"
        details_str = json.dumps(r.details) if r.details else "-"
        if len(details_str) > 40:
            details_str = details_str[:37] + "..."
        print(
            f"{r.id:<6} {ts_str:<25} {r.event_type:<16} {r.severity:<8} {ok_str:<6} {user_str:<15} {ip_str:<16} {details_str}"
        )


if __name__ == "__main__":
    main()

