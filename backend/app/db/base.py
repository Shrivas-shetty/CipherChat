from pathlib import Path
from typing import Generator, Optional

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from app.config import get_db_file_path

Base = declarative_base()

_db_file = get_db_file_path()
_db_file.parent.mkdir(parents=True, exist_ok=True)
engine = create_engine(
    f"sqlite:///{_db_file}",
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def set_engine_and_session(new_engine: Engine):
    """Allows test fixtures to swap out the active database engine."""
    global engine, SessionLocal
    engine = new_engine
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db(engine_instance: Optional[Engine] = None) -> None:
    # Import models so all tables are registered with Base.metadata
    from app.db import models  # noqa: F401

    target_engine = engine_instance or engine
    Base.metadata.create_all(bind=target_engine)
    from app.db.migrate import ensure_model_columns
    ensure_model_columns(target_engine, Base.metadata.tables["messages"])
    # Preserve old signing records but retire keys from any previous signature format.
    if inspect(target_engine).has_table("signing_keys"):
        from app.db.models import utc_now
        with target_engine.begin() as connection:
            connection.execute(text(
                "UPDATE signing_keys SET retired_at = COALESCE(retired_at, :retired_at), "
                "retire_reason = 'legacy_algorithm' WHERE length(public_key_der) != 65"
            ), {"retired_at": utc_now()})


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

