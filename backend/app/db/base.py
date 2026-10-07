from pathlib import Path
from typing import Generator, Optional

from sqlalchemy import create_engine, event
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


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

