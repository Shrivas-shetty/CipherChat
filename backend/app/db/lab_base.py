from typing import Generator, Optional

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import get_lab_db_file_path

LabBase = declarative_base()
_lab_file = get_lab_db_file_path()


def _sqlite_pragmas(connection, _record):
    cursor = connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


engine = create_engine(f"sqlite:///{_lab_file}", connect_args={"check_same_thread": False})
event.listen(engine, "connect", _sqlite_pragmas)
LabSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def set_lab_engine_and_session(new_engine: Engine) -> None:
    global engine, LabSessionLocal
    engine = new_engine
    event.listen(engine, "connect", _sqlite_pragmas)
    LabSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_lab_db(engine_instance: Optional[Engine] = None) -> None:
    from app.db import lab_models  # noqa: F401
    LabBase.metadata.create_all(bind=engine_instance or engine)


def get_lab_db() -> Generator[Session, None, None]:
    db = LabSessionLocal()
    try:
        yield db
    finally:
        db.close()
