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
    target = engine_instance or engine
    LabBase.metadata.create_all(bind=target)
    image_table = LabBase.metadata.tables["image_metrics"]
    columns = {column.name: column.type.compile(dialect=target.dialect) for column in image_table.columns
               if column.name.startswith(("corr_v_", "corr_d_"))}
    ensure_columns(target, "image_metrics", columns)


def ensure_columns(engine: Engine, table_name: str, columns: dict[str, str]) -> None:
    """Idempotently add nullable SQLite columns while preserving existing rows."""
    from sqlalchemy import inspect
    from sqlalchemy.sql import quoted_name
    if not inspect(engine).has_table(table_name):
        return
    with engine.begin() as connection:
        present = {row["name"] for row in inspect(connection).get_columns(table_name)}
        preparer = engine.dialect.identifier_preparer
        table = preparer.quote(quoted_name(table_name, True))
        for name, sql_type in columns.items():
            if name not in present:
                column = preparer.quote(quoted_name(name, True))
                connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")


def get_lab_db() -> Generator[Session, None, None]:
    db = LabSessionLocal()
    try:
        yield db
    finally:
        db.close()
