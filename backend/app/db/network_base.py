from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from app.config import get_network_db_file_path
from app.db.network_models import NetworkBase

_network_file = get_network_db_file_path()
engine = create_engine(f"sqlite:///{_network_file}", connect_args={"check_same_thread": False})
def _sqlite_pragmas(connection, _record):
    cursor=connection.cursor(); cursor.execute("PRAGMA journal_mode=WAL"); cursor.execute("PRAGMA foreign_keys=ON"); cursor.close()
event.listen(engine, "connect", _sqlite_pragmas)
NetworkSessionLocal=sessionmaker(autocommit=False,autoflush=False,bind=engine)
def set_network_engine_and_session(new_engine: Engine) -> None:
    global engine, NetworkSessionLocal
    engine=new_engine
    if not event.contains(engine,"connect",_sqlite_pragmas):event.listen(engine,"connect",_sqlite_pragmas)
    NetworkSessionLocal=sessionmaker(autocommit=False,autoflush=False,bind=engine)
def init_network_db(engine_instance: Engine | None=None) -> None: NetworkBase.metadata.create_all(bind=engine_instance or engine)
def get_network_db() -> Generator[Session,None,None]:
    db=NetworkSessionLocal()
    try: yield db
    finally: db.close()
