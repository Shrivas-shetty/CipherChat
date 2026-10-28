"""Small idempotent SQLite schema upgrades shared by application databases."""
from sqlalchemy import inspect
from sqlalchemy.engine import Engine
from sqlalchemy.sql import quoted_name


def ensure_columns(engine: Engine, table_name: str, columns: dict[str, str]) -> None:
    if not inspect(engine).has_table(table_name):
        return
    with engine.begin() as connection:
        present = {row["name"] for row in inspect(connection).get_columns(table_name)}
        preparer = engine.dialect.identifier_preparer
        table = preparer.quote(quoted_name(table_name, True))
        for name, sql_type in columns.items():
            if name not in present:
                column = preparer.quote(quoted_name(name, True))
                # Intentionally omit ORM foreign-key constraints for SQLite ALTER TABLE.
                connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")


def ensure_model_columns(engine: Engine, table) -> None:
    columns = {
        column.name: column.type.compile(dialect=engine.dialect)
        for column in table.columns
        if column.nullable and not column.primary_key
    }
    ensure_columns(engine, table.name, columns)
