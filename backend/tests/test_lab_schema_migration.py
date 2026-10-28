from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, JSON, MetaData, String, Table, create_engine, inspect, select

from app.db.lab_base import init_lab_db
from app.db.lab_models import ImageMetric


def test_image_metric_columns_upgrade_preserves_existing_rows(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old-lab.db'}")
    old_columns = [column for column in ImageMetric.__table__.columns if not column.name.startswith(("corr_v_", "corr_d_"))]
    old = Table("image_metrics", MetaData(), *(Column(column.name, column.type, primary_key=column.primary_key, nullable=column.nullable) for column in old_columns))
    old.metadata.create_all(engine)
    values = {}
    for column in old.columns:
        if column.primary_key: continue
        if column.name == "message_id": values[column.name] = 991
        elif column.name == "session_id": values[column.name] = "00000000-0000-0000-0000-000000000001"
        elif column.name == "sender_id": values[column.name] = 1
        elif isinstance(column.type, DateTime): values[column.name] = datetime.now(timezone.utc)
        elif isinstance(column.type, Integer): values[column.name] = 1
        elif isinstance(column.type, Float): values[column.name] = 1.0
        elif isinstance(column.type, JSON): values[column.name] = []
        elif isinstance(column.type, String): values[column.name] = "x"
    with engine.begin() as connection: connection.execute(old.insert().values(**values))

    init_lab_db(engine)
    init_lab_db(engine)
    columns = {column["name"] for column in inspect(engine).get_columns("image_metrics")}
    new_names = {column.name for column in ImageMetric.__table__.columns if column.name.startswith(("corr_v_", "corr_d_"))}
    assert new_names <= columns and len(new_names) == 16
    with engine.connect() as connection:
        row = connection.execute(select(ImageMetric.__table__).where(ImageMetric.message_id == 991)).mappings().one()
        assert row["session_id"] == values["session_id"]
        assert all(row[name] is None for name in new_names)
    engine.dispose()
