"""Database-only helpers for client-reported text metrics."""
from sqlalchemy.orm import Session

from app.db.models import Message, User, to_iso_z
from app.db.lab_models import ImageMetric, TextMetric
from app.image import parse_image_meta


def create_text_metric(db: Session, values: dict) -> TextMetric:
    row = TextMetric(**values)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def create_image_metric(db: Session, values: dict) -> ImageMetric:
    row = ImageMetric(**values)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_text_metrics(db: Session, *, limit: int = 200, before_id: int | None = None):
    limit = max(1, min(limit, 2000))
    query = db.query(TextMetric)
    if before_id is not None:
        query = query.filter(TextMetric.id < before_id)
    rows = query.order_by(TextMetric.id.desc()).limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    total = db.query(TextMetric).count()
    latest_id = db.query(TextMetric.id).order_by(TextMetric.id.desc()).limit(1).scalar()
    return {"total": total, "items": rows, "has_more_older": has_more, "latest_id": latest_id}


def clear_text_metrics(db: Session) -> int:
    deleted = db.query(TextMetric).delete(synchronize_session=False)
    db.commit()
    return deleted


def clear_image_metrics(db: Session) -> int:
    deleted = db.query(ImageMetric).delete(synchronize_session=False)
    db.commit()
    return deleted


def list_image_metrics(db: Session, *, limit: int = 200, before_id: int | None = None):
    limit = max(1, min(limit, 2000))
    query = db.query(ImageMetric)
    if before_id is not None:
        query = query.filter(ImageMetric.id < before_id)
    rows = query.order_by(ImageMetric.id.desc()).limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    return {
        "total": db.query(ImageMetric).count(),
        "items": rows,
        "has_more_older": has_more,
        "latest_id": db.query(ImageMetric.id).order_by(ImageMetric.id.desc()).limit(1).scalar(),
    }


def query_image_records(lab_db: Session, app_db: Session, *, limit: int = 200, before_id: int | None = None):
    page = list_image_metrics(lab_db, limit=limit, before_id=before_id)
    metrics = page["items"]
    ids = [row.message_id for row in metrics]
    messages = {row.id: row for row in app_db.query(Message).filter(Message.id.in_(ids)).all()} if ids else {}
    sender_ids = {row.sender_id for row in metrics}
    users = {row.id: row for row in app_db.query(User).filter(User.id.in_(sender_ids)).all()} if sender_ids else {}
    items = []
    for row in metrics:
        item = {column.name: getattr(row, column.name) for column in ImageMetric.__table__.columns}
        item["sender"] = users[row.sender_id].username if row.sender_id in users else None
        message = messages.get(row.message_id)
        item["message_created_at"] = to_iso_z(message.created_at) if message else None
        item.pop("sender_id", None)
        items.append(item)
    page["items"] = items
    return page


def get_cipher_noise_message(app_db: Session, message_id: int):
    message = app_db.query(Message).filter(Message.id == message_id, Message.msg_type == "image").first()
    if message is None:
        return None
    try:
        width, height = parse_image_meta(message.meta_json)
    except ValueError:
        return None
    return width, height, bytes(message.ct[:width * height * 3])


def query_text_records(lab_db: Session, app_db: Session, *, limit: int = 200, before_id: int | None = None):
    page = list_text_metrics(lab_db, limit=limit, before_id=before_id)
    metrics = page["items"]
    message_ids = [row.message_id for row in metrics]
    messages = {row.id: row for row in app_db.query(Message).filter(Message.id.in_(message_ids)).all()} if message_ids else {}
    sender_ids = {messages[row.message_id].sender_id for row in metrics if row.message_id in messages}
    users = {row.id: row for row in app_db.query(User).filter(User.id.in_(sender_ids)).all()} if sender_ids else {}
    output = []
    for row in metrics:
        message = messages.get(row.message_id)
        user = users.get(row.sender_id)
        item = {column.name: getattr(row, column.name) for column in TextMetric.__table__.columns}
        item["sender"] = user.username if user else None
        item["message_created_at"] = to_iso_z(message.created_at) if message else None
        item.pop("sender_id", None)
        output.append(item)
    page["items"] = output
    return page
