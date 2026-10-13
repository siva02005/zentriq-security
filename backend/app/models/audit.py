from sqlalchemy import Column, Integer, String, Float, JSON, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime, timezone
from backend.app.db.base import Base
import uuid

def generate_uuid():
    return str(uuid.uuid4())

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, default=generate_uuid)
    session_id: Mapped[str] = mapped_column(String(255), nullable=True)
    task_id: Mapped[str] = mapped_column(String(255), nullable=True)
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    action_description: Mapped[str] = mapped_column(String(1000), nullable=True)
    target: Mapped[str] = mapped_column(String(500), nullable=True)
    destination: Mapped[str] = mapped_column(String(500), nullable=True)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    reasons: Mapped[str] = mapped_column(JSON, nullable=False)
    applied_policies: Mapped[str] = mapped_column(JSON, nullable=False)
    triggered_rule: Mapped[str] = mapped_column(String(255), nullable=False)
    affected_resource: Mapped[str] = mapped_column(String(500), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
