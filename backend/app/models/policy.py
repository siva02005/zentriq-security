from sqlalchemy import Column, Integer, String, Boolean, JSON, Float
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.db.base import Base

class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    effect: Mapped[str] = mapped_column(String(50), nullable=False)  # ALLOW, RESTRICT, BLOCK
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    action_types: Mapped[str] = mapped_column(JSON, nullable=True)  # list of action types this applies to
    destination_patterns: Mapped[str] = mapped_column(JSON, nullable=True)  # list of destination patterns
    data_tags: Mapped[str] = mapped_column(JSON, nullable=True)  # list of data tags
    third_party: Mapped[bool] = mapped_column(Boolean, nullable=True)
