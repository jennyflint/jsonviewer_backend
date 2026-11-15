from __future__ import annotations

import enum
import uuid

from sqlalchemy import (
    CHAR,
    Boolean,
    Computed,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    desc,
    false,
)
from sqlalchemy.dialects.postgresql import TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, pg_enum


class HistorySource(str, enum.Enum):  # noqa: UP042
    MANUAL = "manual"
    FORMAT = "format"
    SHARE = "share"
    URL = "url"
    COMPARE = "compare"


class HistoryEntry(Base):
    __tablename__ = "history_entries"
    __table_args__ = (
        UniqueConstraint("user_id", "content_hash", name="uq_history_user_hash"),
        Index("ix_history_user_updated", "user_id", desc("updated_at")),
        Index("ix_history_search_vector", "search_vector", postgresql_using="gin"),
        Index(
            "ix_history_title_trgm",
            "title",
            postgresql_using="gin",
            postgresql_ops={"title": "gin_trgm_ops"},
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(CHAR(64))
    is_valid_json: Mapped[bool] = mapped_column(Boolean)
    size_bytes: Mapped[int] = mapped_column(Integer)
    source: Mapped[HistorySource] = mapped_column(pg_enum(HistorySource, "history_source"))
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    share_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("shares.id", ondelete="SET NULL"), nullable=True
    )
    pinned: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    search_vector: Mapped[str] = mapped_column(
        TSVECTOR,
        Computed(
            "to_tsvector('simple', coalesce(title,'') || ' ' || left(content, 100000))",
            persisted=True,
        ),
        deferred=True,
    )
