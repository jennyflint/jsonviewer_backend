from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import CHAR, Boolean, DateTime, ForeignKey, Integer, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, pg_enum


class ShareKind(str, enum.Enum):  # noqa: UP042
    SINGLE = "single"
    COMPARE = "compare"


class Share(Base):
    __tablename__ = "shares"

    slug: Mapped[str] = mapped_column(String(16), unique=True)
    kind: Mapped[ShareKind] = mapped_column(pg_enum(ShareKind, "share_kind"))
    title: Mapped[str | None] = mapped_column(String(200), nullable=True)
    content: Mapped[str] = mapped_column(Text)
    content_right: Mapped[str | None] = mapped_column(Text, nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    delete_token_hash: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    view_count: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    last_viewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(200), nullable=True)
    burn_after_read: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false")
    )
    comments_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false")
    )


class ShareComment(Base):
    """A comment on a shared document, optionally anchored to a JSON path."""

    __tablename__ = "share_comments"

    share_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("shares.id", ondelete="CASCADE"), index=True
    )
    path: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    author: Mapped[str] = mapped_column(String(60))
    text: Mapped[str] = mapped_column(String(2000))
