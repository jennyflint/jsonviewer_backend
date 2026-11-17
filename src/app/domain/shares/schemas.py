from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

import msgspec
from msgspec import Meta


class CreateShareRequest(msgspec.Struct, kw_only=True):
    content: str
    kind: Literal["single", "compare"] = "single"
    title: Annotated[str, Meta(max_length=200)] | None = None
    content_right: str | None = None
    expires_in: Literal["1h", "1d", "7d", "30d", "never"] = "30d"
    save_to_history: bool = False
    password: Annotated[str, Meta(min_length=4, max_length=128)] | None = None
    burn_after_read: bool = False
    comments_enabled: bool = False


class ShareCreated(msgspec.Struct):
    slug: str
    url: str
    kind: str
    expires_at: datetime | None
    created_at: datetime
    delete_token: str | None = None


class ShareDetail(msgspec.Struct):
    slug: str
    kind: str
    title: str | None
    content: str
    content_right: str | None
    size_bytes: int
    created_at: datetime
    expires_at: datetime | None
    view_count: int
    is_owner: bool
    comments_enabled: bool = False
    password_protected: bool = False
    burn_after_read: bool = False


class ShareListItem(msgspec.Struct):
    slug: str
    url: str
    kind: str
    title: str | None
    preview: str
    size_bytes: int
    created_at: datetime
    expires_at: datetime | None
    view_count: int


class SharePage(msgspec.Struct):
    items: list[ShareListItem]
    total: int
    limit: int
    offset: int


class ShareMeta(msgspec.Struct):
    """Non-consuming description of a share (does not count as a view and never burns it)."""

    slug: str
    kind: str
    title: str | None
    created_at: datetime
    expires_at: datetime | None
    password_protected: bool
    burn_after_read: bool
    comments_enabled: bool


class OpenShareRequest(msgspec.Struct, kw_only=True):
    password: Annotated[str, Meta(max_length=128)] | None = None


class CreateCommentRequest(msgspec.Struct, kw_only=True):
    text: Annotated[str, Meta(min_length=1, max_length=2000)]
    author: Annotated[str, Meta(min_length=1, max_length=60)]
    path: Annotated[str, Meta(max_length=1000)] | None = None


class CommentOut(msgspec.Struct):
    id: str
    path: str | None
    author: str
    text: str
    created_at: datetime
