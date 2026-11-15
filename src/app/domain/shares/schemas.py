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
