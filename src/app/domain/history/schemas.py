from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

import msgspec
from msgspec import Meta

SourceLiteral = Literal["manual", "format", "share", "url", "compare"]


class CreateHistoryRequest(msgspec.Struct, kw_only=True):
    content: str
    source: SourceLiteral
    title: Annotated[str, Meta(max_length=200)] | None = None
    source_url: Annotated[str, Meta(max_length=2048)] | None = None


class UpdateHistoryRequest(msgspec.Struct, kw_only=True):
    title: Annotated[str, Meta(min_length=1, max_length=200)] | msgspec.UnsetType = msgspec.UNSET
    pinned: bool | msgspec.UnsetType = msgspec.UNSET


class ClearHistoryRequest(msgspec.Struct):
    confirm: bool


class HistoryItem(msgspec.Struct):
    id: str
    title: str
    preview: str
    size_bytes: int
    is_valid_json: bool
    source: str
    source_url: str | None
    share_slug: str | None
    pinned: bool
    created_at: datetime
    updated_at: datetime


class HistoryDetail(msgspec.Struct):
    id: str
    title: str
    content: str
    preview: str
    size_bytes: int
    is_valid_json: bool
    source: str
    source_url: str | None
    share_slug: str | None
    pinned: bool
    created_at: datetime
    updated_at: datetime
    deduplicated: bool | None = None


class HistoryPage(msgspec.Struct):
    items: list[HistoryItem]
    total: int
    limit: int
    offset: int
