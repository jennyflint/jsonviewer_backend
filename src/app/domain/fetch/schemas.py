from __future__ import annotations

from typing import Annotated

import msgspec
from msgspec import Meta

from app.domain.analysis.schemas import ParseErrorOut


class FetchRequest(msgspec.Struct):
    url: Annotated[str, Meta(max_length=4096)]


class FetchResponse(msgspec.Struct):
    url: str
    final_url: str
    status_code: int
    content_type: str | None
    size_bytes: int
    is_valid_json: bool
    parse_error: ParseErrorOut | None
    content: str
