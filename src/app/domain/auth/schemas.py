from __future__ import annotations

from datetime import datetime

import msgspec


class UserOut(msgspec.Struct):
    id: str
    email: str | None
    name: str | None
    avatar_url: str | None
    providers: list[str]
    created_at: datetime


class MeResponse(msgspec.Struct):
    user: UserOut | None


class ProvidersResponse(msgspec.Struct):
    providers: list[str]


class SessionOut(msgspec.Struct):
    id: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    user_agent: str | None
    ip: str | None
    current: bool
