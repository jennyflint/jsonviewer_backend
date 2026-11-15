from __future__ import annotations

import enum
from typing import Any

from advanced_alchemy.base import UUIDv7AuditBase
from sqlalchemy import Enum as SAEnum


class Base(UUIDv7AuditBase):
    """Declarative base: UUIDv7 primary key + created_at/updated_at (timestamptz)."""

    __abstract__ = True


def pg_enum(enum_cls: type[enum.Enum], name: str) -> SAEnum:
    kwargs: dict[str, Any] = {"values_callable": lambda e: [m.value for m in e], "name": name}
    return SAEnum(enum_cls, **kwargs)
