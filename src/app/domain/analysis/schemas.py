from __future__ import annotations

from typing import Annotated, Any, Literal

import msgspec
from msgspec import Meta

ValueType = Literal["string", "number", "boolean", "null"]


class ByField(msgspec.Struct):
    array_path: Annotated[str, Meta(max_length=1000)]
    field: Annotated[str, Meta(max_length=500)]


class DuplicateOptions(msgspec.Struct, kw_only=True):
    keys: bool = True
    values: bool = True
    subtrees: bool = True
    by_field: ByField | None = None
    min_occurrences: Annotated[int, Meta(ge=2, le=1_000_000)] = 2
    min_string_length: Annotated[int, Meta(ge=0, le=1_000_000)] = 1
    value_types: list[ValueType] = msgspec.field(
        default_factory=lambda: ["string", "number", "boolean", "null"]
    )
    min_subtree_size: Annotated[int, Meta(ge=1, le=1_000_000)] = 2
    max_groups: Annotated[int, Meta(ge=1, le=5000)] = 500


class DuplicatesRequest(msgspec.Struct, kw_only=True):
    content: str
    options: DuplicateOptions = msgspec.field(default_factory=DuplicateOptions)


class ValidateRequest(msgspec.Struct):
    content: str


class ParseErrorOut(msgspec.Struct):
    message: str
    line: int
    column: int


class Stats(msgspec.Struct):
    nodes: int
    depth: int
    elapsed_ms: int


class KeyOccurrence(msgspec.Struct):
    line: int
    column: int
    offset: int
    value_preview: str


class DuplicateKey(msgspec.Struct):
    object_path: str
    key: str
    occurrences: list[KeyOccurrence]


class DuplicateValue(msgspec.Struct):
    type: str
    value: Any
    count: int
    paths: list[str]
    lexemes: list[str] | None = None


class DuplicateSubtree(msgspec.Struct):
    hash: str
    kind: str
    size: int
    count: int
    preview: str
    paths: list[str]


class FieldGroup(msgspec.Struct):
    value: Any
    indices: list[int]


class DuplicatesByField(msgspec.Struct):
    array_path: str
    field: str
    groups: list[FieldGroup]
    missing: int


class DuplicatesResponse(msgspec.Struct):
    valid: bool
    parse_error: ParseErrorOut | None
    stats: Stats
    duplicate_keys: list[DuplicateKey]
    duplicate_values: list[DuplicateValue]
    duplicate_subtrees: list[DuplicateSubtree]
    duplicates_by_field: DuplicatesByField | None
    truncated: bool


class ValidateStats(msgspec.Struct):
    nodes: int
    depth: int
    size_bytes: int


class ValidateResponse(msgspec.Struct):
    valid: bool
    parse_error: ParseErrorOut | None
    stats: ValidateStats
    has_duplicate_keys: bool
