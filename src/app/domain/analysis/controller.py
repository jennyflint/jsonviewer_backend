from __future__ import annotations

from functools import partial

import anyio
from litestar import Controller, post

from app.config import Settings
from app.domain.analysis.duplicates import analyze, load_document
from app.domain.analysis.schemas import (
    DuplicatesRequest,
    DuplicatesResponse,
    ParseErrorOut,
    ValidateRequest,
    ValidateResponse,
    ValidateStats,
)
from app.lib.errors import AppError, Unprocessable
from app.lib.json_utils import prepare_content

ANALYSIS_TIMEOUT_SECONDS = 10


class AnalysisTimeout(AppError):
    status_code = 504
    code = "analysis_timeout"
    message = "Analysis took too long."


async def run_cpu(func: partial[object] | partial[DuplicatesResponse] | partial[ValidateResponse]):  # type: ignore[no-untyped-def]
    try:
        with anyio.fail_after(ANALYSIS_TIMEOUT_SECONDS):
            return await anyio.to_thread.run_sync(func, abandon_on_cancel=True)
    except TimeoutError:
        raise AnalysisTimeout() from None


def _validate(text: str, size: int) -> ValidateResponse:
    loaded = load_document(text)
    if loaded.too_deep:
        raise Unprocessable("JSON nesting is too deep.", code="nesting_too_deep")
    err: ParseErrorOut | None = loaded.error
    return ValidateResponse(
        valid=loaded.valid,
        parse_error=err,
        stats=ValidateStats(nodes=loaded.nodes, depth=loaded.depth, size_bytes=size),
        has_duplicate_keys=loaded.has_dups,
    )


class AnalysisController(Controller):
    path = "/analysis"
    tags = ["Analysis"]

    @post("/duplicates", summary="Find duplicate keys, values and subtrees", status_code=200)
    async def duplicates(self, data: DuplicatesRequest, settings: Settings) -> DuplicatesResponse:
        text, _ = prepare_content(data.content, settings.max_document_bytes)
        return await run_cpu(partial(analyze, text, data.options))  # type: ignore[no-any-return]

    @post("/validate", summary="Validate JSON and report basic stats", status_code=200)
    async def validate(self, data: ValidateRequest, settings: Settings) -> ValidateResponse:
        text, size = prepare_content(data.content, settings.max_document_bytes)
        return await run_cpu(partial(_validate, text, size))  # type: ignore[no-any-return]
