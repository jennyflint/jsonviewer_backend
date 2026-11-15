from __future__ import annotations

import msgspec
from litestar import Controller, Response, get
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import VERSION


class HealthResponse(msgspec.Struct):
    status: str
    db: str
    version: str


class SystemController(Controller):
    path = "/health"
    tags = ["System"]

    @get("/", summary="Health check")
    async def health(self, db_session: AsyncSession) -> Response[HealthResponse]:
        try:
            await db_session.execute(text("SELECT 1"))
        except Exception:
            return Response(HealthResponse("error", "error", VERSION), status_code=503)
        return Response(HealthResponse("ok", "ok", VERSION), status_code=200)
