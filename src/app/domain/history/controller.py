from __future__ import annotations

import uuid
from typing import Annotated, Literal

import msgspec
from litestar import Controller, Response, delete, get, patch, post
from litestar.di import Provide
from litestar.params import Parameter
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.db.models import HistorySource, User
from app.domain.auth.guards import provide_required_user, requires_auth
from app.domain.history.schemas import (
    ClearHistoryRequest,
    CreateHistoryRequest,
    HistoryDetail,
    HistoryPage,
    UpdateHistoryRequest,
)
from app.domain.history.service import HistoryService
from app.lib.errors import Unprocessable


async def provide_history_service(db_session: AsyncSession, settings: Settings) -> HistoryService:
    return HistoryService(db_session, settings)


class HistoryController(Controller):
    path = "/history"
    tags = ["History"]
    guards = [requires_auth]
    dependencies = {
        "service": Provide(provide_history_service),
        "user": Provide(provide_required_user, sync_to_thread=False),
    }

    @get("/", summary="List and search history")
    async def list_history(
        self,
        service: HistoryService,
        user: User,
        q: str | None = None,
        source: Literal["manual", "format", "share", "url", "compare"] | None = None,
        pinned: bool | None = None,
        limit: Annotated[int, Parameter(ge=1, le=100)] = 20,
        offset: Annotated[int, Parameter(ge=0)] = 0,
        sort: Literal["updated_at", "created_at", "title", "size"] | None = None,
        order: Literal["desc", "asc"] = "desc",
    ) -> HistoryPage:
        return await service.list_entries(
            user.id,
            q=q,
            source=source,
            pinned=pinned,
            limit=limit,
            offset=offset,
            sort=sort,
            order=order,
        )

    @post("/", summary="Create or refresh a history entry", status_code=201)
    async def create_entry(
        self, data: CreateHistoryRequest, service: HistoryService, user: User
    ) -> Response[HistoryDetail]:
        entry, created = await service.upsert(
            user_id=user.id,
            content=data.content,
            source=HistorySource(data.source),
            title=data.title,
            source_url=data.source_url,
        )
        detail = await service.detail(entry, deduplicated=not created)
        return Response(detail, status_code=201 if created else 200)

    @get("/{entry_id:uuid}", summary="Get a history entry")
    async def get_entry(
        self, entry_id: uuid.UUID, service: HistoryService, user: User
    ) -> HistoryDetail:
        return await service.get(user.id, entry_id)

    @patch("/{entry_id:uuid}", summary="Rename or pin a history entry")
    async def update_entry(
        self, entry_id: uuid.UUID, data: UpdateHistoryRequest, service: HistoryService, user: User
    ) -> HistoryDetail:
        title = None if isinstance(data.title, msgspec.UnsetType) else data.title
        pinned = None if isinstance(data.pinned, msgspec.UnsetType) else data.pinned
        return await service.update(user.id, entry_id, title, pinned)

    @delete("/{entry_id:uuid}", summary="Delete a history entry", status_code=204)
    async def delete_entry(self, entry_id: uuid.UUID, service: HistoryService, user: User) -> None:
        await service.delete(user.id, entry_id)

    @delete("/", summary="Clear all history", status_code=204)
    async def clear_history(
        self, data: ClearHistoryRequest, service: HistoryService, user: User
    ) -> None:
        if not data.confirm:
            raise Unprocessable(
                "Set confirm to true to clear history.", code="confirmation_required"
            )
        await service.clear(user.id)
