from __future__ import annotations

from typing import Annotated

from litestar import Controller, delete, get, post
from litestar.di import Provide
from litestar.params import Parameter
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.db.models import User
from app.domain.auth.guards import provide_required_user, requires_auth
from app.domain.shares.schemas import CreateShareRequest, ShareCreated, ShareDetail, SharePage
from app.domain.shares.service import ShareService


async def provide_share_service(db_session: AsyncSession, settings: Settings) -> ShareService:
    return ShareService(db_session, settings)


class ShareController(Controller):
    path = "/shares"
    tags = ["Shares"]
    dependencies = {"service": Provide(provide_share_service)}

    @post("/", summary="Create a share", status_code=201)
    async def create_share(
        self,
        data: CreateShareRequest,
        service: ShareService,
        current_user: User | None,
    ) -> ShareCreated:
        return await service.create(data, current_user)

    @get("/{slug:str}", summary="Get a share by slug")
    async def get_share(
        self, slug: str, service: ShareService, current_user: User | None
    ) -> ShareDetail:
        return await service.view(slug, current_user)

    @delete("/{slug:str}", summary="Delete a share", status_code=204)
    async def delete_share(
        self,
        slug: str,
        service: ShareService,
        current_user: User | None,
        delete_token: Annotated[
            str | None, Parameter(header="X-Delete-Token", required=False)
        ] = None,
    ) -> None:
        await service.delete(slug, current_user, delete_token)

    @get(
        "/",
        summary="List my shares",
        guards=[requires_auth],
        dependencies={"user": Provide(provide_required_user, sync_to_thread=False)},
    )
    async def list_shares(
        self,
        service: ShareService,
        user: User,
        limit: Annotated[int, Parameter(ge=1, le=100)] = 20,
        offset: Annotated[int, Parameter(ge=0)] = 0,
    ) -> SharePage:
        return await service.list_for_user(user.id, limit, offset)
