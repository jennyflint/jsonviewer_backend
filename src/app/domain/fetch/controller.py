from __future__ import annotations

from litestar import Controller, post

from app.config import Settings
from app.domain.fetch.schemas import FetchRequest, FetchResponse
from app.domain.fetch.service import Fetcher


class FetchController(Controller):
    path = "/fetch"
    tags = ["Fetch"]

    @post("/", summary="Fetch JSON from a remote URL (SSRF-protected)", status_code=200)
    async def fetch_url(self, data: FetchRequest, settings: Settings) -> FetchResponse:
        return await Fetcher(settings).fetch(data.url)
