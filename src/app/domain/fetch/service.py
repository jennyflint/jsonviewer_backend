from __future__ import annotations

import asyncio
from urllib.parse import urljoin

import httpx

from app.config import Settings
from app.domain.analysis.duplicates import check_text
from app.domain.fetch import ssrf
from app.domain.fetch.schemas import FetchResponse
from app.lib.errors import UpstreamError

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
USER_AGENT = "JSONViewer/1.0"
ACCEPT = "application/json, */*;q=0.8"


def decode_body(raw: bytes, charset: str | None) -> str:
    if charset:
        try:
            return raw.decode(charset, errors="replace").removeprefix("﻿")
        except LookupError:
            pass
    return raw.decode("utf-8", errors="replace").removeprefix("﻿")


class Fetcher:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def fetch(self, url: str) -> FetchResponse:
        try:
            async with asyncio.timeout(self.settings.fetch_timeout_seconds):
                return await self._fetch(url)
        except TimeoutError:
            raise ssrf.UpstreamTimedOut() from None

    async def _fetch(self, url: str) -> FetchResponse:
        current = url
        for _hop in range(self.settings.fetch_max_redirects + 1):
            target = ssrf.parse_url(current)
            ips = await ssrf.resolve_public(target)
            transport = ssrf.PinnedTransport(ips)
            timeout = httpx.Timeout(self.settings.fetch_timeout_seconds, connect=5.0)
            async with httpx.AsyncClient(
                transport=transport,
                follow_redirects=False,
                timeout=timeout,
                trust_env=False,
                headers={"User-Agent": USER_AGENT, "Accept": ACCEPT},
            ) as client:
                try:
                    request = client.build_request("GET", current)
                    response = await client.send(request, stream=True)
                except httpx.TimeoutException:
                    raise ssrf.UpstreamTimedOut() from None
                except httpx.HTTPError:
                    raise UpstreamError("Could not connect to the remote server.") from None
                try:
                    if response.status_code in REDIRECT_STATUSES:
                        location = response.headers.get("location")
                        if not location:
                            raise UpstreamError(
                                "Redirect without a Location header.",
                                details={"status": response.status_code},
                            )
                        current = urljoin(current, location)
                        continue
                    if response.status_code >= 300:
                        raise UpstreamError(
                            f"Upstream responded with status {response.status_code}.",
                            details={"status": response.status_code},
                        )
                    return await self._read(url, current, response)
                except httpx.TimeoutException:
                    raise ssrf.UpstreamTimedOut() from None
                except httpx.HTTPError:
                    raise UpstreamError("Failed while reading the remote response.") from None
                finally:
                    await response.aclose()
        raise ssrf.TooManyRedirects()

    async def _read(self, url: str, final_url: str, response: httpx.Response) -> FetchResponse:
        limit = self.settings.max_fetch_bytes
        declared = response.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise ssrf.FetchTooLarge()
        buf = bytearray()
        async for chunk in response.aiter_bytes():
            buf.extend(chunk)
            if len(buf) > limit:
                raise ssrf.FetchTooLarge()
        text = decode_body(bytes(buf), response.charset_encoding)
        valid, err = check_text(text)
        return FetchResponse(
            url=url,
            final_url=final_url,
            status_code=response.status_code,
            content_type=response.headers.get("content-type"),
            size_bytes=len(buf),
            is_valid_json=valid,
            parse_error=err,
            content=text,
        )
