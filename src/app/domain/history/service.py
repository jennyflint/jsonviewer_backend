from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.db.models import HistoryEntry, HistorySource, Share
from app.domain.history.repository import HistoryRepository
from app.domain.history.schemas import HistoryDetail, HistoryItem, HistoryPage
from app.lib.errors import NotFound
from app.lib.json_utils import auto_title, content_hash, make_preview, prepare_content

SORT_COLUMNS: dict[str, Any] = {
    "updated_at": HistoryEntry.updated_at,
    "created_at": HistoryEntry.created_at,
    "title": HistoryEntry.title,
    "size": HistoryEntry.size_bytes,
}


def not_found() -> NotFound:
    return NotFound("History entry not found.", code="history_not_found")


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class HistoryService:
    def __init__(self, db: AsyncSession, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.repo = HistoryRepository(session=db)

    # ---- writes -------------------------------------------------------------------------
    async def upsert(
        self,
        *,
        user_id: uuid.UUID,
        content: str,
        source: HistorySource,
        title: str | None = None,
        source_url: str | None = None,
        share_id: uuid.UUID | None = None,
    ) -> tuple[HistoryEntry, bool]:
        """Create or refresh an entry keyed by (user_id, content_hash). Returns (entry, created)."""
        text, size = prepare_content(content, self.settings.max_document_bytes)
        digest, valid = content_hash(text)
        existing = await self._find_by_hash(user_id, digest)
        created = False
        if existing is None:
            entry = HistoryEntry(
                user_id=user_id,
                title=(title or auto_title(text, size, source_url))[:200],
                content=text,
                content_hash=digest,
                is_valid_json=valid,
                size_bytes=size,
                source=source,
                source_url=source_url,
                share_id=share_id,
            )
            try:
                async with self.db.begin_nested():
                    self.db.add(entry)
                    await self.db.flush()
                created = True
            except IntegrityError:  # concurrent insert of the same content
                existing = await self._find_by_hash(user_id, digest)
        if not created:
            assert existing is not None
            entry = existing
            entry.updated_at = datetime.now(UTC)
            entry.source = source
            entry.source_url = source_url
            if title:
                entry.title = title[:200]
            if share_id is not None:
                entry.share_id = share_id
            await self.db.flush()
        else:
            await self._enforce_quota(user_id)
        await self.db.refresh(entry)
        return entry, created

    async def _find_by_hash(self, user_id: uuid.UUID, digest: str) -> HistoryEntry | None:
        return (
            await self.db.execute(
                select(HistoryEntry).where(
                    HistoryEntry.user_id == user_id, HistoryEntry.content_hash == digest
                )
            )
        ).scalar_one_or_none()

    async def _enforce_quota(self, user_id: uuid.UUID) -> None:
        limit = self.settings.history_max_entries_per_user
        total = (
            await self.db.execute(
                select(func.count())
                .select_from(HistoryEntry)
                .where(HistoryEntry.user_id == user_id)
            )
        ).scalar_one()
        excess = total - limit
        if excess <= 0:
            return
        oldest = (
            select(HistoryEntry.id)
            .where(HistoryEntry.user_id == user_id, HistoryEntry.pinned.is_(False))
            .order_by(HistoryEntry.updated_at.asc(), HistoryEntry.id.asc())
            .limit(excess)
        )
        await self.db.execute(
            delete(HistoryEntry)
            .where(HistoryEntry.id.in_(oldest))
            .execution_options(synchronize_session=False)
        )

    async def update(
        self, user_id: uuid.UUID, entry_id: uuid.UUID, title: str | None, pinned: bool | None
    ) -> HistoryDetail:
        entry = await self._get_owned(user_id, entry_id)
        if title is not None:
            entry.title = title
        if pinned is not None:
            entry.pinned = pinned
        entry.updated_at = datetime.now(UTC)
        await self.db.flush()
        await self.db.refresh(entry)
        return await self.detail(entry)

    async def delete(self, user_id: uuid.UUID, entry_id: uuid.UUID) -> None:
        entry = await self._get_owned(user_id, entry_id)
        await self.db.delete(entry)
        await self.db.flush()

    async def clear(self, user_id: uuid.UUID) -> None:
        await self.db.execute(delete(HistoryEntry).where(HistoryEntry.user_id == user_id))

    # ---- reads --------------------------------------------------------------------------
    async def _get_owned(self, user_id: uuid.UUID, entry_id: uuid.UUID) -> HistoryEntry:
        entry = (
            await self.db.execute(
                select(HistoryEntry).where(
                    HistoryEntry.id == entry_id, HistoryEntry.user_id == user_id
                )
            )
        ).scalar_one_or_none()
        if entry is None:
            raise not_found()
        return entry

    async def get(self, user_id: uuid.UUID, entry_id: uuid.UUID) -> HistoryDetail:
        return await self.detail(await self._get_owned(user_id, entry_id))

    async def detail(self, entry: HistoryEntry, deduplicated: bool | None = None) -> HistoryDetail:
        slug: str | None = None
        if entry.share_id:
            slug = (
                await self.db.execute(select(Share.slug).where(Share.id == entry.share_id))
            ).scalar_one_or_none()
        return HistoryDetail(
            id=str(entry.id),
            title=entry.title,
            content=entry.content,
            preview=make_preview(entry.content),
            size_bytes=entry.size_bytes,
            is_valid_json=entry.is_valid_json,
            source=entry.source.value,
            source_url=entry.source_url,
            share_slug=slug,
            pinned=entry.pinned,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            deduplicated=deduplicated,
        )

    async def list_entries(
        self,
        user_id: uuid.UUID,
        *,
        q: str | None,
        source: str | None,
        pinned: bool | None,
        limit: int,
        offset: int,
        sort: str | None,
        order: str,
    ) -> HistoryPage:
        conds: list[Any] = [HistoryEntry.user_id == user_id]
        if source:
            conds.append(HistoryEntry.source == HistorySource(source))
        if pinned is not None:
            conds.append(HistoryEntry.pinned.is_(pinned))
        rank = None
        q = q.strip() if q else None
        if q:
            tsq = func.websearch_to_tsquery("simple", q)
            conds.append(
                or_(
                    HistoryEntry.search_vector.op("@@")(tsq),
                    HistoryEntry.title.ilike(f"%{_escape_like(q)}%", escape="\\"),
                )
            )
            rank = func.ts_rank(HistoryEntry.search_vector, tsq)

        total = (
            await self.db.execute(select(func.count()).select_from(HistoryEntry).where(*conds))
        ).scalar_one()

        stmt: Select[Any] = (
            select(
                HistoryEntry,
                func.left(HistoryEntry.content, 1000).label("head"),
                Share.slug.label("share_slug"),
            )
            .options(*self._no_content())
            .outerjoin(Share, Share.id == HistoryEntry.share_id)
            .where(*conds)
        )
        if sort is None and rank is not None:
            stmt = stmt.order_by(rank.desc(), HistoryEntry.updated_at.desc())
        else:
            col = SORT_COLUMNS[sort or "updated_at"]
            stmt = stmt.order_by(
                col.asc() if order == "asc" else col.desc(), HistoryEntry.id.desc()
            )
        rows = (await self.db.execute(stmt.limit(limit).offset(offset))).all()
        items = [
            HistoryItem(
                id=str(e.id),
                title=e.title,
                preview=make_preview(head),
                size_bytes=e.size_bytes,
                is_valid_json=e.is_valid_json,
                source=e.source.value,
                source_url=e.source_url,
                share_slug=slug,
                pinned=e.pinned,
                created_at=e.created_at,
                updated_at=e.updated_at,
            )
            for e, head, slug in rows
        ]
        return HistoryPage(items=items, total=total, limit=limit, offset=offset)

    @staticmethod
    def _no_content() -> list[Any]:
        from sqlalchemy.orm import defer

        return [defer(HistoryEntry.content)]
