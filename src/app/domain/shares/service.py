from __future__ import annotations

import hmac
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.db.models import HistorySource, Share, ShareComment, ShareKind, User
from app.domain.history.service import HistoryService
from app.domain.shares.repository import ShareRepository
from app.domain.shares.schemas import (
    CommentOut,
    CreateCommentRequest,
    CreateShareRequest,
    ShareCreated,
    ShareDetail,
    ShareListItem,
    ShareMeta,
    SharePage,
)
from app.lib.errors import Conflict, NotFound, PermissionDenied, Unprocessable
from app.lib.json_utils import make_preview, prepare_content
from app.lib.security import (
    generate_slug,
    hash_password,
    random_token,
    token_hash,
    verify_password,
)

EXPIRES = {
    "1h": timedelta(hours=1),
    "1d": timedelta(days=1),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
SLUG_ATTEMPTS = 5
MAX_COMMENTS_PER_SHARE = 200


def not_found() -> NotFound:
    return NotFound("Share not found or expired.", code="share_not_found")


def _not_expired(now: datetime):  # type: ignore[no-untyped-def]
    return (Share.expires_at.is_(None)) | (Share.expires_at > now)


class ShareService:
    def __init__(self, db: AsyncSession, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.repo = ShareRepository(session=db)

    def share_url(self, slug: str) -> str:
        return f"{self.settings.frontend_url.rstrip('/')}/s/{slug}"

    async def create(self, data: CreateShareRequest, user: User | None) -> ShareCreated:
        if data.expires_in == "never" and user is None:
            raise Unprocessable(
                "Anonymous users cannot create shares that never expire.",
                code="never_requires_auth",
            )
        left, left_size = prepare_content(data.content, self.settings.max_document_bytes)
        right: str | None = None
        right_size = 0
        if data.kind == "compare":
            if data.content_right is None:
                raise Unprocessable(
                    "content_right is required for compare shares.", code="content_right_required"
                )
            right, right_size = prepare_content(
                data.content_right, self.settings.max_document_bytes, field="content_right"
            )
        total = left_size + right_size
        if total > self.settings.max_document_bytes:
            from app.lib.errors import PayloadTooLarge

            raise PayloadTooLarge(f"Document exceeds {self.settings.max_document_bytes} bytes.")

        now = datetime.now(UTC)
        delta = EXPIRES.get(data.expires_in)
        expires_at = now + delta if delta else None
        delete_token: str | None = None
        delete_hash: str | None = None
        if user is None:
            delete_token = random_token(32)
            delete_hash = token_hash(delete_token)

        share: Share | None = None
        for _ in range(SLUG_ATTEMPTS):
            candidate = Share(
                slug=generate_slug(12),
                kind=ShareKind(data.kind),
                title=data.title or None,
                content=left,
                content_right=right,
                size_bytes=total,
                owner_id=user.id if user else None,
                delete_token_hash=delete_hash,
                expires_at=expires_at,
                password_hash=hash_password(data.password) if data.password else None,
                burn_after_read=data.burn_after_read,
                comments_enabled=data.comments_enabled,
            )
            try:
                async with self.db.begin_nested():
                    self.db.add(candidate)
                    await self.db.flush()
            except IntegrityError:
                continue
            share = candidate
            break
        if share is None:  # pragma: no cover - astronomically unlikely
            raise Unprocessable("Could not allocate a unique slug.", code="slug_collision")

        if user is not None and data.save_to_history:
            source = HistorySource.COMPARE if data.kind == "compare" else HistorySource.SHARE
            await HistoryService(self.db, self.settings).upsert(
                user_id=user.id,
                content=left,
                source=source,
                title=data.title or None,
                share_id=share.id,
            )
        await self.db.refresh(share)
        return ShareCreated(
            slug=share.slug,
            url=self.share_url(share.slug),
            kind=share.kind.value,
            expires_at=share.expires_at,
            created_at=share.created_at,
            delete_token=delete_token,
        )

    @staticmethod
    def _detail(share: Share, user: User | None) -> ShareDetail:
        return ShareDetail(
            slug=share.slug,
            kind=share.kind.value,
            title=share.title,
            content=share.content,
            content_right=share.content_right,
            size_bytes=share.size_bytes,
            created_at=share.created_at,
            expires_at=share.expires_at,
            view_count=share.view_count,
            is_owner=bool(user and share.owner_id == user.id),
            comments_enabled=share.comments_enabled,
            password_protected=share.password_hash is not None,
            burn_after_read=share.burn_after_read,
        )

    async def _get(self, slug: str) -> Share:
        share = (
            await self.db.execute(
                select(Share).where(Share.slug == slug, _not_expired(datetime.now(UTC)))
            )
        ).scalar_one_or_none()
        if share is None:
            raise not_found()
        return share

    @staticmethod
    def _check_password(share: Share, password: str | None) -> None:
        if share.password_hash is None:
            return
        if not password:
            raise PermissionDenied("This share is password protected.", code="password_required")
        if not verify_password(password, share.password_hash):
            raise PermissionDenied("Wrong password.", code="invalid_password")

    async def meta(self, slug: str) -> ShareMeta:
        share = await self._get(slug)
        return ShareMeta(
            slug=share.slug,
            kind=share.kind.value,
            title=share.title,
            created_at=share.created_at,
            expires_at=share.expires_at,
            password_protected=share.password_hash is not None,
            burn_after_read=share.burn_after_read,
            comments_enabled=share.comments_enabled,
        )

    async def view(self, slug: str, user: User | None) -> ShareDetail:
        """Plain read. Locked shares (password / burn-after-read) must go through ``open``."""
        now = datetime.now(UTC)
        share = await self._get(slug)
        if share.password_hash is not None or share.burn_after_read:
            raise PermissionDenied(
                "This share must be opened explicitly (password or one-time link).",
                code="share_locked",
            )
        stmt = (
            update(Share)
            .where(Share.id == share.id)
            .values(view_count=Share.view_count + 1, last_viewed_at=now)
            .returning(Share)
            .execution_options(synchronize_session=False)
        )
        await self.db.execute(stmt)
        await self.db.refresh(share)  # the row was loaded earlier: pick up the new view_count
        return self._detail(share, user)

    async def open(self, slug: str, password: str | None, user: User | None) -> ShareDetail:
        """Read a share, checking its password; one-time links are destroyed after this read."""
        share = await self._get(slug)
        self._check_password(share, password)
        now = datetime.now(UTC)
        if share.burn_after_read:
            detail = self._detail(share, user)
            detail.view_count += 1
            # delete atomically: a concurrent second reader finds nothing
            deleted = (
                await self.db.execute(delete(Share).where(Share.id == share.id).returning(Share.id))
            ).scalar_one_or_none()
            if deleted is None:
                raise not_found()
            return detail
        stmt = (
            update(Share)
            .where(Share.id == share.id)
            .values(view_count=Share.view_count + 1, last_viewed_at=now)
            .returning(Share)
            .execution_options(synchronize_session=False)
        )
        await self.db.execute(stmt)
        await self.db.refresh(share)
        return self._detail(share, user)

    # ----------------------------------------------------------------- comments

    @staticmethod
    def _comment_out(c: ShareComment) -> CommentOut:
        return CommentOut(
            id=str(c.id), path=c.path, author=c.author, text=c.text, created_at=c.created_at
        )

    async def list_comments(self, slug: str, password: str | None) -> list[CommentOut]:
        share = await self._get(slug)
        self._check_password(share, password)
        rows = (
            await self.db.execute(
                select(ShareComment)
                .where(ShareComment.share_id == share.id)
                .order_by(ShareComment.created_at, ShareComment.id)
            )
        ).scalars()
        return [self._comment_out(c) for c in rows]

    async def add_comment(
        self, slug: str, data: CreateCommentRequest, password: str | None
    ) -> CommentOut:
        share = await self._get(slug)
        self._check_password(share, password)
        if not share.comments_enabled:
            raise PermissionDenied(
                "Comments are disabled for this share.", code="comments_disabled"
            )
        count = (
            await self.db.execute(
                select(func.count())
                .select_from(ShareComment)
                .where(ShareComment.share_id == share.id)
            )
        ).scalar_one()
        if count >= MAX_COMMENTS_PER_SHARE:
            raise Conflict("Too many comments on this share.", code="too_many_comments")
        comment = ShareComment(
            share_id=share.id,
            path=data.path or None,
            author=data.author.strip(),
            text=data.text.strip(),
        )
        self.db.add(comment)
        await self.db.flush()
        await self.db.refresh(comment)
        return self._comment_out(comment)

    async def delete_comment(
        self, slug: str, comment_id: uuid.UUID, user: User | None, delete_token: str | None
    ) -> None:
        share = await self._get(slug)
        allowed = bool(user and share.owner_id is not None and share.owner_id == user.id)
        if not allowed and delete_token and share.delete_token_hash:
            allowed = hmac.compare_digest(share.delete_token_hash, token_hash(delete_token))
        if not allowed:
            raise PermissionDenied()
        comment = (
            await self.db.execute(
                select(ShareComment).where(
                    ShareComment.id == comment_id, ShareComment.share_id == share.id
                )
            )
        ).scalar_one_or_none()
        if comment is None:
            raise NotFound("Comment not found.", code="comment_not_found")
        await self.db.delete(comment)
        await self.db.flush()

    async def delete(self, slug: str, user: User | None, delete_token: str | None) -> None:
        now = datetime.now(UTC)
        share = (
            await self.db.execute(select(Share).where(Share.slug == slug, _not_expired(now)))
        ).scalar_one_or_none()
        if share is None:
            raise not_found()
        allowed = bool(user and share.owner_id is not None and share.owner_id == user.id)
        if not allowed and delete_token and share.delete_token_hash:
            allowed = hmac.compare_digest(share.delete_token_hash, token_hash(delete_token))
        if not allowed:
            raise PermissionDenied()
        await self.db.delete(share)
        await self.db.flush()

    async def list_for_user(self, user_id: uuid.UUID, limit: int, offset: int) -> SharePage:
        now = datetime.now(UTC)
        cond = (Share.owner_id == user_id, _not_expired(now))
        total = (
            await self.db.execute(select(func.count()).select_from(Share).where(*cond))
        ).scalar_one()
        rows = (
            await self.db.execute(
                select(Share, func.left(Share.content, 1000).label("head"))
                .where(*cond)
                .order_by(Share.created_at.desc(), Share.id.desc())
                .limit(limit)
                .offset(offset)
            )
        ).all()
        items = [
            ShareListItem(
                slug=s.slug,
                url=self.share_url(s.slug),
                kind=s.kind.value,
                title=s.title,
                preview=make_preview(head),
                size_bytes=s.size_bytes,
                created_at=s.created_at,
                expires_at=s.expires_at,
                view_count=s.view_count,
            )
            for s, head in rows
        ]
        return SharePage(items=items, total=total, limit=limit, offset=offset)
