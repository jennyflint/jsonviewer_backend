from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime

import structlog
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.db.models import Session, Share

logger = structlog.get_logger()
CLEANUP_LOCK_ID = 7_265_001  # arbitrary application-wide advisory lock key


async def run_cleanup(engine: AsyncEngine) -> dict[str, int] | None:
    """Delete expired shares and sessions. Returns None when another instance holds the lock."""
    async with engine.connect() as conn:
        locked = (
            await conn.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": CLEANUP_LOCK_ID})
        ).scalar_one()
        await conn.commit()
        if not locked:
            return None
        try:
            now = datetime.now(UTC)
            async with AsyncSession(bind=conn, expire_on_commit=False) as db:
                shares = await db.execute(
                    delete(Share).where(Share.expires_at.is_not(None), Share.expires_at < now)
                )
                sessions = await db.execute(delete(Session).where(Session.expires_at < now))
                await db.commit()
            result = {"shares": shares.rowcount or 0, "sessions": sessions.rowcount or 0}  # type: ignore[attr-defined]
            logger.info("cleanup_done", **result)
            return result
        finally:
            await conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": CLEANUP_LOCK_ID})
            await conn.commit()


async def cleanup_loop(engine: AsyncEngine, interval_seconds: int) -> None:
    while True:
        try:
            await run_cleanup(engine)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("cleanup_failed")
        await asyncio.sleep(interval_seconds)


async def stop_task(task: asyncio.Task[None]) -> None:
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
