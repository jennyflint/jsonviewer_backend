from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.db.models import OAuthAccount, OAuthProvider, Session, User
from app.domain.auth.providers import Identity
from app.lib.security import random_token, token_hash


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


class AuthService:
    def __init__(self, db: AsyncSession, settings: Settings) -> None:
        self.db = db
        self.settings = settings

    async def resolve_user(self, identity: Identity) -> User:
        """Find, link or create the user for an OAuth identity (race-safe)."""
        for attempt in range(2):
            try:
                async with self.db.begin_nested():
                    return await self._resolve(identity)
            except IntegrityError:
                if attempt == 1:
                    raise
        raise RuntimeError("unreachable")  # pragma: no cover

    async def _resolve(self, identity: Identity) -> User:
        provider = OAuthProvider(identity.provider)
        now = datetime.now(UTC)
        email = identity.email.lower() if identity.email else None
        account = (
            await self.db.execute(
                select(OAuthAccount).where(
                    OAuthAccount.provider == provider,
                    OAuthAccount.provider_user_id == identity.provider_user_id,
                )
            )
        ).scalar_one_or_none()

        if account is not None:
            account_user = (
                await self.db.execute(select(User).where(User.id == account.user_id))
            ).scalar_one()
            account.provider_email = email
            account.provider_login = identity.login
            if identity.name:
                account_user.name = identity.name
            if identity.avatar_url:
                account_user.avatar_url = identity.avatar_url
            if email and identity.email_verified and account_user.email is None:
                taken = (
                    await self.db.execute(select(User.id).where(User.email == email))
                ).scalar_one_or_none()
                if taken is None:
                    account_user.email = email
                    account_user.email_verified = True
            account_user.last_login_at = now
            await self.db.flush()
            return account_user

        user: User | None = None
        if email and identity.email_verified:
            user = (
                await self.db.execute(select(User).where(User.email == email))
            ).scalar_one_or_none()
            if user is not None:
                user.email_verified = True
        if user is None:
            user = User(
                email=email if identity.email_verified else None,
                email_verified=bool(email and identity.email_verified),
                name=identity.name,
                avatar_url=identity.avatar_url,
            )
            self.db.add(user)
            await self.db.flush()
        else:
            user.name = user.name or identity.name
            user.avatar_url = user.avatar_url or identity.avatar_url
        user.last_login_at = now
        self.db.add(
            OAuthAccount(
                user_id=user.id,
                provider=provider,
                provider_user_id=identity.provider_user_id,
                provider_email=email,
                provider_login=identity.login,
            )
        )
        await self.db.flush()
        return user

    async def create_session(self, user: User, user_agent: str | None, ip: str | None) -> str:
        raw = random_token(32)
        now = datetime.now(UTC)
        self.db.add(
            Session(
                user_id=user.id,
                token_hash=token_hash(raw),
                expires_at=now + timedelta(days=self.settings.session_ttl_days),
                last_seen_at=now,
                user_agent=user_agent[:512] if user_agent else None,
                ip=_valid_ip(ip),
            )
        )
        await self.db.flush()
        return raw

    async def list_sessions(self, user_id: uuid.UUID) -> list[Session]:
        now = datetime.now(UTC)
        rows = await self.db.execute(
            select(Session)
            .where(Session.user_id == user_id, Session.expires_at > now)
            .order_by(Session.created_at.desc())
        )
        return list(rows.scalars())

    async def revoke_session(self, user_id: uuid.UUID, session_id: uuid.UUID) -> bool:
        res: Any = await self.db.execute(
            delete(Session).where(Session.id == session_id, Session.user_id == user_id)
        )
        return bool(res.rowcount)

    async def revoke_others(self, user_id: uuid.UUID, keep: Any) -> None:
        await self.db.execute(delete(Session).where(Session.user_id == user_id, Session.id != keep))

    async def delete_by_token(self, raw: str) -> None:
        await self.db.execute(delete(Session).where(Session.token_hash == token_hash(raw)))

    async def delete_account(self, user_id: uuid.UUID) -> None:
        await self.db.execute(delete(User).where(User.id == user_id))
