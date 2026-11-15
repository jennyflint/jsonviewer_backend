"""OAuth providers (Google OIDC, GitHub). Token exchange uses Authlib's async httpx client."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.jose import JsonWebKey, jwt

from app.config import Settings

GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"]
GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"  # noqa: S105
GITHUB_API = "https://api.github.com"
JWKS_TTL_SECONDS = 3600
HTTP_TIMEOUT = 10.0


class OAuthError(Exception):
    """Raised for any failure during the OAuth exchange. ``code`` is shown to the frontend."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


@dataclass(slots=True)
class Identity:
    provider: str
    provider_user_id: str
    email: str | None
    email_verified: bool
    name: str | None
    avatar_url: str | None
    login: str | None = None


_jwks_cache: dict[str, Any] = {"expires": 0.0, "keys": None}


def reset_jwks_cache() -> None:
    _jwks_cache.update(expires=0.0, keys=None)


async def _google_jwks() -> Any:
    now = time.monotonic()
    if _jwks_cache["keys"] is not None and _jwks_cache["expires"] > now:
        return _jwks_cache["keys"]
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        resp = await client.get(GOOGLE_JWKS_URL)
        resp.raise_for_status()
        keys = JsonWebKey.import_key_set(resp.json())
    _jwks_cache.update(keys=keys, expires=now + JWKS_TTL_SECONDS)
    return keys


class Provider:
    name: str
    authorize_url: str
    token_url: str
    scope: str

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def client_id(self) -> str:
        return getattr(self.settings, f"{self.name}_client_id")  # type: ignore[no-any-return]

    @property
    def client_secret(self) -> str:
        return getattr(self.settings, f"{self.name}_client_secret")  # type: ignore[no-any-return]

    @property
    def redirect_uri(self) -> str:
        return f"{self.settings.oauth_redirect_base_url.rstrip('/')}/{self.name}/callback"

    def client(self) -> AsyncOAuth2Client:
        return AsyncOAuth2Client(
            client_id=self.client_id,
            client_secret=self.client_secret,
            scope=self.scope,
            redirect_uri=self.redirect_uri,
            code_challenge_method="S256",
            timeout=HTTP_TIMEOUT,
        )

    def authorization_url(self, state: str, verifier: str, nonce: str | None) -> str:
        raise NotImplementedError

    async def identify(self, code: str, verifier: str, nonce: str | None) -> Identity:
        raise NotImplementedError

    async def _token(self, client: AsyncOAuth2Client, code: str, verifier: str) -> dict[str, Any]:
        try:
            token = await client.fetch_token(
                self.token_url,
                code=code,
                code_verifier=verifier,
                headers={"Accept": "application/json"},
            )
        except Exception as exc:
            raise OAuthError("token_exchange_failed", type(exc).__name__) from None
        if not isinstance(token, dict) or ("access_token" not in token and "id_token" not in token):
            raise OAuthError("token_exchange_failed")
        return dict(token)


class GoogleProvider(Provider):
    name = "google"
    authorize_url = GOOGLE_AUTHORIZE_URL
    token_url = GOOGLE_TOKEN_URL
    scope = "openid email profile"

    def authorization_url(self, state: str, verifier: str, nonce: str | None) -> str:
        client = self.client()
        url, _ = client.create_authorization_url(
            self.authorize_url,
            state=state,
            code_verifier=verifier,
            nonce=nonce,
            response_type="code",
            prompt="select_account",
        )
        return str(url)

    async def identify(self, code: str, verifier: str, nonce: str | None) -> Identity:
        async with self.client() as client:
            token = await self._token(client, code, verifier)
        id_token = token.get("id_token")
        if not id_token:
            raise OAuthError("invalid_identity", "missing id_token")
        try:
            keys = await _google_jwks()
            claims = jwt.decode(
                id_token,
                keys,
                claims_options={
                    "iss": {"essential": True, "values": GOOGLE_ISSUERS},
                    "aud": {"essential": True, "value": self.client_id},
                    "exp": {"essential": True},
                    "sub": {"essential": True},
                    "nonce": {"essential": True, "value": nonce},
                },
            )
            claims.validate()
        except OAuthError:
            raise
        except Exception as exc:
            raise OAuthError("invalid_identity", type(exc).__name__) from None
        verified = claims.get("email_verified")
        return Identity(
            provider="google",
            provider_user_id=str(claims["sub"]),
            email=claims.get("email"),
            email_verified=verified is True or verified == "true",
            name=claims.get("name"),
            avatar_url=claims.get("picture"),
        )


class GitHubProvider(Provider):
    name = "github"
    authorize_url = GITHUB_AUTHORIZE_URL
    token_url = GITHUB_TOKEN_URL
    scope = "read:user user:email"

    def authorization_url(self, state: str, verifier: str, nonce: str | None) -> str:
        client = self.client()
        url, _ = client.create_authorization_url(
            self.authorize_url, state=state, code_verifier=verifier, response_type="code"
        )
        return str(url)

    async def identify(self, code: str, verifier: str, nonce: str | None) -> Identity:
        async with self.client() as client:
            token = await self._token(client, code, verifier)
        access = token.get("access_token")
        if not access:
            raise OAuthError("token_exchange_failed")
        headers = {
            "Authorization": f"Bearer {access}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "JSONViewer/1.0",
        }
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=headers) as http:
                user_resp = await http.get(f"{GITHUB_API}/user")
                user_resp.raise_for_status()
                user = user_resp.json()
                emails_resp = await http.get(f"{GITHUB_API}/user/emails")
                emails_resp.raise_for_status()
                emails = emails_resp.json()
        except (httpx.HTTPError, ValueError):
            raise OAuthError("invalid_identity", "github api failure") from None
        if not isinstance(user, dict) or "id" not in user:
            raise OAuthError("invalid_identity")
        email: str | None = None
        for item in emails if isinstance(emails, list) else []:
            if item.get("primary") and item.get("verified"):
                email = item.get("email")
                break
        return Identity(
            provider="github",
            provider_user_id=str(user["id"]),
            email=email,
            email_verified=email is not None,
            name=user.get("name") or user.get("login"),
            avatar_url=user.get("avatar_url"),
            login=user.get("login"),
        )


def get_provider(name: str, settings: Settings) -> Provider | None:
    if not settings.provider_enabled(name):
        return None
    return {"google": GoogleProvider, "github": GitHubProvider}[name](settings)
