# JSON Viewer API

Backend for **JSON Viewer**: a Litestar + PostgreSQL REST API under `/api`.

- Share JSON documents (and two-document comparisons) by short link, no login required
- Fetch JSON from a remote URL through an **SSRF-protected** server-side proxy
- **OAuth-only** login (Google, GitHub), no passwords
- Personal **history** (authenticated users only)
- **Duplicate detection**: duplicate keys, values, subtrees and duplicates by field

Every feature except history works without authentication. Logging in adds history and ownership of shares.

Stack: Python 3.12, Litestar 2, SQLAlchemy 2 (async) + asyncpg + advanced-alchemy, Alembic, PostgreSQL 16, pgAdmin 4,
msgspec, httpx, Authlib, structlog, uv, ruff, mypy `--strict`, pytest.

## Prerequisites

- Docker with the Compose plugin (to run the stack)
- [uv](https://docs.astral.sh/uv/) and Python 3.12 (to develop and test locally)

## Quick start

```bash
cp .env.example .env          # then set SECRET_KEY to a long random value
docker compose up -d --build
```

Then open:

- API docs (Scalar): http://localhost:8000/api/docs (Swagger UI: `/api/docs/swagger`, schema: `/api/openapi.json`)
- pgAdmin: http://localhost:5050 (log in with `PGADMIN_DEFAULT_EMAIL` / `PGADMIN_DEFAULT_PASSWORD`;
  the `JSON Viewer (db)` server is pre-registered, its password is `POSTGRES_PASSWORD`)

The `api` container waits for the database, runs `alembic upgrade head`, then starts uvicorn
(`UVICORN_WORKERS` workers). `GET /api/health` is its Docker healthcheck.

## Creating the OAuth apps

The redirect URI goes through the **frontend origin**, because the frontend's nginx proxies `/api/*` to this
service, so the browser sees a single origin. The callback is `{OAUTH_REDIRECT_BASE_URL}/{provider}/callback`.

**Google** (Google Cloud Console)

1. APIs & Services → OAuth consent screen: configure it (External is fine for testing).
2. Credentials → Create credentials → OAuth client ID → *Web application*.
3. Authorized redirect URI: `http://localhost:3000/api/auth/google/callback`.
4. Put the values in `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`.

**GitHub**

1. Settings → Developer settings → OAuth Apps → New OAuth App.
2. Authorization callback URL: `http://localhost:3000/api/auth/github/callback`.
3. Put the values in `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`.

A provider whose client id or secret is empty is disabled: it is missing from `GET /api/auth/providers` and its
login endpoint returns `404`.

When running **the API alone** (no frontend proxy), register `http://localhost:8000/api/auth/<provider>/callback`
instead and set `OAUTH_REDIRECT_BASE_URL=http://localhost:8000/api/auth`.

## Joining from the frontend compose project

`docker-compose.yml` creates the network `jsonviewer-net`. The frontend project joins it as an external network
and reaches the API at `http://api:8000`:

```yaml
services:
  web:
    # ...
    networks: [jsonviewer-net]
networks:
  jsonviewer-net:
    external: true
```

and its nginx proxies `/api/` to `http://api:8000` (forwarding `X-Forwarded-For`/`X-Forwarded-Proto`; uvicorn runs
with `--proxy-headers` so rate limits are keyed by the real client IP).

## Development workflow

```bash
# stack with source mounted, one worker, --reload, DB published on 127.0.0.1:5432
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

# local environment
uv sync
export DATABASE_URL=postgresql+asyncpg://jsonviewer:jsonviewer@127.0.0.1:5432/jsonviewer SECRET_KEY=dev-secret-key-123456
uv run alembic upgrade head
uv run alembic revision --autogenerate -m "describe change"      # create a migration (review it!)
uv run uvicorn app.main:app --reload --app-dir src
```

Tests (need Docker: PostgreSQL is started with testcontainers; or point `TEST_DATABASE_URL` at a server, e.g.
`postgresql+asyncpg://jsonviewer:jsonviewer@127.0.0.1:5432/jsonviewer`; the `jsonviewer_test` database is
recreated and migrated with Alembic on every run):

```bash
uv run pytest
uv run pytest --cov=app --cov-report=term-missing
uv run ruff check . && uv run ruff format --check .
uv run mypy src
uv run pip-audit
```

Maintenance: `uv run litestar --app app.main:app cleanup` deletes expired shares and sessions once (the same job
runs every 15 minutes inside the app, guarded by a PostgreSQL advisory lock so only one worker/replica runs it).

## API overview

All paths are prefixed with `/api`. Bodies are JSON; timestamps are ISO-8601 UTC; ids are UUIDs.

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /health` | – | `{"status","db","version"}`; `503` if the DB is down |
| `POST /fetch` | – | Fetch a remote URL (SSRF-protected); returns raw text |
| `POST /shares` | – | Create a share (`single` / `compare`) |
| `GET /shares/{slug}` | – | Read a share (increments `view_count`) |
| `DELETE /shares/{slug}` | owner or `X-Delete-Token` | Delete a share |
| `GET /shares` | required | My shares (`limit` ≤ 100 default 20, `offset`; returns `{items,total,limit,offset}`) |
| `GET /auth/providers` | – | Enabled OAuth providers |
| `GET /auth/{provider}/login?return_to=` | – | Start OAuth (302) |
| `GET /auth/{provider}/callback` | – | OAuth callback (302 to the frontend) |
| `GET /auth/me` | – | `{"user": …}` or `{"user": null}` |
| `POST /auth/logout` | – | Delete the session, clear cookies (204) |
| `GET /auth/sessions`, `DELETE /auth/sessions/{id}`, `DELETE /auth/sessions` | required | List / revoke sessions (the last revokes all but the current) |
| `DELETE /auth/account` | required | Delete the account (shares are kept, `owner_id` → null) |
| `GET/POST /history`, `GET/PATCH/DELETE /history/{id}`, `DELETE /history` | required | History (another user's entry → 404) |
| `POST /analysis/duplicates` | – | Duplicate keys / values / subtrees / by field |
| `POST /analysis/validate` | – | Validity, stats, `has_duplicate_keys` |

JSON paths use `$.key` for identifier-like keys, `$["weird key"]` (JSON-escaped) otherwise, and `[n]` for array
indices.

### Error format

Every error has the same shape:

```json
{ "error": { "code": "share_not_found", "message": "Share not found or expired.", "details": null } }
```

| HTTP | `code` | When |
|---|---|---|
| 401 | `auth_required` | Endpoint needs a session |
| 403 | `forbidden` | Not the owner / wrong or missing delete token |
| 403 | `csrf_failed` | Cookie-authenticated unsafe request without a valid `X-CSRF-Token` |
| 403 | `origin_not_allowed` | Unsafe request with a disallowed `Origin` header |
| 404 | `share_not_found` | Missing **or expired** share |
| 404 | `history_not_found` | No such entry for this user (also for other users' entries) |
| 404 | `session_not_found` | Session id is not yours |
| 404 | `provider_not_found` | Unknown or disabled OAuth provider |
| 404 | `not_found` | Unknown URL |
| 405 | `method_not_allowed` | |
| 413 | `document_too_large` | Content exceeds `MAX_DOCUMENT_BYTES` |
| 413 | `fetch_too_large` | Remote body exceeds `MAX_FETCH_BYTES` |
| 413 | `payload_too_large` | Request body exceeds `MAX_FETCH_BYTES` + 1 MB |
| 422 | `validation_error` | Request validation (`details` = field errors) |
| 422 | `invalid_content` | Content contains NUL bytes |
| 422 | `never_requires_auth` | Anonymous share with `expires_in: "never"` |
| 422 | `content_right_required` | `compare` share without `content_right` |
| 422 | `confirmation_required` | `DELETE /history` without `{"confirm": true}` |
| 422 | `invalid_url` | Bad scheme, userinfo, port or syntax |
| 422 | `blocked_destination` | Target resolves to a non-public address (the IP is never revealed) |
| 422 | `nesting_too_deep` | JSON nesting deeper than 512 |
| 422 | `invalid_array_path` | `by_field.array_path` is invalid or not an array of objects |
| 429 | `rate_limited` | Rate limit hit (`Retry-After` header) |
| 500 | `internal_error` | Unhandled error (generic message; the stack trace is logged with the request id) |
| 502 | `dns_resolution_failed` | Host did not resolve |
| 502 | `upstream_error` | Upstream status ≥ 300 (`details.status`) or connection failure |
| 502 | `too_many_redirects` | More than `FETCH_MAX_REDIRECTS` redirects |
| 503 | `service_unavailable` | Reserved; `/health` itself answers `503` with `db: "error"` |
| 504 | `upstream_timeout` | Remote server too slow |
| 504 | `analysis_timeout` | Analysis exceeded 10 s |

OAuth failures never show an error page: the callback redirects to `{FRONTEND_URL}/login?error=<code>` with
`invalid_state`, `oauth_cancelled`, `token_exchange_failed`, `invalid_identity`, `provider_not_found` or `oauth_failed`.

### Rate limits (per client IP)

`POST /fetch` 20/min · `POST /shares` 30/hour · `POST /analysis/*` 60/min · `/auth/*` 30/min · everything else
300/min (`/health` is exempt). In-memory store by default; `RATE_LIMIT_STORE=redis` + `REDIS_URL` shares counters
between replicas.

### Security notes

- **SSRF**: http/https only, no userinfo, ports 80/443/1024–65535; every resolved address must be globally
  routable (private, loopback, link-local, CGNAT, multicast, reserved, unique-local, IPv4-mapped, NAT64/6to4,
  cloud metadata are rejected; decimal/octal/hex IPv4 forms are normalised first). The connection is made to the
  *validated IP* (custom httpcore network backend) while Host, SNI and certificate verification use the original
  host name, so DNS rebinding cannot swap the target. Redirects are followed manually and re-validated at every hop.
  Responses are streamed with a hard size cap; environment proxies are ignored; client cookies/headers are never
  forwarded.
- **OAuth**: `state` + PKCE (S256) for both providers, `nonce` and full `id_token` verification (JWKS signature,
  `iss`, `aud`, `exp`, `nonce`) for Google; account linking only through *verified* emails; `return_to` must be a
  relative path.
- **Sessions**: random 32-byte token in an `HttpOnly`, `SameSite=Lax` cookie; only its SHA-256 is stored; revocable
  and expiring.
- **CSRF**: double-submit `csrftoken` cookie + `X-CSRF-Token` header for all unsafe requests that carry a session
  cookie (anonymous requests have no ambient credentials); the OAuth callback is exempt; unsafe requests with a
  foreign `Origin` are rejected. The frontend must echo the `csrftoken` cookie in `X-CSRF-Token`.
- Logs never contain document content, OAuth codes, tokens or cookies.

### Behaviour worth knowing

- `POST /shares` has `save_to_history` (default `false`); it only has an effect for authenticated users.
- Duplicate analysis follows `JSON.parse` semantics: for a duplicated key the **last** value is effective, and only
  effective values take part in the value / subtree analysis. Numbers compare by value (`1.0 == 1`) and the original
  lexemes are returned in `lexemes`. `stats.depth` is the container nesting depth. At most 1000 paths are listed per group.
- Nested repeats are suppressed: if two parents are identical, their identical children are not reported as a
  separate group unless they also occur elsewhere (or repeat inside a single parent).
- Syntax errors and the line/column of duplicate keys come from the iterative positional parser
  (`domain/analysis/positional_parser.py`); valid documents are loaded with the C JSON scanner for speed.

## Production notes

- `APP_ENV=production`, `COOKIE_SECURE=true`, a strong random `SECRET_KEY` (the app refuses a `change-me…` key in
  production; it also encrypts the OAuth state cookie), real OAuth credentials.
- Use `RATE_LIMIT_STORE=redis` with several replicas (otherwise limits are per process).
- Do **not** publish PostgreSQL or pgAdmin publicly (the base compose file does not publish the DB; remove the
  pgAdmin service or bind it to localhost / put it behind a VPN in production).
- Terminate TLS in front (nginx) and forward `X-Forwarded-For` / `X-Forwarded-Proto`.
- Set `OPENAPI_ENABLED=false` if you do not want public docs.
