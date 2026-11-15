#!/bin/sh
set -eu

# 1. Wait for the database
python - <<'PY'
import asyncio, os, sys, time

import asyncpg

dsn = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://")


async def main() -> None:
    deadline = time.monotonic() + 60
    while True:
        try:
            conn = await asyncpg.connect(dsn, timeout=5)
            await conn.close()
            return
        except Exception as exc:  # noqa: BLE001
            if time.monotonic() > deadline:
                print(f"database not reachable: {exc}", file=sys.stderr)
                sys.exit(1)
            print("waiting for database...", flush=True)
            await asyncio.sleep(1)


asyncio.run(main())
PY

# 2. Apply migrations
alembic upgrade head

# 3. Start the server (a custom command, e.g. from the dev override, replaces the default)
if [ "$#" -gt 0 ]; then
    exec "$@"
fi
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers "${UVICORN_WORKERS:-2}" \
    --proxy-headers --forwarded-allow-ips='*'
