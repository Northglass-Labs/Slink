#!/bin/sh
# API container entrypoint.
#
# Runs database migrations to head BEFORE starting the app server. The app's
# startup hook (bootstrap_admin, seed defaults) reads tables that only exist
# after migrations, so on a fresh database the server must not start until the
# schema is present. Doing this here makes `docker compose up -d` self-contained:
# no separate `alembic upgrade head` step and no first-boot race.
#
# Idempotent: `alembic upgrade head` is a no-op once the schema is current.
set -e

echo "[entrypoint] applying database migrations…"
alembic upgrade head
echo "[entrypoint] migrations at head; starting server."

exec "$@"
