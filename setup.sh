#!/usr/bin/env bash
# Build, start, migrate, and smoke-test the local Slink development stack.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR"

pass=0
fail=0
ok() { printf '  [ok] %s\n' "$1"; pass=$((pass + 1)); }
warn() { printf '  [warn] %s\n' "$1"; }
error() { printf '  [error] %s\n' "$1"; fail=$((fail + 1)); }

printf '\nSlink first-run setup\n\n'
command -v docker >/dev/null 2>&1 || {
  error "Docker is required"
  exit 1
}
docker info >/dev/null 2>&1 || {
  error "Docker is not running"
  exit 1
}
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  error "Docker Compose is required"
  exit 1
fi
[[ -f .env ]] || {
  error ".env is missing; copy .env.example and replace every required value"
  exit 1
}
ok "Prerequisites available"

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/slink-setup.XXXXXX")"
chmod 0700 "$temporary_dir"
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

printf '\nBuilding and starting services\n'
$COMPOSE build
$COMPOSE up -d
ok "Services started"

printf '\nWaiting for PostgreSQL\n'
database_ready=0
for _ in $(seq 1 30); do
  if $COMPOSE exec -T db pg_isready -U slink -d slink -q >/dev/null 2>&1; then
    database_ready=1
    break
  fi
  sleep 1
done
[[ "$database_ready" -eq 1 ]] || {
  error "PostgreSQL did not become ready"
  exit 1
}
ok "PostgreSQL healthy"

printf '\nWaiting for API and entrypoint migrations\n'
api_ready=0
for _ in $(seq 1 30); do
  if curl --fail --silent http://127.0.0.1:8000/api/health >/dev/null; then
    api_ready=1
    break
  fi
  sleep 2
done
[[ "$api_ready" -eq 1 ]] || {
  error "API did not become ready"
  exit 1
}
ok "API healthy; entrypoint migrations completed"

printf '\nRunning authenticated smoke checks\n'
login_request="$temporary_dir/login.json"
login_response="$temporary_dir/login-response.json"
auth_header="$temporary_dir/authorization.txt"

$COMPOSE exec -T api python -c \
  'import json, os; print(json.dumps({"username": os.environ["ADMIN_USERNAME"], "password": os.environ["ADMIN_PASSWORD"]}))' \
  > "$login_request"
chmod 0600 "$login_request"

if curl --fail --silent --show-error \
  --request POST \
  --header "Content-Type: application/json" \
  --data-binary "@$login_request" \
  --output "$login_response" \
  http://127.0.0.1:8000/api/auth/login; then
  rm -f "$login_request"
else
  rm -f "$login_request"
  error "Admin login failed; inspect API logs"
  exit 1
fi

python3 - "$login_response" "$auth_header" <<'PY'
import json
import os
from pathlib import Path
import sys

payload = json.loads(Path(sys.argv[1]).read_text())
token = payload.get("access_token")
if not isinstance(token, str) or not token:
    raise SystemExit("login response did not contain an access token")
Path(sys.argv[2]).write_text(f"Authorization: Bearer {token}\n")
os.chmod(sys.argv[2], 0o600)
PY
rm -f "$login_response"
ok "Admin login succeeded"

sources_response="$temporary_dir/sources.json"
curl --fail --silent --show-error \
  --header "@$auth_header" \
  --output "$sources_response" \
  http://127.0.0.1:8000/api/sources
source_count="$(python3 - "$sources_response" <<'PY'
import json
from pathlib import Path
import sys
print(len(json.loads(Path(sys.argv[1]).read_text())))
PY
)"
ok "Collectors registered: $source_count"

keyword_count="$(curl --fail --silent --show-error \
  --header "@$auth_header" \
  http://127.0.0.1:8000/api/keywords \
  | python3 -c 'import json, sys; print(len(json.load(sys.stdin)))')"
ok "Keywords in watchlist: $keyword_count"

frontend_status="$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:5180/)"
if [[ "$frontend_status" == "200" ]]; then
  ok "Frontend reachable"
else
  warn "Frontend returned HTTP $frontend_status"
fi

printf '\n%s checks passed; %s failed.\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
