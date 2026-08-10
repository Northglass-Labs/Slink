#!/usr/bin/env bash
# Restore a Slink database from an age-encrypted backup without plaintext disk.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"
SLINK_COMPOSE_DATABASE="${SLINK_COMPOSE_DATABASE:-0}"
COMPOSE_ARGS=(
  --project-directory "$REPO_ROOT"
  -f "$REPO_ROOT/docker-compose.yml"
  -f "$REPO_ROOT/docker-compose.prod.yml"
)

usage() {
  printf '%s\n' \
    "Usage: SLINK_RESTORE_OK=1 ./scripts/restore.sh --yes <backup.sql.gz.age>" \
    "Required: PGUSER, PGDATABASE, BACKUP_AGE_IDENTITY_FILE, and either" \
    "          SLINK_COMPOSE_DATABASE=1 or PGHOST plus PGPASSWORD/PGPASSFILE."
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

check_private_file() {
  local path="$1"
  local label="$2"
  local mode
  [[ -r "$path" ]] || fail "$label is not readable"
  if mode="$(stat -f '%Lp' "$path" 2>/dev/null)"; then
    :
  elif mode="$(stat -c '%a' "$path" 2>/dev/null)"; then
    :
  else
    fail "cannot verify permissions for $label"
  fi
  case "$mode" in
    400|600) ;;
    *) fail "$label must be owner-only (mode 0400 or 0600)" ;;
  esac
}

yes=0
backup_file=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) yes=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) printf 'Unknown flag: %s\n' "$1" >&2; usage; exit 1 ;;
    *) backup_file="$1"; shift ;;
  esac
done

[[ "$yes" -eq 1 ]] || { printf 'ERROR: --yes is required\n' >&2; exit 1; }
[[ "${SLINK_RESTORE_OK:-}" == "1" ]] || {
  printf 'ERROR: SLINK_RESTORE_OK=1 is required\n' >&2
  exit 1
}
[[ -r "$backup_file" && "$backup_file" == *.sql.gz.age ]] || {
  printf 'ERROR: readable .sql.gz.age backup is required\n' >&2
  exit 2
}
for variable in PGUSER PGDATABASE BACKUP_AGE_IDENTITY_FILE; do
  value="${!variable:-}"
  [[ -n "$value" ]] || { printf 'ERROR: set %s\n' "$variable" >&2; exit 1; }
done
[[ "$SLINK_COMPOSE_DATABASE" == "0" || "$SLINK_COMPOSE_DATABASE" == "1" ]] \
  || fail "SLINK_COMPOSE_DATABASE must be 0 or 1"
if [[ "$SLINK_COMPOSE_DATABASE" == "1" ]]; then
  command -v docker >/dev/null 2>&1 || fail "docker is required for Compose mode"
  docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
else
  [[ -n "${PGHOST:-}" ]] || fail "set PGHOST"
  [[ -n "${PGPASSWORD:-}" || -n "${PGPASSFILE:-}" ]] \
    || fail "set PGPASSWORD or PGPASSFILE"
  [[ -n "${PGPASSFILE:-}" ]] && check_private_file "$PGPASSFILE" "PGPASSFILE"
  command -v psql >/dev/null 2>&1 || fail "psql is required"
fi
check_private_file "$BACKUP_AGE_IDENTITY_FILE" "BACKUP_AGE_IDENTITY_FILE"
[[ "$PGDATABASE" =~ ^[A-Za-z_][A-Za-z0-9_$]*$ ]] || {
  printf 'ERROR: PGDATABASE contains unsupported characters\n' >&2
  exit 1
}

command -v age >/dev/null 2>&1 || { printf 'ERROR: age is required\n' >&2; exit 1; }

run_psql_admin() {
  if [[ "$SLINK_COMPOSE_DATABASE" == "1" ]]; then
    docker compose "${COMPOSE_ARGS[@]}" exec -T db \
      psql -U "$PGUSER" -d postgres "$@"
  else
    PGDATABASE=postgres psql "$@"
  fi
}

run_psql_target() {
  if [[ "$SLINK_COMPOSE_DATABASE" == "1" ]]; then
    docker compose "${COMPOSE_ARGS[@]}" exec -T db \
      psql -U "$PGUSER" -d "$target_db" "$@"
  else
    PGDATABASE="$target_db" psql "$@"
  fi
}

printf '\nDANGER: this will replace database %s from %s\n' "$PGDATABASE" "$backup_file"
read -r -p "Type the database name to confirm: " confirmation
[[ "$confirmation" == "$PGDATABASE" ]] || {
  printf 'Confirmation did not match; aborting\n' >&2
  exit 1
}

target_db="$PGDATABASE"
terminate_sql="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$target_db' AND pid <> pg_backend_pid();"
run_psql_admin -v ON_ERROR_STOP=1 -c "$terminate_sql" >/dev/null || true
run_psql_admin -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS \"$target_db\";" >/dev/null
run_psql_admin -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$target_db\";" >/dev/null

if ! age --decrypt --identity "$BACKUP_AGE_IDENTITY_FILE" "$backup_file" \
  | gunzip \
  | run_psql_target -v ON_ERROR_STOP=1; then
  printf 'ERROR: restore failed\n' >&2
  exit 3
fi

printf 'Restore complete; verify health and detection counts.\n'
