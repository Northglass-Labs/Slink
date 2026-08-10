#!/usr/bin/env bash
# Create an owner-only, client-encrypted Slink PostgreSQL backup.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$REPO_ROOT/backups}"
RETENTION_DAYS_LOCAL="${RETENTION_DAYS_LOCAL:-30}"
AWS_S3_PREFIX="${AWS_S3_PREFIX:-slink-backups/}"
AWS_S3_SSE="${AWS_S3_SSE:-AES256}"
SLINK_COMPOSE_DATABASE="${SLINK_COMPOSE_DATABASE:-0}"
COMPOSE_ARGS=(
  --project-directory "$REPO_ROOT"
  -f "$REPO_ROOT/docker-compose.yml"
  -f "$REPO_ROOT/docker-compose.prod.yml"
)

log() {
  printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 3
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

for variable in PGUSER PGDATABASE; do
  value="${!variable:-}"
  [[ -n "$value" ]] || fail "set $variable before running the backup"
done
[[ "$SLINK_COMPOSE_DATABASE" == "0" || "$SLINK_COMPOSE_DATABASE" == "1" ]] \
  || fail "SLINK_COMPOSE_DATABASE must be 0 or 1"

if [[ "$SLINK_COMPOSE_DATABASE" == "1" ]]; then
  command -v docker >/dev/null 2>&1 || fail "docker is required for Compose mode"
  docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
  dump_command=(docker compose "${COMPOSE_ARGS[@]}" exec -T db pg_dump -U "$PGUSER" -d "$PGDATABASE")
else
  [[ -n "${PGHOST:-}" ]] || fail "set PGHOST before running the backup"
  if [[ -z "${PGPASSWORD:-}" && -z "${PGPASSFILE:-}" ]]; then
    fail "set PGPASSWORD or a mode-0600 PGPASSFILE"
  fi
  if [[ -n "${PGPASSFILE:-}" ]]; then
    check_private_file "$PGPASSFILE" "PGPASSFILE"
  fi
  command -v pg_dump >/dev/null 2>&1 || fail "pg_dump is required"
  dump_command=(pg_dump)
fi
[[ -n "${BACKUP_AGE_RECIPIENT:-}" ]] || fail "set BACKUP_AGE_RECIPIENT"
[[ "$RETENTION_DAYS_LOCAL" =~ ^[0-9]+$ ]] || fail "RETENTION_DAYS_LOCAL must be numeric"

command -v age >/dev/null 2>&1 || fail "age is required"

mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

timestamp="$(date -u +%Y%m%d-%H%M%S)"
filename="slink-$timestamp.sql.gz.age"
path="$BACKUP_DIR/$filename"
temporary="$(mktemp "$BACKUP_DIR/.slink-backup.XXXXXX")"
trap 'rm -f "$temporary"' EXIT HUP INT TERM

log "creating encrypted backup $filename"
dump_args=(
  --format=plain
  --no-owner
  --no-privileges
  --clean
  --if-exists
)
if ! "${dump_command[@]}" "${dump_args[@]}" \
  | gzip -9 \
  | age --encrypt --recipient "$BACKUP_AGE_RECIPIENT" --output "$temporary"; then
  log "backup pipeline failed"
  exit 1
fi
chmod 0600 "$temporary"
mv "$temporary" "$path"
trap - EXIT HUP INT TERM
log "encrypted backup complete: $filename"

if [[ -n "${AWS_S3_BUCKET:-}" ]]; then
  command -v aws >/dev/null 2>&1 || fail "AWS_S3_BUCKET is set but aws is unavailable"
  key="${AWS_S3_PREFIX%/}/$filename"
  destination="s3://$AWS_S3_BUCKET/$key"
  upload_args=(
    s3 cp
    --only-show-errors
    --storage-class STANDARD_IA
    --sse "$AWS_S3_SSE"
  )
  if [[ "$AWS_S3_SSE" == "aws:kms" ]]; then
    [[ -n "${AWS_KMS_KEY_ID:-}" ]] || fail "AWS_KMS_KEY_ID is required for aws:kms"
    upload_args+=(--sse-kms-key-id "$AWS_KMS_KEY_ID")
  fi
  if ! aws "${upload_args[@]}" "$path" "$destination"; then
    log "S3 upload failed; encrypted local copy retained"
    exit 2
  fi
  log "S3 upload complete"
fi

log "rotating local backups older than $RETENTION_DAYS_LOCAL days"
find "$BACKUP_DIR" -type f -name 'slink-*.sql.gz.age' \
  -mtime "+$RETENTION_DAYS_LOCAL" -exec rm -f -- {} +

log "backup finished successfully"
