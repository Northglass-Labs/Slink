import gzip
import os
from pathlib import Path
import stat
import subprocess

import pytest


pytestmark = pytest.mark.no_db

ROOT = Path(__file__).resolve().parents[2]


def _executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _stub_tools(tmp_path: Path) -> tuple[Path, Path]:
    tools = tmp_path / "bin"
    trace = tmp_path / "trace"
    tools.mkdir()
    trace.mkdir()
    _executable(
        tools / "age",
        """#!/bin/sh
set -eu
mode=encrypt
output=
input=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --decrypt) mode=decrypt; shift ;;
    --output) output=$2; shift 2 ;;
    --identity|--recipient) shift 2 ;;
    *) input=$1; shift ;;
  esac
done
if [ "$mode" = decrypt ]; then
  cat "$input"
else
  cat > "$output"
fi
""",
    )
    _executable(
        tools / "pg_dump",
        """#!/bin/sh
set -eu
printf '%s\n' "$@" > "$TRACE_DIR/pg_dump.args"
printf '%s\n' 'CREATE TABLE release_test (id integer);'
""",
    )
    _executable(
        tools / "psql",
        """#!/bin/sh
set -eu
{
  printf 'PGDATABASE=%s\n' "${PGDATABASE:-}"
  printf '%s\n' "$@"
} >> "$TRACE_DIR/psql.args"
case " $* " in
  *" -c "*) ;;
  *) cat > "$TRACE_DIR/restored.sql" ;;
esac
""",
    )
    return tools, trace


def _add_docker_stub(tools: Path) -> None:
    _executable(
        tools / "docker",
        """#!/bin/sh
set -eu
if [ "${1:-}" = compose ] && [ "${2:-}" = version ]; then
  exit 0
fi
printf '%s\n' "$@" >> "$TRACE_DIR/docker.args"
case " $* " in
  *" pg_dump "*) printf '%s\n' 'CREATE TABLE compose_test (id integer);' ;;
  *" psql "*" -c "*) ;;
  *" psql "*) cat > "$TRACE_DIR/compose-restored.sql" ;;
esac
""",
    )


def _base_env(tools: Path, trace: Path) -> dict[str, str]:
    return {
        **os.environ,
        "PATH": f"{tools}:{os.environ['PATH']}",
        "TRACE_DIR": str(trace),
        "PGHOST": "127.0.0.1",
        "PGUSER": "slink",
        "PGDATABASE": "slink_test",
    }


def test_backup_is_encrypted_owner_only_and_keeps_credentials_off_argv(tmp_path):
    tools, trace = _stub_tools(tmp_path)
    password_file = tmp_path / "pgpass"
    password_file.write_text("127.0.0.1:5432:slink_test:slink:test-only-password\n")
    password_file.chmod(0o600)
    backup_dir = tmp_path / "backups"
    env = {
        **_base_env(tools, trace),
        "PGPASSFILE": str(password_file),
        "BACKUP_DIR": str(backup_dir),
        "BACKUP_AGE_RECIPIENT": "age1testrecipient",
    }

    result = subprocess.run(
        ["/bin/bash", str(ROOT / "scripts/backup.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    backups = list(backup_dir.glob("slink-*.sql.gz.age"))
    assert len(backups) == 1
    assert stat.S_IMODE(backups[0].stat().st_mode) == 0o600
    arguments = (trace / "pg_dump.args").read_text()
    assert "test-only-password" not in arguments
    assert "postgresql://" not in arguments
    assert str(password_file) not in arguments


def test_backup_rejects_group_readable_password_file(tmp_path):
    tools, trace = _stub_tools(tmp_path)
    password_file = tmp_path / "pgpass"
    password_file.write_text("test")
    password_file.chmod(0o640)
    env = {
        **_base_env(tools, trace),
        "PGPASSFILE": str(password_file),
        "BACKUP_DIR": str(tmp_path / "backups"),
        "BACKUP_AGE_RECIPIENT": "age1testrecipient",
    }

    result = subprocess.run(
        ["/bin/bash", str(ROOT / "scripts/backup.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "owner-only" in result.stderr


def test_compose_backup_runs_inside_private_database_container(tmp_path):
    tools, trace = _stub_tools(tmp_path)
    _add_docker_stub(tools)
    env = {
        **_base_env(tools, trace),
        "SLINK_COMPOSE_DATABASE": "1",
        "BACKUP_DIR": str(tmp_path / "backups"),
        "BACKUP_AGE_RECIPIENT": "age1testrecipient",
    }
    env.pop("PGHOST")

    result = subprocess.run(
        ["/bin/bash", str(ROOT / "scripts/backup.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    arguments = (trace / "docker.args").read_text()
    assert "exec\n-T\ndb\npg_dump" in arguments
    assert "password" not in arguments.lower()


def test_restore_streams_decrypted_sql_and_keeps_credentials_off_argv(tmp_path):
    tools, trace = _stub_tools(tmp_path)
    password_file = tmp_path / "pgpass"
    password_file.write_text("127.0.0.1:5432:slink_test:slink:test-only-password\n")
    password_file.chmod(0o600)
    identity_file = tmp_path / "age-identity"
    identity_file.write_text("AGE-SECRET-KEY-TEST\n")
    identity_file.chmod(0o600)
    sql = b"CREATE TABLE restored_test (id integer);\n"
    encrypted_backup = tmp_path / "slink-test.sql.gz.age"
    encrypted_backup.write_bytes(gzip.compress(sql))
    encrypted_backup.chmod(0o600)
    env = {
        **_base_env(tools, trace),
        "PGPASSFILE": str(password_file),
        "BACKUP_AGE_IDENTITY_FILE": str(identity_file),
        "SLINK_RESTORE_OK": "1",
    }

    result = subprocess.run(
        ["/bin/bash", str(ROOT / "scripts/restore.sh"), "--yes", str(encrypted_backup)],
        env=env,
        input="slink_test\n",
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (trace / "restored.sql").read_bytes() == sql
    arguments = (trace / "psql.args").read_text()
    assert "test-only-password" not in arguments
    assert "postgresql://" not in arguments
    assert not list(tmp_path.glob("*.sql"))


def test_compose_restore_streams_into_private_database_container(tmp_path):
    tools, trace = _stub_tools(tmp_path)
    _add_docker_stub(tools)
    identity_file = tmp_path / "age-identity"
    identity_file.write_text("AGE-SECRET-KEY-TEST\n")
    identity_file.chmod(0o600)
    sql = b"CREATE TABLE compose_restore_test (id integer);\n"
    encrypted_backup = tmp_path / "slink-test.sql.gz.age"
    encrypted_backup.write_bytes(gzip.compress(sql))
    encrypted_backup.chmod(0o600)
    env = {
        **_base_env(tools, trace),
        "BACKUP_AGE_IDENTITY_FILE": str(identity_file),
        "SLINK_COMPOSE_DATABASE": "1",
        "SLINK_RESTORE_OK": "1",
    }
    env.pop("PGHOST")

    result = subprocess.run(
        ["/bin/bash", str(ROOT / "scripts/restore.sh"), "--yes", str(encrypted_backup)],
        env=env,
        input="slink_test\n",
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (trace / "compose-restored.sql").read_bytes() == sql
    arguments = (trace / "docker.args").read_text()
    assert "exec\n-T\ndb\npsql" in arguments
    assert "password" not in arguments.lower()
    assert "postgresql://" not in arguments
    assert not list(tmp_path.glob("*.sql"))
