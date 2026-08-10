import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.no_db

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text()


def test_internal_agent_instruction_files_are_not_in_public_tree():
    assert not (ROOT / "AGENTS.md").exists()
    assert not (ROOT / "CLAUDE.md").exists()


def test_sensitive_runtime_outputs_and_local_environments_are_ignored():
    gitignore = read(".gitignore")
    for expected in (
        ".venv/",
        ".coverage",
        "deploy/k8s/secret.env",
        "nginx/certs/*.pem",
        "nginx/certs/*.key",
        "backups/",
        "*.sql.gz",
        "*.sql.gz.age",
    ):
        assert expected in gitignore


@pytest.mark.parametrize("context", ["backend", "frontend"])
def test_docker_context_is_allowlisted(context):
    dockerignore = read(f"{context}/.dockerignore")
    assert dockerignore.splitlines()[0].strip() == "**"
    assert "!Dockerfile" in dockerignore
    assert "__pycache__" not in dockerignore


def test_container_bases_are_digest_pinned_and_frontend_serves_on_unprivileged_port():
    backend = read("backend/Dockerfile")
    frontend = read("frontend/Dockerfile")

    assert re.search(r"ARG PYTHON_BASE=.+@sha256:[0-9a-f]{64}", backend)
    assert re.search(r"ARG NODE_BASE=.+@sha256:[0-9a-f]{64}", frontend)
    assert re.search(r"ARG NGINX_BASE=.+@sha256:[0-9a-f]{64}", frontend)
    assert 'CMD ["echo", "Build complete"]' not in frontend
    assert "EXPOSE 8080" in frontend
    assert "USER 101" in frontend or "nginx-unprivileged" in frontend
    production_stage = backend.split("FROM base AS production", 1)[1]
    assert "COPY --chown=appuser:appgroup . ." not in production_stage
    assert "/data/archive" in production_stage
    assert '"--workers", "4"' not in production_stage


def test_production_python_dependencies_exclude_test_tools():
    production = read("backend/requirements.txt")
    development = read("backend/requirements-dev.txt")
    production_lock = read("backend/requirements.lock")
    development_lock = read("backend/requirements-dev.lock")

    assert "pytest" not in production.lower()
    assert "-r requirements.txt" in development
    assert "pytest==" in development
    assert "--hash=sha256:" in production_lock
    assert "--hash=sha256:" in development_lock
    assert "--require-hashes -r requirements.lock" in read("backend/Dockerfile")
    assert "--require-hashes -r requirements-dev.lock" in read("backend/Dockerfile")


def test_compose_production_resets_dev_ports_and_forces_production_mode():
    base = read("docker-compose.yml")
    production = read("docker-compose.prod.yml")

    assert "POSTGRES_PASSWORD:-slink" not in base
    assert '127.0.0.1:5434:5432' in base
    assert '127.0.0.1:8000:8000' in base
    assert '127.0.0.1:5180:5173' in base
    assert production.count("ports: !reset []") >= 3
    assert "APP_ENV: production" in production
    assert "SECURE_COOKIES: \"true\"" in production
    assert 'TRUSTED_PROXY_CIDRS: "172.30.50.10/32"' in production
    assert "internal: true" in production
    assert "nginxinc/nginx-unprivileged" in production
    assert '443:8443' in production
    assert '"curl", "--fail"' in production
    assert production.count("read_only: true") >= 3
    assert "archive:/data/archive" in production
    assert production.count("volumes: !override") >= 2
    assert "frontend-build" not in production


def test_effective_compose_publishes_only_tls_edge():
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose is unavailable")
    environment = {
        **os.environ,
        "POSTGRES_PASSWORD": "test-only-database-password",
        "DATABASE_URL": (
            "postgresql+asyncpg://slink:"
            "test-only-database-password@db:5432/slink"
        ),
    }
    command = [
        "docker",
        "compose",
        "-f",
        str(ROOT / "docker-compose.yml"),
        "-f",
        str(ROOT / "docker-compose.prod.yml"),
        "config",
        "--format",
        "json",
    ]
    result = subprocess.run(
        command,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    services = json.loads(result.stdout)["services"]
    assert not services["api"].get("ports")
    assert not services["db"].get("ports")
    assert not services["frontend"].get("ports")
    assert services["nginx"]["ports"][0]["published"] == "443"
    assert services["frontend"].get("volumes") in (None, [])
    assert [volume["target"] for volume in services["api"]["volumes"]] == [
        "/data/archive"
    ]


def test_kustomize_requires_local_secret_and_uses_runnable_frontend():
    kustomization = read("deploy/k8s/kustomization.yaml")
    frontend = read("deploy/k8s/deployment-frontend.yaml")
    api = read("deploy/k8s/deployment-api.yaml")
    postgres = read("deploy/k8s/postgres-statefulset.yaml")
    archive = read("deploy/k8s/archive-pvc.yaml")
    config = read("deploy/k8s/configmap.yaml")

    assert "- secret.env" in kustomization
    assert "- secret.env.example" not in kustomization
    assert "- archive-pvc.yaml" in kustomization
    assert "job-migrate.yaml" not in kustomization
    assert not (ROOT / "deploy/k8s/job-migrate.yaml").exists()
    assert ":latest" not in kustomization + frontend + api
    assert "containerPort: 8080" in frontend
    assert "port: 8080" in frontend
    assert 'APP_ENV: "production"' in config
    assert "kind: PersistentVolumeClaim" in archive
    assert "claimName: slink-archive" in api
    for workload in (frontend, api, postgres):
        assert "automountServiceAccountToken: false" in workload
        assert "seccompProfile:" in workload
        assert "type: RuntimeDefault" in workload


def test_helm_requires_external_secret_and_immutable_image_references():
    values = read("deploy/helm/slink/values.yaml")
    helpers = read("deploy/helm/slink/templates/_helpers.tpl")
    helmignore = read("deploy/helm/slink/.helmignore")
    chart_lock = read("deploy/helm/slink/Chart.lock")
    api = read("deploy/helm/slink/templates/deployment-api.yaml")
    frontend = read("deploy/helm/slink/templates/deployment-frontend.yaml")
    migrate = read("deploy/helm/slink/templates/job-migrate.yaml")
    archive = read("deploy/helm/slink/templates/pvc-archive.yaml")

    assert not (ROOT / "deploy/helm/slink/templates/secret.yaml").exists()
    assert 'tag: "latest"' not in values
    assert "digest:" in values
    assert "existingSecret" in helpers
    assert "required" in helpers or "fail" in helpers
    assert "api.replicas must remain 1" in helpers
    assert "readOnlyRootFilesystem: true" in values
    assert "seccompProfile:" in values
    assert "type: RuntimeDefault" in values
    assert "archive:" in values and "persistence:" in values
    assert "kind: PersistentVolumeClaim" in archive
    assert "existingClaim" in archive
    for workload in (api, frontend, migrate):
        assert "automountServiceAccountToken: false" in workload
    assert "charts/*.tgz" not in helmignore
    assert "version: 15.5.38" in chart_lock
    assert re.search(r"digest: sha256:[0-9a-f]{64}", chart_lock)


def test_workflow_actions_are_full_sha_pinned():
    workflows = "\n".join(
        path.read_text() for path in sorted((ROOT / ".github/workflows").glob("*.yml"))
    )
    uses = re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", workflows, flags=re.MULTILINE)
    assert uses
    for action in uses:
        assert re.search(r"@[0-9a-f]{40}$", action), action


def test_ci_scans_git_history_and_current_tree_with_verified_tool():
    workflow = read(".github/workflows/ci.yml")
    assert "fetch-depth: 0" in workflow
    assert "gitleaks git" in workflow
    assert "gitleaks dir" in workflow
    assert "--no-git" not in workflow
    assert "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" in workflow
    assert "sudo install" not in workflow
    assert "HELM_IMAGE=" in workflow
    assert "dependency build" in workflow
    assert "template slink /chart" in workflow
    assert "kubectl kustomize" in workflow
    assert "api.replicas=2" in workflow
    assert "kind: PersistentVolumeClaim" in workflow
    assert "automountServiceAccountToken: false" in workflow
    assert "type: RuntimeDefault" in workflow
    assert "npm audit" in workflow
    assert "gh-action-pip-audit" in workflow
    assert "ruff check app tests" in workflow
    assert "bandit -q -r app -ll" in workflow
    assert "--cov-fail-under=65" in workflow


def test_release_requires_reviewed_main_and_emits_provenance_and_sbom():
    workflow = read(".github/workflows/release.yml")
    assert "environment: release" in workflow
    assert "merge-base --is-ancestor" in workflow
    assert "sbom: true" in workflow
    assert "provenance: mode=max" in workflow
    assert "attest-build-provenance" in workflow
    assert "trivy-action" in workflow
    assert "${{ matrix.image }}:latest" not in workflow


def test_backup_is_owner_only_client_encrypted_and_portable():
    backup = read("scripts/backup.sh")
    restore = read("scripts/restore.sh")

    assert "umask 077" in backup
    assert "BACKUP_AGE_RECIPIENT" in backup
    assert ".sql.gz.age" in backup
    assert "mapfile" not in backup
    assert "PG_CONN_URL" not in backup
    assert "--sse" in backup
    assert "BACKUP_AGE_IDENTITY_FILE" in restore
    assert "age --decrypt" in restore
    assert "PG_CONN_URL" not in restore
    assert "check_private_file" in backup
    assert "check_private_file" in restore
    assert "SLINK_COMPOSE_DATABASE" in backup
    assert "SLINK_COMPOSE_DATABASE" in restore


def test_setup_and_user_cli_do_not_put_credentials_in_argv():
    setup = read("setup.sh")
    create_user = read("backend/app/utils/create_user.py")

    assert "source .env" not in setup
    assert "alembic upgrade head" not in setup
    curl_lines = "\n".join(
        line for line in setup.splitlines() if "curl" in line or line.lstrip().startswith("-d ")
    )
    for secret_name in (
        "ADMIN_PASSWORD",
        "CS_CLIENT_SECRET",
        "OTX_API_KEY",
        "PUSHOVER_API_TOKEN",
        "PUSHOVER_USER_KEY",
    ):
        assert secret_name not in curl_lines
    assert "getpass" in create_user
    assert "<password>" not in create_user
    assert os.access(ROOT / "setup.sh", os.X_OK)
    assert os.access(ROOT / "scripts/backup.sh", os.X_OK)
    assert os.access(ROOT / "scripts/restore.sh", os.X_OK)
