# Contributing to Slink

Thanks for your interest. Slink is built to be extended — adding a new threat-intel source, a new notification channel, or sharpening severity logic should all be small, self-contained changes. This guide is the short path.

If anything below is wrong, stale, or just confusing, please open an issue or PR. Documentation drift is a bug.

---

## Getting Started

```bash
git clone https://github.com/Northglass-Labs/Slink.git
cd Slink
cp .env.example .env
docker compose up -d
```

Full first-run walkthrough (admin user creation, ports, defaults) lives in the [README Quick Start](README.md#quick-start).

---

## Development Loop

Slink is two services and a database. Keep both green before opening a PR.

### Backend

The test suite needs a separate Postgres database. Easiest way is to run pytest inside the running api container against `db:5432/slink_test`:

```bash
docker compose exec -T db psql -U slink -d postgres \
  -c "CREATE DATABASE slink_test;"
docker compose exec -T api sh -lc \
  'export TEST_DATABASE_URL="postgresql+asyncpg://slink:${POSTGRES_PASSWORD}@db:5432/slink_test"; pytest -q --cov=app --cov-fail-under=65'
```

Bare-metal alternative (Postgres on localhost:5433):

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements-dev.lock
install -m 600 /dev/null .env.test
${EDITOR:-vi} .env.test  # add TEST_DATABASE_URL for a dedicated test database
set -a; . ./.env.test; set +a
pytest --cov=app --cov-report=term-missing --cov-fail-under=65
unset TEST_DATABASE_URL
```

### Frontend

```bash
cd frontend
npm ci
npm run dev      # vite dev server on :5173 (proxied to :5180 in compose)
npm run build    # tsc -b && vite build
npm run lint     # eslint .
```

### Dependency locks

Edit `backend/requirements.txt` or `backend/requirements-dev.txt`, then regenerate
the universal hash locks with the same commands recorded at the top of each lock:

```bash
cd backend
uv pip compile --universal --python-version 3.12 --generate-hashes \
  requirements.txt -o requirements.lock
uv pip compile --universal --python-version 3.12 --generate-hashes \
  requirements-dev.txt -o requirements-dev.lock
```

Commit the input and both regenerated lock files together. Python installs use
`--require-hashes`; npm installs use the checked-in package lock through `npm ci`.

### Database migrations

```bash
cd backend
alembic revision --autogenerate -m "describe the change"
alembic upgrade head
```

Review the generated migration before committing. Autogenerate gets simple cases right; renames and constraint reshuffles often need a hand-edit.

---

## How to add a TI source

This is the most common contribution path, and it's intentionally small.

1. Read [`docs/COLLECTORS.md`](docs/COLLECTORS.md) — the plug-in pattern is documented end-to-end there.
2. Create `backend/app/collectors/<name>.py` extending `BaseCollector`.
3. Register the class in `backend/app/collectors/__init__.py:COLLECTOR_REGISTRY`.
4. Add a test in `backend/tests/test_collectors/` that exercises collection with a mocked HTTP response.
5. If the source needs credentials, add the env vars to `.env.example` (placeholders only — never real values).

The collector auto-disables when its credentials are missing, so partial wiring is safe to merge.

---

## Pull Request expectations

Before requesting review:

- **Conventional Commits.** `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`. One commit per logical change.
- **Tests for new behaviour.** New endpoint or collector → tests in `backend/tests/`. PRs are expected to add to the suite, not subtract from it.
- **Lint and tests pass locally.** Backend coverage, Ruff, Bandit, and frontend build/lint/audit checks are green.
- **Never bypass repository hooks.** If an installed hook fails, fix the underlying issue.
- **Keep PRs focused.** Two unrelated changes? Two PRs.
- **Update docs that the change invalidates.** README, ROADMAP, or the relevant public guide should always match behavior.

CI will re-run all of the above. A green CI run is required before merge.

---

## Code Style

- **Small functions with clear names.** If the function name doesn't describe what it does, the function is doing too much.
- **Comments explain the *why*, not the *what*.** The code already shows what. Comment on non-obvious trade-offs, security-critical sections, or surprising constraints.
- **No inline secrets.** API keys, tokens, passwords live in `.env`. The `.gitleaks.toml` and pre-commit hook are the safety net — don't rely on them.
- **Async everywhere on the backend.** SQLAlchemy sessions are async, httpx clients are AsyncClient, no blocking I/O in request handlers.
- **Tailwind tokens, not hex codes.** Frontend colours come from the `@theme` block in `frontend/src/index.css`. New components reference `var(--color-*)` — they don't hardcode.
- **Test data uses generic placeholders** (`acme-corp`, `acme.example`, `example-threat-actor`). Never real brands, customers, or live incident identifiers.

---

## Issues and discussion

- **Bugs and feature requests** → use the [issue templates](.github/ISSUE_TEMPLATE).
- **New TI source request** → there's a dedicated [collector request template](.github/ISSUE_TEMPLATE/collector_request.yml).
- **Open-ended questions** → [GitHub Discussions](https://github.com/Northglass-Labs/Slink/discussions).

---

## Code of Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Report issues to `hello@northglass.io`.

---

By contributing, you agree your contributions are licensed under the project's [LICENSE](LICENSE).
