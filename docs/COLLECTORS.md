# Adding a Threat-Intel Source to Slink

This guide is for contributors who want to add a new collector. The pattern is intentionally small: one file in `backend/app/collectors/`, one line in `collectors/__init__.py`, optionally one row in `.env.example`. No core change is ever needed to add or remove a source.

## What "a source" is in Slink

A **source** is anything Slink can poll on a schedule and turn into normalised `Detection` rows. That includes JSON APIs (most of the existing collectors), CSV/TSV feeds, RSS/Atom, MISP-event endpoints, even regular HTML pages if you want to write a parser. It does **not** include push integrations (webhooks Slink receives) — that's a different surface and lives under `routers/webhooks.py`.

## The contract

Every collector extends `BaseCollector` (in `backend/app/collectors/base.py`). The interface is intentionally tiny:

```python
class BaseCollector(ABC):
    name: str                       # short slug, must match COLLECTOR_REGISTRY key
    poll_interval_seconds: int      # how often the scheduler runs this collector

    @abstractmethod
    async def collect(self, since: datetime | None = None) -> list[RawDetection]: ...

    @abstractmethod
    async def health_check(self) -> bool: ...

    async def configure_watches(self, keywords: list) -> None: ...   # optional
```

`RawDetection` is also defined in `base.py`:

```python
@dataclass
class RawDetection:
    source: str               # always self.name
    source_url: str           # link to the post / report / IOC record
    title: str                # short headline
    content: str              # body text — feeds into keyword matching
    raw_payload: dict         # whatever the upstream gave you, kept verbatim
    collected_at: datetime    # default: now, UTC
    actor: str | None         # threat-actor / group name if known
```

The detection-engine pipeline takes the list of `RawDetection` you return and:

1. Hashes `(source, content)` for per-source dedup.
2. Hashes `(victim, source)` (extracted from `title` + `actor`) for cross-source dedup within 24 h.
3. Runs the watchlist keywords against `title + content`.
4. Computes severity from the configurable `severity_rules` table.
5. Persists matches to the `detections` table.
6. Hands incident-linked detections to the AI triage path (Claude Haiku) when `ANTHROPIC_API_KEY` is set.

You don't need to know any of that to write a collector — just produce honest `RawDetection` objects.

## Step-by-step: adding a new source

Here is the full process for a hypothetical "Acme Threat Feed" with a JSON API that returns recent indicators.

### 1. Create the collector file

`backend/app/collectors/acme_feed.py`:

```python
"""Acme Threat Feed collector.

Acme publishes a JSON list of indicators at https://feed.acme.example/recent.
We poll every 15 minutes; the API has no incremental cursor so we fetch the
last 100 records and let dedup handle the rest.
"""
from datetime import datetime, timezone
from typing import Any

import httpx

from app.collectors.base import BaseCollector, RawDetection
from app.config import settings


class AcmeFeedCollector(BaseCollector):
    name = "acme_feed"
    poll_interval_seconds = 15 * 60  # 15 minutes

    def __init__(self):
        # Auth pulled from settings; collector becomes a no-op when missing.
        self._api_key = settings.acme_api_key
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url="https://feed.acme.example",
                timeout=20.0,
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
        return self._client

    async def collect(self, since: datetime | None = None) -> list[RawDetection]:
        if not self._api_key:
            return []

        client = await self._get_client()
        resp = await client.get("/recent", params={"limit": 100})
        resp.raise_for_status()
        records: list[dict[str, Any]] = resp.json().get("indicators", [])

        results: list[RawDetection] = []
        for r in records:
            results.append(RawDetection(
                source=self.name,
                source_url=r.get("permalink", ""),
                title=r.get("title", "")[:500],
                content=r.get("description", ""),
                raw_payload=r,
                collected_at=datetime.now(timezone.utc),
                actor=r.get("threat_group"),
            ))
        return results

    async def health_check(self) -> bool:
        if not self._api_key:
            # No key configured = collector is intentionally disabled, not failing.
            return True
        try:
            client = await self._get_client()
            resp = await client.get("/ping")
            return resp.status_code == 200
        except Exception:
            return False
```

### 2. Add config knobs

`backend/app/config.py` — add the field to the `Settings` model:

```python
class Settings(BaseSettings):
    # ... existing fields ...
    acme_api_key: str = ""
```

`.env.example` — add the variable:

```
# Acme Threat Feed (https://feed.acme.example) — free signup at acme.example/auth
ACME_API_KEY=
```

### 3. Register the collector

`backend/app/collectors/__init__.py`:

```python
from app.collectors.acme_feed import AcmeFeedCollector

COLLECTOR_REGISTRY: dict[str, type] = {
    # ... existing entries ...
    "acme_feed": AcmeFeedCollector,
}
```

Place it in the right group (free no-account / free with signup / paid). The order in this dict is the order the source appears in the Source Status UI and the poll order.

### 4. Add a frontend display label

`frontend/src/components/DetectionRow.tsx` and `DetectionDetail.tsx` have a couple of small lookup tables for source labels and dashboard URLs. Add an entry so the source name renders nicely:

```typescript
const SOURCE_LABELS: Record<string, string> = {
  // ...existing...
  acme_feed: "Acme Feed",
};
```

(If you skip this step, the source still works — it'll just show as the raw slug `acme_feed`.)

### 5. Write tests

`backend/tests/test_collector_acme_feed.py` — at minimum:

- A unit test for the `collect()` mapping with a mocked httpx response.
- A unit test for the no-key short-circuit (`assert results == []`).
- A unit test for `health_check()` happy path and failure path.

Use `pytest-httpx` (already in the test deps) to stub HTTP responses. Pattern:

```python
import pytest
from app.collectors.acme_feed import AcmeFeedCollector

@pytest.mark.asyncio
async def test_acme_feed_maps_indicators(httpx_mock):
    httpx_mock.add_response(
        url="https://feed.acme.example/recent?limit=100",
        json={"indicators": [{"permalink": "...", "title": "...", "description": "..."}]},
    )
    # ... rest of the test ...
```

### 6. Optional: server-side rule sync

If your source supports keyword-based monitoring rules on its end (CrowdStrike Recon does; most don't), override `configure_watches`:

```python
async def configure_watches(self, keywords: list) -> None:
    """Push the current keyword list to the upstream service."""
    ...
```

The keyword routers in `backend/app/routers/keywords.py` call this whenever the watchlist changes.

## Things not to do

- **Don't crash the scheduler.** If your upstream is down, `collect()` should raise the underlying exception — the per-collector error isolation in `services/scheduler.py` will log it, mark the source as failing, and let other collectors keep running. Don't try to handle it yourself.
- **Don't dedup inside the collector.** Dedup is centralised in `services/detection_engine.py` and uses both content hashes and victim hashes. Adding your own dedup will make the cross-source dedup math wrong.
- **Don't compute severity inside the collector.** That's the severity-rules engine's job, and it's user-editable in the UI.
- **Don't write to the DB from a collector.** Collectors only return data; persistence is the engine's responsibility.
- **Don't hardcode credentials.** Always read from `app.config.settings`. The settings object reads from `.env` at startup.
- **Don't include real brand names, customer names, or live incident identifiers** in test fixtures or comments. Use the seeded placeholder vocabulary: `acme-corp`, `acme.example`, `example-threat-actor`, etc.

## Source slugs that already exist

- `ransomwatch`, `ransomlook`, `cisa_kev` — free, no account
- `threatfox`, `alienvault_otx` — free, signup / auth-key
- `crowdstrike_recon`, `crowdstrike_intel` — paid, optional

Pick a slug that doesn't collide with any of the above. Use `snake_case`. Keep it short — the slug appears in the UI and in URLs.

## Roadmap

`docs/ROADMAP.md` and the README's "Roadmap" table list collectors that are designed in but not yet built. If you pick one off that list, claim it in a PR or an issue first so two people don't build the same thing.

If you build a collector and we accept the PR, you get to add yourself to a contributors section in the README.
