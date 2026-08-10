"""
GitHub Advisory Database collector.

Polls the GitHub Advisory Database via the GraphQL API for recent advisories
that are HIGH or CRITICAL severity. The Advisory DB is GitHub's curated
public feed of CVE-equivalent records, including ones that don't have a
CVE ID yet — useful for catching ecosystem-specific vulns earlier than NVD.

Auth: a personal access token (or fine-grained token) lifts the rate limit
from 60 unauthenticated requests/hour to 5,000 authenticated. The API is
useless at 60/hr in practice, so this collector requires a token — it
returns an empty list when ``GITHUB_TOKEN`` is unset (consistent with the
"missing creds = disabled" pattern documented in COLLECTORS.md).

Reference: https://docs.github.com/en/graphql/reference/objects#securityadvisory

GraphQL response shape (we only ask for what we use):
  {
    "data": {"securityAdvisories": {"nodes": [
      {
        "ghsaId": "GHSA-xxxx-xxxx-xxxx",
        "summary": "...",
        "description": "...",
        "severity": "HIGH" | "CRITICAL" | ...,
        "publishedAt": ISO8601,
        "permalink": "https://github.com/advisories/GHSA-...",
        "identifiers": [{"type": "GHSA"|"CVE", "value": "..."}],
        "references": [{"url": "..."}],
        "vulnerabilities": {"nodes": [
          {"package": {"ecosystem": "NPM", "name": "..."},
           "vulnerableVersionRange": "< 1.2.3",
           "firstPatchedVersion": {"identifier": "1.2.3"}}
        ]}
      }, ...
    ]}}
  }
"""
import logging
from datetime import datetime, timedelta, timezone

import httpx

from app.collectors.base import BaseCollector, RawDetection

logger = logging.getLogger(__name__)

_GITHUB_GRAPHQL = "https://api.github.com/graphql"

# Pulled out so tests can introspect the exact query if it ever needs to
# change. Keep it minimal — every additional field costs us against the
# GraphQL rate budget.
_ADVISORY_QUERY = """
query($since: DateTime!, $first: Int!, $after: String) {
  securityAdvisories(
    first: $first
    after: $after
    publishedSince: $since
    orderBy: {field: PUBLISHED_AT, direction: DESC}
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      permalink
      origin
      identifiers { type value }
      references { url }
      vulnerabilities(first: 10) {
        nodes {
          package { ecosystem name }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}
""".strip()


class GitHubAdvisoryCollector(BaseCollector):
    name = "github_advisory"
    poll_interval_seconds = 1800  # 30 minutes

    # We pull a 24-hour lookback window on each poll. The GraphQL filter is
    # publishedSince, so dedup at the engine level handles the overlap with
    # earlier polls; we just need to keep the page size sane.
    _LOOKBACK_HOURS = 24
    _PAGE_SIZE = 50
    # Severities we care about per the brief — HIGH/CRITICAL only. We filter
    # client-side because the GraphQL securityAdvisories root query doesn't
    # accept a severity filter (only the per-advisory vulnerabilities edge does).
    _ALLOWED_SEVERITIES = {"HIGH", "CRITICAL"}

    def __init__(self, token: str | None = None) -> None:
        self._token = token or ""
        # Bearer auth per GitHub docs. We always send the User-Agent header
        # because GitHub will 403 a missing UA.
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Slink-GitHubAdvisoryCollector",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        self._client = httpx.AsyncClient(timeout=60, headers=headers)

    async def collect(self, since: datetime | None = None) -> list[RawDetection]:
        if not self._token:
            # Match the documented "no creds = collector disabled" behaviour.
            # 60/hr unauthenticated is too low to be useful in practice.
            logger.info("GitHub Advisory: GITHUB_TOKEN not set — skipping collection")
            return []

        published_since = (
            since
            if since is not None
            else datetime.now(timezone.utc) - timedelta(hours=self._LOOKBACK_HOURS)
        )
        # GitHub's DateTime scalar accepts ISO-8601 with Z suffix.
        since_iso = published_since.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        resp = await self._client.post(
            _GITHUB_GRAPHQL,
            json={
                "query": _ADVISORY_QUERY,
                "variables": {
                    "since": since_iso,
                    "first": self._PAGE_SIZE,
                    "after": None,
                },
            },
        )
        resp.raise_for_status()
        data = resp.json()

        if "errors" in data:
            # GraphQL hands errors back at HTTP 200 — surface them so the
            # scheduler logs the failure rather than silently producing 0 rows.
            raise RuntimeError(f"GitHub Advisory GraphQL errors: {data['errors']}")

        nodes = (
            data.get("data", {})
            .get("securityAdvisories", {})
            .get("nodes", [])
        ) or []

        detections = self._parse_advisories(nodes)
        logger.info(
            "GitHub Advisory: fetched %d advisories, %d above severity threshold",
            len(nodes), len(detections),
        )
        return detections

    # ------------------------------------------------------------------
    # parse_advisories — pure mapping
    # ------------------------------------------------------------------

    def _parse_advisories(self, nodes: list[dict]) -> list[RawDetection]:
        results: list[RawDetection] = []
        for adv in nodes:
            severity = (adv.get("severity") or "").upper()
            cve_ids = _cve_identifiers(adv.get("identifiers") or [])
            # Pass HIGH/CRITICAL through, plus anything with a CVE — the brief
            # asks for "all CVEs with active exploitation indicators". We
            # don't have a clean exploitation flag in the public schema, so
            # we proxy "has a CVE" as the broader inclusion criterion and
            # let downstream keyword/severity rules do the rest.
            if severity not in self._ALLOWED_SEVERITIES and not cve_ids:
                continue

            ghsa_id = adv.get("ghsaId", "")
            summary = (adv.get("summary") or "").strip()
            description = (adv.get("description") or "").strip()
            permalink = adv.get(
                "permalink"
            ) or (f"https://github.com/advisories/{ghsa_id}" if ghsa_id else "")

            # Title format per the brief: "GHSA-... — <summary>"
            title_summary = summary or description[:120]
            title = (
                f"{ghsa_id} — {title_summary}" if ghsa_id and title_summary
                else ghsa_id or title_summary
            )
            title = title[:500]

            packages = _format_packages(adv.get("vulnerabilities") or {})
            cve_str = ", ".join(cve_ids) if cve_ids else ""

            content_parts = [
                summary,
                description,
                f"Severity: {severity}" if severity else "",
                f"CVE refs: {cve_str}" if cve_str else "",
                f"Affected packages:\n{packages}" if packages else "",
            ]
            content = "\n\n".join(p for p in content_parts if p)

            results.append(
                RawDetection(
                    source=self.name,
                    source_url=permalink,
                    title=title,
                    content=content,
                    raw_payload=adv,
                )
            )
        return results

    # ------------------------------------------------------------------
    # health_check
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        # No token = collector intentionally disabled, not failing.
        if not self._token:
            return True
        try:
            # A trivial query to /graphql — `viewer { login }` is the
            # canonical "are my creds OK" probe and costs 0 against the
            # rate budget.
            resp = await self._client.post(
                _GITHUB_GRAPHQL,
                json={"query": "{ viewer { login } }"},
            )
            if resp.status_code != 200:
                return False
            body = resp.json()
            return "errors" not in body
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------
# Helpers — module-level so tests can import directly
# ---------------------------------------------------------------------------


def _cve_identifiers(identifiers: list[dict]) -> list[str]:
    """Pull the CVE-prefixed identifiers out of an advisory's identifier list."""
    return [
        i.get("value", "")
        for i in identifiers
        if i.get("type", "").upper() == "CVE" and i.get("value")
    ]


def _format_packages(vulnerabilities: dict) -> str:
    """Render the affected-package list as a short multi-line block."""
    nodes = vulnerabilities.get("nodes") or []
    lines: list[str] = []
    for v in nodes:
        pkg = v.get("package") or {}
        name = pkg.get("name", "")
        ecosystem = pkg.get("ecosystem", "")
        vrange = v.get("vulnerableVersionRange", "")
        patched = (v.get("firstPatchedVersion") or {}).get("identifier", "")
        bits = [f"{ecosystem}:{name}" if ecosystem and name else name or ecosystem]
        if vrange:
            bits.append(f"vulnerable {vrange}")
        if patched:
            bits.append(f"patched in {patched}")
        line = " — ".join(b for b in bits if b)
        if line:
            lines.append(f"- {line}")
    return "\n".join(lines)
