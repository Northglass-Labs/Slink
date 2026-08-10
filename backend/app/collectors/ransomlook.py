import httpx
from app.collectors.base import BaseCollector, RawDetection

# ransomlook.io API field reference (verified 2026-03):
#   post_title  — victim / site name (often a domain)
#   group_name  — threat actor / ransomware group
#   description — attacker-written text (often empty)
#   link        — relative path to the ransomlook blog entry (prefix with base URL)
#   discovered  — ISO-ish datetime string
#   magnet      — torrent magnet link (may be null)


class RansomlookCollector(BaseCollector):
    name = "ransomlook"
    poll_interval_seconds = 600
    BASE_URL = "https://www.ransomlook.io"

    def __init__(self):
        self._client = httpx.AsyncClient(timeout=60)

    def parse_posts(self, data: list[dict]) -> list[RawDetection]:
        detections = []
        for post in data:
            title = post.get("post_title", "")
            group = post.get("group_name", "")
            description = post.get("description", "")

            # Build absolute URL from the relative link ransomlook returns
            relative_link = post.get("link", "")
            source_url = f"{self.BASE_URL}{relative_link}" if relative_link else ""

            content = "\n".join(filter(None, [
                title,
                description,
                f"Group: {group}" if group else "",
            ]))

            # Use source's discovered timestamp for accurate first_seen
            from datetime import datetime, timezone
            disc_str = post.get("discovered", "")
            try:
                collected = datetime.fromisoformat(disc_str.replace("Z", "+00:00"))
                if collected.tzinfo is None:
                    collected = collected.replace(tzinfo=timezone.utc)
            except (ValueError, AttributeError):
                collected = datetime.now(timezone.utc)

            detections.append(
                RawDetection(
                    source=self.name,
                    source_url=source_url,
                    title=title,
                    content=content,
                    raw_payload=post,
                    actor=group or None,
                    collected_at=collected,
                )
            )
        return detections

    async def collect(self, since=None) -> list[RawDetection]:
        resp = await self._client.get(f"{self.BASE_URL}/api/recent")
        resp.raise_for_status()
        return self.parse_posts(resp.json())

    async def close(self) -> None:
        """Close the underlying HTTP client to release connections."""
        await self._client.aclose()

    async def health_check(self) -> bool:
        try:
            resp = await self._client.get(f"{self.BASE_URL}/api/groups")
            return resp.status_code == 200
        except Exception:
            return False
