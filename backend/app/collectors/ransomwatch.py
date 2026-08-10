import httpx
from app.collectors.base import BaseCollector, RawDetection

# ransomware.live API field reference (verified 2026-03):
#   victim      — target organization name
#   group       — threat actor / ransomware group
#   description — attacker-written description of the victim
#   url         — ransomware.live permalink for this entry
#   domain      — victim domain
#   country     — victim country code
#   attackdate  — ISO-ish datetime string


class RansomWatchCollector(BaseCollector):
    name = "ransomwatch"
    poll_interval_seconds = 300
    BASE_URL = "https://api.ransomware.live/v2"

    def __init__(self):
        self._client = httpx.AsyncClient(timeout=60)

    def parse_posts(self, data: list[dict]) -> list[RawDetection]:
        detections = []
        for post in data:
            victim = post.get("victim", "")
            group = post.get("group", "")
            domain = post.get("domain", "")
            description = post.get("description", "")

            # Build a human-readable content block for keyword matching
            content = "\n".join(filter(None, [
                victim,
                f"Domain: {domain}" if domain else "",
                description,
                f"Group: {group}" if group else "",
                f"Country: {post.get('country', '')}",
            ]))

            # Use source's attackdate for accurate first_seen
            from datetime import datetime, timezone
            attack_str = post.get("attackdate", "") or post.get("discovered", "")
            try:
                collected = datetime.fromisoformat(attack_str.replace("Z", "+00:00"))
                if collected.tzinfo is None:
                    collected = collected.replace(tzinfo=timezone.utc)
            except (ValueError, AttributeError):
                collected = datetime.now(timezone.utc)

            detections.append(
                RawDetection(
                    source=self.name,
                    source_url=post.get("url", ""),
                    title=victim,
                    content=content,
                    raw_payload=post,
                    actor=group or None,
                    collected_at=collected,
                )
            )
        return detections

    async def collect(self, since=None) -> list[RawDetection]:
        resp = await self._client.get(f"{self.BASE_URL}/recentvictims")
        resp.raise_for_status()
        return self.parse_posts(resp.json())

    async def close(self) -> None:
        """Close the underlying HTTP client to release connections."""
        await self._client.aclose()

    async def health_check(self) -> bool:
        try:
            resp = await self._client.get(f"{self.BASE_URL}/groups")
            return resp.status_code == 200
        except Exception:
            return False
