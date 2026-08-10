from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class RawDetection:
    source: str
    source_url: str
    title: str
    content: str
    raw_payload: dict = field(default_factory=dict)
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str | None = None


class BaseCollector(ABC):
    name: str
    poll_interval_seconds: int

    @abstractmethod
    async def collect(self, since: datetime | None = None) -> list[RawDetection]:
        """Collect new detections.

        Args:
            since: Optional datetime. Collectors that support incremental polling
                   use this to filter results to only items created after this
                   timestamp. When None, the collector falls back to its default
                   behaviour (usually the most recent N items).
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        ...

    async def configure_watches(self, keywords: list) -> None:
        """Override in collectors that support server-side monitoring rules."""
        pass
