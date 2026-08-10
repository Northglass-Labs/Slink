from datetime import datetime
from pydantic import BaseModel


class DashboardDetectionSummary(BaseModel):
    id: int
    severity: str
    source: str
    title: str
    first_seen: datetime
    model_config = {"from_attributes": True}


class SeverityDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class TimeSeriesPoint(BaseModel):
    date: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DashboardStats(BaseModel):
    active_count: int
    new_count: int
    acknowledged_count: int
    critical_count: int
    high_count: int
    last_critical: DashboardDetectionSummary | None
    sources_healthy: int
    sources_total: int
    sources_failing: int
    severity_distribution: SeverityDistribution
    time_series: list[TimeSeriesPoint]
    needs_attention: list[DashboardDetectionSummary]
