"""Custom Prometheus metrics for Slink."""
from prometheus_client import Counter, Histogram

# Detection processing
detections_created = Counter(
    "slink_detections_created_total",
    "Total detections created",
    ["source", "severity"],
)

detections_deduplicated = Counter(
    "slink_detections_deduplicated_total",
    "Total detections deduplicated (content hash or cross-source)",
    ["source"],
)

# Notifications
notifications_sent = Counter(
    "slink_notifications_sent_total",
    "Total notifications sent",
    ["channel", "status"],  # channel: pushover/teams/webhook, status: success/failure
)

# Collector polling
collector_poll_duration = Histogram(
    "slink_collector_poll_duration_seconds",
    "Time taken for a collector poll cycle",
    ["source"],
    buckets=[1, 5, 10, 30, 60, 120, 300],
)

collector_errors = Counter(
    "slink_collector_errors_total",
    "Total collector errors",
    ["source"],
)

# IOC extraction
indicators_extracted = Counter(
    "slink_indicators_extracted_total",
    "Total IOC indicators extracted",
    ["type"],
)
