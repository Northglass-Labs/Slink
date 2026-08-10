# Slink — Grafana dashboard

A single Grafana dashboard that visualises everything Slink exports to
Prometheus. Covers detection volume, source health, notification dispatch,
and API performance.

## What you need

- A Grafana instance (any version that supports schemaVersion 38, i.e.
  Grafana 9.4+; tested on 10.x).
- A Prometheus instance scraping the Slink API's `/metrics` endpoint.
- Network reachability between Prometheus and the Slink API on port 8000.

## Set up the Prometheus datasource

In Grafana → **Connections → Data sources → Add data source → Prometheus**:

| Field | Value |
|---|---|
| Name | `Prometheus` (or anything — the dashboard variable picks it up) |
| URL | `http://prometheus:9090` (or your scraper's address) |
| Access | Server (default) |

Save & test — the datasource must be green before importing the dashboard.

## Configure the Prometheus scrape

Add this to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: slink
    metrics_path: /metrics
    static_configs:
      - targets: ['slink-api:8000']   # in-cluster service DNS
        labels:
          service: slink
```

Two important notes:

1. **`/metrics` is intentionally blocked at the nginx layer in production**
   (see `nginx/nginx.conf` — `location /metrics { deny all; }`). Scrape the
   API service directly inside your cluster network, not through the public
   Ingress.
2. The Helm chart exposes the API as a ClusterIP service named
   `<release>-slink-api`. Point `targets` at that hostname in-cluster.

## Import the dashboard

1. **Dashboards → New → Import**.
2. Upload `slink-dashboard.json` (or paste the JSON).
3. When prompted, pick your Prometheus datasource.
4. Click Import. The dashboard lands at `/d/slink-overview`.

## What each panel means

### Detections row

- **Detection rate by severity** — per-second create rate of new detections,
  stacked by severity (critical/high/medium/low). Spikes are usually either a
  real-world event (good) or a runaway collector (check Source Health below).
- **Detection rate by source** — same metric grouped by source instead. Use
  this to spot which collector dominates volume.
- **Detections (last 24h)** — totals broken out by severity. Quick at-a-glance
  number for the daily standup.
- **Deduplicated (last 24h)** — items the dedup pipeline suppressed. High
  dedup is *normal* — multiple collectors often see the same leak.
- **IOCs extracted (last 24h)** — indicator yield by type
  (hash / ip / domain / cve / mitre).

### Collector health row

- **Collector poll duration (p95)** — 95th-percentile poll latency per source,
  derived from the `slink_collector_poll_duration_seconds` histogram. Sustained
  increases mean a slow upstream API.
- **Collector errors** — error rate per source. Slink fires a Teams health
  alert at 6 consecutive failures and auto-disables the source at 20.
  Flat-lined at zero is the goal.
- **Source health summary** — table view: detections / errors / avg poll
  duration per source over the last 24h. Cross-reference with the Source
  Status page in the Slink UI for the authoritative `consecutive_failures`
  counter.

### Notifications row

- **Notification dispatch rate** — per-channel rate from
  `slink_notifications_sent_total{channel,status}`. Pushover handles
  emergencies + standard urgent; Teams handles AI-triaged + medium digest.
  The webhook fallback only fires when Teams Graph API is unavailable.
- **Notification success ratio (24h)** — successful / total per channel,
  last 24h. Below 0.95 usually means a webhook URL has rotated or a channel
  is rate-limiting.

### API performance row

- **HTTP request rate** — FastAPI request rate by handler and method
  (from `prometheus-fastapi-instrumentator`). Useful for spotting UI
  thrashing or runaway clients.
- **HTTP request latency (p50/p95/p99)** — percentiles from the
  `http_request_duration_seconds` histogram. High p99 with low p50 is
  the classic slow-tail pattern.
- **HTTP error rate (4xx/5xx)** — non-2xx response rate by status. 401/403
  spikes after a frontend deploy are usually expired tokens; 5xx spikes are
  real and should be cross-referenced with API logs.

## Customising

The dashboard's JSON is checked in at `docs/grafana/slink-dashboard.json` —
edit there, not in the Grafana UI, if you want changes to survive upgrades.
The `$datasource` template variable means the dashboard is portable across
environments without hand-editing every panel.

## Troubleshooting

- **All panels show "No data"** — Prometheus probably isn't scraping. From
  the Slink API pod: `curl localhost:8000/metrics | head -20`. From
  Prometheus: visit the Targets page and check the Slink scrape job is UP.
- **Some panels work, some don't** — the missing ones likely depend on
  metrics that haven't fired yet. Custom counters (`slink_detections_*`,
  `slink_notifications_*`) only emit after the corresponding event happens.
  Wait a poll interval (5 minutes) and refresh.
- **`http_request_duration_seconds` panels empty** — older versions of
  `prometheus-fastapi-instrumentator` use different metric names. Check
  what the `/metrics` endpoint actually exposes and adjust the dashboard
  PromQL accordingly.
