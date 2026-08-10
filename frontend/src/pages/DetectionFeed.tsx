import React, { useState, useEffect, useRef, useMemo } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Detection, DetectionListResponse } from "../types";
import api from "../api";
import DetectionRow from "../components/DetectionRow";
import DetectionCard from "../components/DetectionCard";
import DetectionDetail from "../components/DetectionDetail";
import { useKeyboardShortcuts } from "../hooks/useKeyboardShortcuts";
import { useDetections, detectionsKey, type DetectionsParams } from "../queries/useDetections";
import { useSources } from "../queries/useSources";
import { Button } from "../components/ui";

const LIMIT = 50;

const SEVERITIES: Array<Detection["severity"] | ""> = ["", "critical", "high", "medium", "low"];
const STATUSES: Array<Detection["status"] | ""> = ["", "new", "acknowledged", "dismissed", "escalated"];

const DATE_RANGE_OPTIONS = ["24h", "7d", "30d", "all"] as const;
type DateRange = (typeof DATE_RANGE_OPTIONS)[number];

// Columns that support sorting — maps display name to API param value
const SORTABLE_COLUMNS: Record<string, string> = {
  Severity: "severity",
  Source: "source",
  "First Seen": "first_seen",
};

// Severity summary pill config — matches SeverityBadge colors
const severitySummaryConfig: Record<
  Detection["severity"],
  { color: string; bg: string }
> = {
  critical: { color: "var(--color-sev-critical)", bg: "rgba(239,68,68,0.12)" },
  high: { color: "var(--color-sev-high)", bg: "rgba(249,115,22,0.12)" },
  medium: { color: "var(--color-sev-medium)", bg: "rgba(251,191,36,0.10)" },
  low: { color: "var(--color-sev-low)", bg: "rgba(139,159,192,0.08)" },
};

export default function DetectionFeed() {
  const queryClient = useQueryClient();

  const [offset, setOffset] = useState(0);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  // Tick state — not read directly, just forces a re-render every minute so
  // timeAgo() values in DetectionRow recompute from current Date.now() rather
  // than staying frozen between data-fetch intervals.
  const [, setTick] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 60_000);
    return () => clearInterval(id);
  }, []);

  // Bulk selection state
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());

  // New-detection indicator state
  const [lastSeenId, setLastSeenId] = useState<number>(() => {
    return parseInt(localStorage.getItem("slink_last_seen_id") || "0");
  });
  const [newCount, setNewCount] = useState(0);
  // Tracks whether we've received our first payload — without this, the
  // banner would fire on first render claiming every fetched detection is
  // "new" because lastSeenId starts at 0.
  const hasInitialized = useRef(false);

  // Keyboard navigation state
  const [activeRowIndex, setActiveRowIndex] = useState(-1);
  const [showHelp, setShowHelp] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  // Filter state
  const [source, setSource] = useState("");
  const [severity, setSeverity] = useState<Detection["severity"] | "">("");
  const [statusFilter, setStatusFilter] = useState<Detection["status"] | "">("");

  // Search with debounce
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    const timer = setTimeout(() => setSearch(searchInput), 300);
    return () => clearTimeout(timer);
  }, [searchInput]);

  // Source dropdown data — shared with SourceStatus page via React Query cache
  const { data: sourceList } = useSources();
  const sourceOptions = useMemo(
    () => (sourceList ?? []).map((s) => s.source_name),
    [sourceList]
  );

  // Date range filter
  const [dateRange, setDateRange] = useState<DateRange>("all");

  function getAfterDate(): string | undefined {
    const now = new Date();
    if (dateRange === "24h") return new Date(now.getTime() - 86400000).toISOString();
    if (dateRange === "7d") return new Date(now.getTime() - 7 * 86400000).toISOString();
    if (dateRange === "30d") return new Date(now.getTime() - 30 * 86400000).toISOString();
    return undefined;
  }

  // Column sorting
  const [sortBy, setSortBy] = useState("");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  function handleSort(column: string) {
    const apiField = SORTABLE_COLUMNS[column];
    if (!apiField) return;
    if (sortBy === apiField) {
      setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(apiField);
      setSortDir("desc");
    }
  }

  const hasActiveFilters =
    source !== "" || severity !== "" || statusFilter !== "" ||
    search !== "" || dateRange !== "all" || sortBy !== "";

  // Reset pagination + selection whenever filters change. The query itself
  // refetches automatically because the params change the cache key.
  useEffect(() => {
    setOffset(0);
    setExpandedId(null);
    setSelectedIds(new Set());
  }, [source, severity, statusFilter, search, sortBy, sortDir, dateRange]);

  // Build the params object that drives both the query and any cache writes.
  // Memoized so the queryKey stays referentially stable across renders that
  // don't actually change a filter.
  const queryParams = useMemo<DetectionsParams>(() => {
    const p: DetectionsParams = { limit: LIMIT, offset };
    if (source) p.source = source;
    if (severity) p.severity = severity;
    if (statusFilter) p.status = statusFilter;
    if (search) p.search = search;
    if (sortBy) p.sort_by = sortBy;
    if (sortDir) p.sort_dir = sortDir;
    const afterDate = getAfterDate();
    if (afterDate) p.after = afterDate;
    return p;
  // getAfterDate depends on dateRange — include it via dateRange
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source, severity, statusFilter, search, sortBy, sortDir, dateRange, offset]);

  const { data, isLoading, isError, refetch } = useDetections(queryParams);

  const items = useMemo(() => data?.items ?? [], [data]);
  const total = data?.total ?? 0;

  // Track new detections — compare against the last-seen id whenever a fresh
  // payload arrives from the server. The first payload only sets a baseline
  // (no banner), subsequent fetches surface anything above lastSeenId.
  useEffect(() => {
    if (items.length === 0) return;
    const maxId = Math.max(...items.map((d) => d.id));

    if (!hasInitialized.current) {
      hasInitialized.current = true;
      setLastSeenId(maxId);
      localStorage.setItem("slink_last_seen_id", String(maxId));
      setNewCount(0);
      return;
    }

    if (maxId > lastSeenId) {
      setNewCount(items.filter((d) => d.id > lastSeenId).length);
    } else {
      setNewCount(0);
    }
  }, [items, lastSeenId]);

  // Locally update the cached detection so the row reflects the new status
  // immediately. The 30s background poll will reconcile against the server.
  function handleStatusChange(id: number, newStatus: Detection["status"]) {
    queryClient.setQueryData<DetectionListResponse | undefined>(
      detectionsKey(queryParams),
      (prev) =>
        prev
          ? {
              ...prev,
              items: prev.items.map((d) =>
                d.id === id ? { ...d, status: newStatus } : d
              ),
            }
          : prev
    );
  }

  // Bulk selection helpers
  function toggleSelect(id: number) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    if (selectedIds.size === items.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(items.map((d) => d.id)));
    }
  }

  async function handleBulkAction(status: string) {
    try {
      await api.post("/detections/bulk-status", {
        ids: Array.from(selectedIds),
        status,
      });
      setSelectedIds(new Set());
      refetch();
    } catch {
      // refetch will surface any subsequent error via isError
    }
  }

  // New-detection banner click handler
  function dismissNewBanner() {
    const maxId = items.length > 0 ? Math.max(...items.map((d) => d.id)) : 0;
    setLastSeenId(maxId);
    localStorage.setItem("slink_last_seen_id", String(maxId));
    setNewCount(0);
    setOffset(0);
    refetch();
  }

  function clearFilters() {
    setSource("");
    setSeverity("");
    setStatusFilter("");
    setSearchInput("");
    setSearch("");
    setDateRange("all");
    setSortBy("");
    setSortDir("desc");
  }

  // CSV export — uses the api module so auth is handled automatically
  function handleExport() {
    const params = new URLSearchParams();
    if (source) params.set("source", source);
    if (severity) params.set("severity", severity);
    if (statusFilter) params.set("status", statusFilter);
    if (search) params.set("search", search);
    const afterDate = getAfterDate();
    if (afterDate) params.set("after", afterDate);

    api.get(`/detections/export?${params}`, { responseType: "blob" })
      .then((res) => {
        const blob = new Blob([res.data], { type: "text/csv" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `slink-detections-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      })
      .catch(() => {
        // Export errors are non-fatal — surfaced via the page-level error state
      });
  }

  // Severity counts from current page items
  const severityCounts = items.reduce<Record<string, number>>(
    (acc, d) => {
      acc[d.severity] = (acc[d.severity] ?? 0) + 1;
      return acc;
    },
    {}
  );

  const page = Math.floor(offset / LIMIT) + 1;
  const totalPages = Math.ceil(total / LIMIT);

  function goNext() {
    setOffset((prev) => prev + LIMIT);
    setExpandedId(null);
  }

  function goPrev() {
    setOffset((prev) => Math.max(0, prev - LIMIT));
    setExpandedId(null);
  }

  const inputStyle: React.CSSProperties = {
    padding: "7px 12px",
    borderRadius: 6,
    fontSize: 13,
    fontFamily: "var(--font-sans)",
    background: "var(--color-surface-1)",
    border: "1px solid var(--color-border)",
    color: "var(--color-text-primary)",
    outline: "none",
    transition: "border-color 120ms ease",
  };

  // Keyboard shortcut handlers — memoized to avoid re-registering on every render
  const shortcutHandlers = useMemo(
    () => ({
      onNext: () =>
        setActiveRowIndex((i) => Math.min(i + 1, items.length - 1)),
      onPrev: () => setActiveRowIndex((i) => Math.max(i - 1, 0)),
      onExpand: () => {
        if (activeRowIndex >= 0 && activeRowIndex < items.length) {
          const det = items[activeRowIndex];
          setExpandedId((prev) => (prev === det.id ? null : det.id));
        }
      },
      onCollapse: () => setExpandedId(null),
      onAcknowledge: () => {
        if (expandedId !== null) {
          api
            .patch(`/detections/${expandedId}/status`, { status: "acknowledged" })
            .then(() => handleStatusChange(expandedId, "acknowledged"))
            .catch(() => {/* status mutation errors are non-fatal */});
        }
      },
      onDismiss: () => {
        if (expandedId !== null) {
          api
            .patch(`/detections/${expandedId}/status`, { status: "dismissed" })
            .then(() => handleStatusChange(expandedId, "dismissed"))
            .catch(() => {/* status mutation errors are non-fatal */});
        }
      },
      onEscalate: () => {
        if (expandedId !== null) {
          api
            .patch(`/detections/${expandedId}/status`, { status: "escalated" })
            .then(() => handleStatusChange(expandedId, "escalated"))
            .catch(() => {/* status mutation errors are non-fatal */});
        }
      },
      onSearch: () => searchRef.current?.focus(),
      onHelp: () => setShowHelp((s) => !s),
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [items, activeRowIndex, expandedId]
  );

  useKeyboardShortcuts(shortcutHandlers);

  // Esc closes the help modal. Runs in the capture phase + stopPropagation so
  // it preempts useKeyboardShortcuts' Escape handler (which collapses rows).
  useEffect(() => {
    if (!showHelp) return;
    function handler(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.stopPropagation();
        setShowHelp(false);
      }
    }
    window.addEventListener("keydown", handler, { capture: true });
    return () => window.removeEventListener("keydown", handler, { capture: true });
  }, [showHelp]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap gap-y-2">
        <h1
          className="text-xl font-semibold"
          style={{ color: "var(--color-text-primary)" }}
        >
          Detection Feed
          {!isLoading && (
            <span
              className="ml-2 text-sm font-normal"
              style={{ color: "var(--color-text-tertiary)" }}
            >
              {total.toLocaleString()} total
            </span>
          )}
        </h1>

        {/* Severity summary bar — counts from current page */}
        {!isLoading && items.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap">
            {(["critical", "high", "medium", "low"] as Detection["severity"][])
              .filter((s) => severityCounts[s])
              .map((s) => {
                const { color, bg } = severitySummaryConfig[s];
                return (
                  <button
                    key={s}
                    onClick={() => setSeverity(severity === s ? "" : s)}
                    style={{
                      padding: "3px 10px",
                      borderRadius: 4,
                      fontSize: 12,
                      fontWeight: 500,
                      background: severity === s ? bg : "transparent",
                      border: `1px solid ${severity === s ? color + "66" : "var(--color-border)"}`,
                      color: severity === s ? color : "var(--color-text-secondary)",
                      cursor: "pointer",
                      transition: "all 120ms ease",
                    }}
                    title={`Filter by ${s}`}
                  >
                    {severityCounts[s]} {s}
                  </button>
                );
              })}
          </div>
        )}
      </div>

      {/* Filter bar */}
      <div className="flex gap-3 flex-wrap items-center">
        {/* Search input with debounce — ref used by keyboard shortcut "/" */}
        <input
          ref={searchRef}
          type="text"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          placeholder="Search detections…"
          className="w-full sm:w-[220px] sm:flex-none"
          style={{ ...inputStyle, minWidth: 0 }}
          onFocus={(e) => { e.currentTarget.style.borderColor = "var(--color-accent)" }}
          onBlur={(e) => { e.currentTarget.style.borderColor = "var(--color-border)" }}
        />

        {/* Source dropdown */}
        <select
          value={source}
          onChange={(e) => setSource(e.target.value)}
          style={inputStyle}
          onFocus={(e) => { e.currentTarget.style.borderColor = "var(--color-accent)" }}
          onBlur={(e) => { e.currentTarget.style.borderColor = "var(--color-border)" }}
        >
          <option value="">All sources</option>
          {sourceOptions.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>

        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value as Detection["severity"] | "")}
          style={inputStyle}
          onFocus={(e) => { e.currentTarget.style.borderColor = "var(--color-accent)" }}
          onBlur={(e) => { e.currentTarget.style.borderColor = "var(--color-border)" }}
        >
          <option value="">All severities</option>
          {SEVERITIES.filter(Boolean).map((s) => (
            <option key={s} value={s}>
              {s!.charAt(0).toUpperCase() + s!.slice(1)}
            </option>
          ))}
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as Detection["status"] | "")}
          style={inputStyle}
          onFocus={(e) => { e.currentTarget.style.borderColor = "var(--color-accent)" }}
          onBlur={(e) => { e.currentTarget.style.borderColor = "var(--color-border)" }}
        >
          <option value="">All statuses</option>
          {STATUSES.filter(Boolean).map((s) => (
            <option key={s} value={s}>
              {s!.charAt(0).toUpperCase() + s!.slice(1)}
            </option>
          ))}
        </select>

        {/* Date range presets */}
        <div className="flex items-center gap-1">
          {DATE_RANGE_OPTIONS.map((range) => (
            <button
              key={range}
              onClick={() => setDateRange(range)}
              style={{
                padding: "5px 10px",
                borderRadius: 12,
                fontSize: 12,
                fontWeight: 500,
                fontFamily: "var(--font-sans)",
                background: dateRange === range ? "var(--color-accent-muted)" : "var(--color-surface-2)",
                border: `1px solid ${dateRange === range ? "var(--color-accent)" : "var(--color-border)"}`,
                color: dateRange === range ? "var(--color-accent)" : "var(--color-text-secondary)",
                cursor: "pointer",
                transition: "all 120ms ease",
              }}
            >
              {range === "all" ? "All" : range}
            </button>
          ))}
        </div>

        {/* Export CSV */}
        <button
          onClick={handleExport}
          style={{
            padding: "7px 12px",
            borderRadius: 6,
            fontSize: 12,
            fontFamily: "var(--font-sans)",
            fontWeight: 500,
            background: "var(--color-surface-2)",
            border: "1px solid var(--color-border)",
            color: "var(--color-text-secondary)",
            cursor: "pointer",
            transition: "all 120ms ease",
          }}
        >
          Export CSV
        </button>

        {/* Clear filters button — only visible when filters are active */}
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            style={{
              padding: "7px 12px",
              borderRadius: 6,
              fontSize: 12,
              fontFamily: "var(--font-sans)",
              fontWeight: 500,
              background: "rgba(239,68,68,0.10)",
              border: "1px solid rgba(239,68,68,0.25)",
              color: "var(--color-danger)",
              cursor: "pointer",
              transition: "opacity 120ms ease",
            }}
          >
            Clear filters ✕
          </button>
        )}
      </div>

      {/* Error state */}
      {isError && (
        <div
          style={{
            padding: "12px 16px",
            borderRadius: 6,
            background: "rgba(239,68,68,0.08)",
            border: "1px solid rgba(239,68,68,0.25)",
            color: "var(--color-danger)",
            fontSize: 13,
          }}
        >
          Failed to load detections.
        </div>
      )}

      {/* New-detection banner */}
      {newCount > 0 && (
        <div
          onClick={dismissNewBanner}
          style={{
            padding: "10px 16px",
            borderRadius: 8,
            background: "var(--color-accent-muted)",
            border: "1px solid var(--color-accent)",
            color: "var(--color-accent)",
            fontSize: 13,
            fontWeight: 500,
            cursor: "pointer",
            transition: "background 120ms ease",
          }}
        >
          {"\uD83D\uDD14"} {newCount} new detection{newCount !== 1 ? "s" : ""} — click to refresh
        </div>
      )}

      {/* Bulk action bar — visible when detections are selected */}
      {selectedIds.size > 0 && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            padding: "10px 16px",
            borderRadius: 8,
            background: "var(--color-surface-1)",
            border: "1px solid var(--color-accent)",
          }}
        >
          <span
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: "var(--color-accent)",
              padding: "2px 10px",
              background: "var(--color-accent-muted)",
              borderRadius: 4,
            }}
          >
            {selectedIds.size} selected
          </span>
          <button
            onClick={() => setSelectedIds(new Set())}
            style={{
              padding: "5px 12px",
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 500,
              fontFamily: "var(--font-sans)",
              background: "transparent",
              border: "1px solid var(--color-border)",
              color: "var(--color-text-secondary)",
              cursor: "pointer",
              transition: "all 120ms ease",
            }}
          >
            Clear
          </button>
          <div style={{ flex: 1 }} />
          {[
            { label: "Acknowledge", status: "acknowledged" },
            { label: "Dismiss", status: "dismissed" },
            { label: "Escalate", status: "escalated" },
          ].map(({ label, status }) => (
            <button
              key={status}
              onClick={() => handleBulkAction(status)}
              style={{
                padding: "5px 12px",
                borderRadius: 6,
                fontSize: 12,
                fontWeight: 500,
                fontFamily: "var(--font-sans)",
                background: "var(--color-surface-2)",
                border: "1px solid var(--color-border)",
                color: "var(--color-text-secondary)",
                cursor: "pointer",
                transition: "all 120ms ease",
              }}
            >
              {label}
            </button>
          ))}
        </div>
      )}

      {/* Detection table */}
      <div
        style={{
          borderRadius: 8,
          border: "1px solid var(--color-border)",
          overflow: "hidden",
        }}
      >
        {/* Mobile card stack — below sm (640px). Matches same data as the
            desktop table; expanded row detail renders inline below the card. */}
        <div className="sm:hidden">
          {isLoading && items.length === 0 && (
            <div
              style={{
                padding: "24px 16px",
                textAlign: "center",
                fontSize: 13,
                color: "var(--color-text-tertiary)",
              }}
            >
              Loading…
            </div>
          )}
          {!isLoading && items.length === 0 && !isError && (
            <div
              style={{
                padding: "24px 16px",
                textAlign: "center",
                fontSize: 13,
                color: "var(--color-text-tertiary)",
              }}
            >
              No detections found.
            </div>
          )}
          {items.map((detection) => (
            <div key={detection.id}>
              <DetectionCard
                detection={detection}
                isExpanded={expandedId === detection.id}
                onToggle={() =>
                  setExpandedId(expandedId === detection.id ? null : detection.id)
                }
                selected={selectedIds.has(detection.id)}
                onSelect={toggleSelect}
              />
              {expandedId === detection.id && (
                <div
                  style={{
                    padding: "12px 14px",
                    background: "var(--color-surface-1)",
                    borderBottom: "1px solid var(--color-border)",
                    borderTop: "1px solid var(--color-border)",
                  }}
                >
                  {/* DetectionDetail renders a <tr>, which won't render outside
                      a <table>. Wrap in a minimal table so it displays correctly
                      in the card stack as well. */}
                  <table style={{ width: "100%" }}>
                    <tbody>
                      <DetectionDetail
                        detection={detection}
                        onStatusChange={handleStatusChange}
                      />
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Desktop table — sm (640px) and above */}
        <div className="hidden sm:block" style={{ overflowX: "auto", WebkitOverflowScrolling: "touch" }}>
        <table className="w-full text-left" style={{ minWidth: 900 }}>
          <thead>
            <tr
              style={{
                backgroundColor: "var(--color-surface-2)",
              }}
            >
              {/* Select-all checkbox */}
              <th className="px-3 py-3" style={{ width: 32 }}>
                <input
                  type="checkbox"
                  checked={items.length > 0 && selectedIds.size === items.length}
                  onChange={toggleSelectAll}
                  style={{
                    accentColor: "var(--color-accent)",
                    cursor: "pointer",
                    width: 15,
                    height: 15,
                  }}
                />
              </th>
              {["Severity", "Source", "Title", "Keywords", "First Seen", ""].map((h) => {
                const isSortable = h in SORTABLE_COLUMNS;
                const isActive = sortBy === SORTABLE_COLUMNS[h];
                return (
                  <th
                    key={h}
                    className="px-4 py-3"
                    onClick={isSortable ? () => handleSort(h) : undefined}
                    style={{
                      fontSize: 11,
                      fontWeight: 500,
                      textTransform: "uppercase",
                      letterSpacing: "0.5px",
                      color: isActive ? "var(--color-accent)" : "var(--color-text-tertiary)",
                      cursor: isSortable ? "pointer" : "default",
                      userSelect: isSortable ? "none" : undefined,
                      transition: "color 120ms ease",
                    }}
                  >
                    {h}
                    {isActive && (
                      <span style={{ marginLeft: 4, fontSize: 10 }}>
                        {sortDir === "asc" ? "▲" : "▼"}
                      </span>
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody
            style={{
              borderTop: "1px solid var(--color-border)",
            }}
          >
            {/* Rows are separated by border — applied per-row via style */}
            {isLoading && items.length === 0 && (
              <tr>
                <td
                  colSpan={7}
                  className="px-4 py-8 text-center text-sm"
                  style={{ color: "var(--color-text-tertiary)" }}
                >
                  Loading…
                </td>
              </tr>
            )}
            {!isLoading && items.length === 0 && !isError && (
              <tr>
                <td
                  colSpan={7}
                  className="px-4 py-8 text-center text-sm"
                  style={{ color: "var(--color-text-tertiary)" }}
                >
                  No detections found.
                </td>
              </tr>
            )}
            {items.map((detection, idx) => (
              <React.Fragment key={detection.id}>
                <DetectionRow
                  detection={detection}
                  isExpanded={expandedId === detection.id}
                  onToggle={() =>
                    setExpandedId(expandedId === detection.id ? null : detection.id)
                  }
                  isFirst={idx === 0}
                  selected={selectedIds.has(detection.id)}
                  onSelect={toggleSelect}
                  isActive={idx === activeRowIndex}
                />
                {expandedId === detection.id && (
                  <DetectionDetail
                    detection={detection}
                    onStatusChange={handleStatusChange}
                  />
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
        </div>{/* end horizontal scroll wrapper */}
      </div>

      {/* Pagination footer — "Showing N-M of TOTAL" with Prev/Next */}
      {data && total > 0 && (
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "12px 16px",
            borderTop: "1px solid var(--color-border)",
            marginTop: 8,
          }}
        >
          <span style={{ fontSize: 12, color: "var(--color-text-tertiary)" }}>
            Showing {offset + 1}-{Math.min(offset + LIMIT, total)} of {total}
            <span style={{ marginLeft: 12, opacity: 0.7 }}>
              Page {page} of {totalPages}
            </span>
          </span>
          <div style={{ display: "flex", gap: 8 }}>
            <Button
              size="sm"
              variant="secondary"
              disabled={offset === 0}
              onClick={goPrev}
            >
              Previous
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={offset + LIMIT >= total}
              onClick={goNext}
            >
              Next
            </Button>
          </div>
        </div>
      )}

      {/* Keyboard shortcuts help overlay */}
      {showHelp && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
            background: "rgba(0, 0, 0, 0.5)",
          }}
          onClick={() => setShowHelp(false)}
        >
          <div
            style={{
              background: "var(--color-surface-1)",
              border: "1px solid var(--color-border)",
              borderRadius: 12,
              padding: "24px 32px",
              minWidth: 340,
              boxShadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3
              style={{
                fontSize: 14,
                fontWeight: 600,
                color: "var(--color-text-primary)",
                marginBottom: 16,
                marginTop: 0,
              }}
            >
              Keyboard Shortcuts
            </h3>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {[
                { keys: "j / k", desc: "Navigate detections" },
                { keys: "Enter", desc: "Expand / collapse" },
                { keys: "a", desc: "Acknowledge" },
                { keys: "d", desc: "Dismiss" },
                { keys: "e", desc: "Escalate" },
                { keys: "/", desc: "Focus search" },
                { keys: "Esc", desc: "Collapse" },
                { keys: "?", desc: "Toggle this help" },
              ].map(({ keys, desc }) => (
                <div
                  key={keys}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 16,
                  }}
                >
                  <span
                    style={{
                      fontFamily: "var(--font-mono, monospace)",
                      fontSize: 12,
                      fontWeight: 600,
                      color: "var(--color-accent)",
                      background: "var(--color-surface-2)",
                      padding: "2px 8px",
                      borderRadius: 4,
                      border: "1px solid var(--color-border)",
                      minWidth: 60,
                      textAlign: "center",
                    }}
                  >
                    {keys}
                  </span>
                  <span
                    style={{
                      fontSize: 13,
                      color: "var(--color-text-secondary)",
                    }}
                  >
                    {desc}
                  </span>
                </div>
              ))}
            </div>
            <button
              onClick={() => setShowHelp(false)}
              style={{
                marginTop: 20,
                padding: "6px 16px",
                borderRadius: 6,
                fontSize: 12,
                fontWeight: 500,
                fontFamily: "var(--font-sans)",
                background: "var(--color-surface-2)",
                border: "1px solid var(--color-border)",
                color: "var(--color-text-secondary)",
                cursor: "pointer",
                width: "100%",
              }}
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
