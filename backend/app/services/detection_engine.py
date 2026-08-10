"""
Detection Engine — core business logic for Slink.

This module is intentionally free of FastAPI dependencies so it can be called
from both the scheduler (Task 8) and tests without standing up the full app.
"""
import fnmatch
import hashlib
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.base import RawDetection
from app.models.detection import Detection
from app.models.severity_rule import SeverityRule
from app.utils.source_url import sanitize_source_url


# ---------------------------------------------------------------------------
# Content hash and victim hash
# ---------------------------------------------------------------------------

def compute_content_hash(source: str, title: str, content: str) -> str:
    """Return a SHA-256 hex digest of the normalised source|title|content string.

    Normalisation (lowercase + strip) means minor whitespace or capitalisation
    differences don't create spurious duplicate detections.
    """
    normalised = "|".join([
        source.strip().lower(),
        title.strip().lower(),
        content.strip().lower(),
    ])
    return hashlib.sha256(normalised.encode()).hexdigest()


def compute_victim_hash(title: str) -> str:
    """Return a SHA-256 hex digest of the normalised title only (no source prefix).

    This source-agnostic hash lets us identify when two different collectors
    (e.g. RansomWatch and Ransomlook) have reported the same victim. Because
    the source is not included in the hash, the same victim title from any
    source produces the same victim_hash.
    """
    normalised = title.strip().lower()
    return hashlib.sha256(normalised.encode()).hexdigest()


# How far back to look for cross-source duplicates (24 hours)
_CROSS_SOURCE_WINDOW = timedelta(hours=24)


# ---------------------------------------------------------------------------
# Keyword matching
# ---------------------------------------------------------------------------

# Terms that contain dots or hyphens (e.g. "acme.com", "abc123.onion",
# "multi-word-slug") don't have clean word boundaries in all regex flavours,
# so we fall back to a plain case-insensitive substring search for them.
_BOUNDARY_UNSAFE = re.compile(r"[.\-]")


def _has_word_boundary(term: str) -> bool:
    """Return True if the term is safe to wrap in word-boundary anchors."""
    return not _BOUNDARY_UNSAFE.search(term)


def match_keywords(content: str, keywords: list[dict]) -> list[str]:
    """Return the list of keyword terms that appear in *content*.

    Args:
        content:  The text to search (title + body combined by the caller).
        keywords: List of dicts with at minimum a 'term' key.

    Returns:
        List of matched term strings (preserving original capitalisation).
    """
    matched: list[str] = []
    lower_content = content.lower()

    for kw in keywords:
        term: str = kw["term"]
        lower_term = term.lower()

        if _has_word_boundary(term):
            # Word-boundary regex — avoids matching "acme" inside "acmecorp"
            pattern = re.compile(r"\b" + re.escape(lower_term) + r"\b")
            if pattern.search(lower_content):
                matched.append(term)
        else:
            # Substring fallback for domains, onion addresses, hyphenated slugs
            if lower_term in lower_content:
                matched.append(term)

    return matched


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------

async def score_severity(
    source: str,
    matched_categories: list[str],
    db: AsyncSession,
) -> str:
    """Score severity using DB-driven rules. First match (highest priority) wins.

    Rules are stored in the severity_rules table and evaluated in descending
    priority order. Each rule specifies an optional source glob pattern and/or
    keyword category to match against. The first rule where both conditions are
    satisfied determines the severity label.
    """
    result = await db.execute(
        select(SeverityRule)
        .where(SeverityRule.enabled == True)  # noqa: E712
        .order_by(SeverityRule.priority.desc())
    )
    rules = result.scalars().all()

    for rule in rules:
        # Check source pattern match (None or "*" means match any source)
        source_match = (
            rule.source_pattern is None
            or rule.source_pattern == "*"
            or fnmatch.fnmatch(source, rule.source_pattern)
        )

        # Check keyword category match (None or "*" means match any categories)
        category_match = (
            rule.keyword_category is None
            or rule.keyword_category == "*"
            or any(cat == rule.keyword_category for cat in matched_categories)
            or any(
                cat.startswith(rule.keyword_category)
                for cat in matched_categories
                if rule.keyword_category and ":" in rule.keyword_category
            )
        )

        if source_match and category_match:
            return rule.base_severity

    return "medium"  # fallback if no rules match


# ---------------------------------------------------------------------------
# Full detection pipeline
# ---------------------------------------------------------------------------

async def process_raw_detection(
    raw: RawDetection,
    db: AsyncSession,
    keywords: list[dict],
) -> Detection | None:
    """Process a single RawDetection through the full pipeline.

    Steps:
      1. Filter keywords by source type (intel sources → threat_actor only).
      2. Match keywords against combined title + content text.
      3. If nothing matches, return None (no detection to create).
      4. Compute content_hash; check for an exact same-source duplicate.
         - Exists + suppressed status (acknowledged/dismissed) → return None.
         - Exists + active status → update last_seen, return None (dedup).
      5. Compute victim_hash; check for a cross-source duplicate within 24h.
         - If found: persist the detection but mark it "duplicate" so it is
           stored for audit completeness but does NOT trigger notifications.
      6. New unique detection → persist with status "new" and return it.

    Returns:
        The newly created Detection (status "new" or "duplicate"),
        or None if deduped/suppressed/no-match.

        Note: "duplicate" status detections are returned so the caller can
        record them, but the scheduler skips them for notifications.
    """
    # Step 1: source-specific keyword filtering
    if raw.source == "crowdstrike_intel":
        active_keywords = [k for k in keywords if k.get("category") == "threat_actor"]
    else:
        active_keywords = list(keywords)

    # Step 2: keyword matching against title + content
    search_text = f"{raw.title} {raw.content}"
    matched_terms = match_keywords(search_text, active_keywords)

    if not matched_terms:
        return None

    # Derive categories for the matched terms so we can score severity
    term_to_category = {k["term"]: k.get("category", "") for k in active_keywords}
    matched_categories = [term_to_category.get(t, "") for t in matched_terms]

    # Step 3: compute content_hash and check for an exact same-source duplicate
    content_hash = compute_content_hash(raw.source, raw.title, raw.content)

    result = await db.execute(
        select(Detection).where(Detection.content_hash == content_hash)
    )
    existing = result.scalar_one_or_none()

    if existing is not None:
        # Permanently suppressed — never re-surface
        if existing.status in ("acknowledged", "dismissed"):
            return None

        # Active duplicate from the same source — bump last_seen to track recurrence
        existing.last_seen = datetime.now(timezone.utc)
        await db.flush()  # caller commits the whole batch
        return None

    # Step 4: compute victim_hash and check for cross-source duplicate within 24h.
    # This catches the case where RansomWatch and Ransomlook both report the same
    # victim — they'll share a victim_hash even though their content_hashes differ.
    victim_hash = compute_victim_hash(raw.title)
    cutoff = datetime.now(timezone.utc) - _CROSS_SOURCE_WINDOW

    cross_source_result = await db.execute(
        select(Detection).where(
            and_(
                Detection.victim_hash == victim_hash,
                Detection.source != raw.source,       # different source = cross-source
                Detection.created_at >= cutoff,
            )
        )
    )
    cross_source_existing = cross_source_result.scalars().first()

    # Determine status: cross-source duplicates are stored but not notified
    detection_status = "duplicate" if cross_source_existing is not None else "new"

    # Step 5: persist the detection
    severity = await score_severity(raw.source, matched_categories, db)

    detection = Detection(
        source=raw.source,
        title=raw.title,
        # Store up to 500 chars as the visible snippet; full content in raw_data
        snippet=raw.content[:500],
        source_url=sanitize_source_url(raw.source, raw.source_url),
        content_hash=content_hash,
        victim_hash=victim_hash,
        matched_keywords=matched_terms,
        severity=severity,
        status=detection_status,
        raw_data=raw.raw_payload,
    )
    db.add(detection)
    await db.flush()  # populates detection.id; caller commits the whole batch

    return detection
