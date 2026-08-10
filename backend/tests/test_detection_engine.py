"""
Tests for the detection engine.

Unit tests (no DB) validate the pure functions: hashing, keyword matching, and
severity scoring. Integration tests (require DB fixture) validate the full
process_raw_detection pipeline including dedup and intel-source filtering.
"""

from app.collectors.base import RawDetection
from app.services.detection_engine import (
    compute_content_hash,
    compute_victim_hash,
    match_keywords,
    score_severity,
    process_raw_detection,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_raw(
    source="darkweb_forum",
    title="Test Title",
    content="acme corp data breach sale",
    source_url="https://example.onion/thread/1",
    actor=None,
) -> RawDetection:
    return RawDetection(
        source=source,
        source_url=source_url,
        title=title,
        content=content,
        actor=actor,
    )


def kw(term: str, category: str = "brand") -> dict:
    return {"term": term, "category": category}


# ---------------------------------------------------------------------------
# Unit tests — compute_content_hash
# ---------------------------------------------------------------------------

def test_compute_content_hash_deterministic():
    """Same inputs always produce the same hash."""
    h1 = compute_content_hash("src", "title", "content")
    h2 = compute_content_hash("src", "title", "content")
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex digest


def test_compute_content_hash_varies():
    """Different inputs produce different hashes."""
    h1 = compute_content_hash("src", "title", "content A")
    h2 = compute_content_hash("src", "title", "content B")
    assert h1 != h2


def test_compute_content_hash_case_insensitive():
    """Normalisation means case differences don't create duplicate entries."""
    h1 = compute_content_hash("SRC", "TITLE", "CONTENT")
    h2 = compute_content_hash("src", "title", "content")
    assert h1 == h2


# ---------------------------------------------------------------------------
# Unit tests — match_keywords
# ---------------------------------------------------------------------------

def test_match_keywords_case_insensitive():
    """Matching is case-insensitive."""
    terms = [kw("ACME Corp")]
    matched = match_keywords("selling acme corp creds", terms)
    assert "ACME Corp" in matched


def test_match_keywords_multiple():
    """All matching terms are returned."""
    terms = [kw("acme corp"), kw("breach"), kw("unrelated_xyz")]
    matched = match_keywords("acme corp data breach", terms)
    assert "acme corp" in matched
    assert "breach" in matched
    assert "unrelated_xyz" not in matched


def test_match_keywords_no_match():
    """Returns empty list when nothing matches."""
    terms = [kw("acme corp")]
    matched = match_keywords("completely different text", terms)
    assert matched == []


def test_match_keywords_domain_substring():
    """Domain names (dots, no clear word boundary) match as substrings."""
    terms = [kw("acme.com")]
    matched = match_keywords("credentials for acme.com leaked", terms)
    assert "acme.com" in matched


def test_match_keywords_onion_address():
    """Onion addresses match as substrings even without word boundaries."""
    terms = [kw("abc123xyz.onion")]
    matched = match_keywords("forum at abc123xyz.onion selling data", terms)
    assert "abc123xyz.onion" in matched


# ---------------------------------------------------------------------------
# Integration tests — score_severity (DB-driven rules)
# ---------------------------------------------------------------------------

async def _seed_default_rules(db):
    """Insert the default severity rules that mirror the seed migration."""
    from app.models.severity_rule import SeverityRule

    rules = [
        SeverityRule(source_pattern="crowdstrike_recon", keyword_category="threat_actor", base_severity="critical", priority=100, enabled=True),
        SeverityRule(source_pattern="crowdstrike_recon", keyword_category=None, base_severity="high", priority=90, enabled=True),
        SeverityRule(source_pattern="crowdstrike_intel", keyword_category=None, base_severity="high", priority=80, enabled=True),
        SeverityRule(source_pattern=None, keyword_category="threat_actor", base_severity="high", priority=70, enabled=True),
        SeverityRule(source_pattern=None, keyword_category=None, base_severity="medium", priority=0, enabled=True),
    ]
    for rule in rules:
        db.add(rule)
    await db.commit()


async def test_score_severity_critical_for_recon_threat_actor(db):
    """CrowdStrike Recon + threat_actor category → critical."""
    await _seed_default_rules(db)
    severity = await score_severity("crowdstrike_recon", ["threat_actor"], db)
    assert severity == "critical"


async def test_score_severity_high_for_recon_no_threat_actor(db):
    """CrowdStrike Recon without threat_actor → high."""
    await _seed_default_rules(db)
    severity = await score_severity("crowdstrike_recon", ["brand"], db)
    assert severity == "high"


async def test_score_severity_high_for_threat_actor_any_source(db):
    """Any source with threat_actor category → high."""
    await _seed_default_rules(db)
    severity = await score_severity("darkweb_forum", ["threat_actor"], db)
    assert severity == "high"


async def test_score_severity_medium_for_single_brand(db):
    """A single brand match with no special source/category is medium."""
    await _seed_default_rules(db)
    severity = await score_severity("darkweb_forum", ["brand"], db)
    assert severity == "medium"


# ---------------------------------------------------------------------------
# Integration tests — process_raw_detection
# ---------------------------------------------------------------------------

async def test_process_raw_detection_creates_detection(db):
    """A new, previously-unseen detection is persisted and returned."""
    keywords = [kw("acme corp", "brand")]
    raw = make_raw(content="acme corp password dump for sale")

    detection = await process_raw_detection(raw, db, keywords)

    assert detection is not None
    assert detection.id is not None
    assert detection.source == "darkweb_forum"
    assert "acme corp" in detection.matched_keywords
    assert detection.status == "new"


async def test_process_raw_detection_dedup(db):
    """Processing the same raw detection twice returns None on the second pass
    and updates last_seen on the existing record."""
    keywords = [kw("acme corp", "brand")]
    raw = make_raw(content="acme corp password dump for sale")

    first = await process_raw_detection(raw, db, keywords)
    assert first is not None
    original_last_seen = first.last_seen

    # Identical raw payload → same content hash → dedup path
    second = await process_raw_detection(raw, db, keywords)
    assert second is None

    # Verify last_seen was bumped on the existing record
    await db.refresh(first)
    assert first.last_seen >= original_last_seen


async def test_process_raw_detection_intel_uses_actor_keywords(db):
    """crowdstrike_intel source only matches against threat_actor category keywords."""
    keywords = [
        kw("acme corp", "brand"),
        kw("SandWorm", "threat_actor"),
    ]
    # Content mentions brand term but NOT the actor — should produce no match
    raw_no_actor = make_raw(
        source="crowdstrike_intel",
        content="acme corp credentials available",
    )
    result = await process_raw_detection(raw_no_actor, db, keywords)
    # No threat_actor keyword matched → no detection created
    assert result is None

    # Content mentions the actor — should match
    raw_with_actor = make_raw(
        source="crowdstrike_intel",
        source_url="https://intel.example.com/report/2",
        content="SandWorm campaign targeting financial sector",
    )
    result2 = await process_raw_detection(raw_with_actor, db, keywords)
    assert result2 is not None
    assert "SandWorm" in result2.matched_keywords


async def test_process_raw_detection_suppresses_dismissed(db):
    """A detection with status 'dismissed' is not re-created on subsequent runs."""
    from app.models.detection import Detection
    from app.services.detection_engine import compute_content_hash

    raw = make_raw(content="acme corp dump dismissed scenario")
    keywords = [kw("acme corp", "brand")]

    # Pre-insert a dismissed detection with the matching hash
    content_hash = compute_content_hash(raw.source, raw.title, raw.content)
    existing = Detection(
        source=raw.source,
        title=raw.title,
        snippet=raw.content[:500],
        source_url=raw.source_url,
        content_hash=content_hash,
        matched_keywords=["acme corp"],
        severity="medium",
        status="dismissed",
        raw_data={},
    )
    db.add(existing)
    await db.commit()
    await db.refresh(existing)

    result = await process_raw_detection(raw, db, keywords)
    assert result is None


async def test_process_raw_detection_suppresses_acknowledged(db):
    """A detection with status 'acknowledged' is suppressed (not re-created)."""
    from app.models.detection import Detection
    from app.services.detection_engine import compute_content_hash

    raw = make_raw(content="acme corp dump acknowledged scenario")
    keywords = [kw("acme corp", "brand")]

    content_hash = compute_content_hash(raw.source, raw.title, raw.content)
    existing = Detection(
        source=raw.source,
        title=raw.title,
        snippet=raw.content[:500],
        source_url=raw.source_url,
        content_hash=content_hash,
        matched_keywords=["acme corp"],
        severity="medium",
        status="acknowledged",
        raw_data={},
    )
    db.add(existing)
    await db.commit()

    result = await process_raw_detection(raw, db, keywords)
    assert result is None


# ---------------------------------------------------------------------------
# Unit tests — compute_victim_hash
# ---------------------------------------------------------------------------

def test_compute_victim_hash_deterministic():
    """Same title always produces the same victim_hash."""
    h1 = compute_victim_hash("Acme Corp Breach")
    h2 = compute_victim_hash("Acme Corp Breach")
    assert h1 == h2
    assert len(h1) == 64


def test_compute_victim_hash_case_insensitive():
    """Victim hash is case-insensitive so ACME CORP == acme corp."""
    h1 = compute_victim_hash("ACME CORP BREACH")
    h2 = compute_victim_hash("acme corp breach")
    assert h1 == h2


def test_compute_victim_hash_excludes_source():
    """Victim hash is source-agnostic — same title from different sources matches."""
    # If source were included, these would differ; since it's not, they're equal
    h1 = compute_victim_hash("Acme Corp")
    h2 = compute_victim_hash("Acme Corp")
    assert h1 == h2


def test_compute_victim_hash_differs_for_different_titles():
    """Different victim titles produce different hashes."""
    h1 = compute_victim_hash("Acme Corp")
    h2 = compute_victim_hash("Beta Inc")
    assert h1 != h2


# ---------------------------------------------------------------------------
# Integration tests — cross-source dedup
# ---------------------------------------------------------------------------

async def test_cross_source_dedup_marks_duplicate(db):
    """When the same victim title appears from two sources within 24h, the
    second detection is stored with status='duplicate' and not returned as new."""
    keywords = [kw("acme corp", "brand")]

    # First detection: from ransomwatch
    raw_rw = make_raw(
        source="ransomwatch",
        title="Acme Corp",
        content="acme corp listed on ransomwatch",
        source_url="https://ransomwatch.example/post/1",
    )
    first = await process_raw_detection(raw_rw, db, keywords)
    assert first is not None
    assert first.status == "new"
    assert first.victim_hash is not None

    # Second detection: same victim title from ransomlook
    raw_rl = make_raw(
        source="ransomlook",
        title="Acme Corp",
        content="acme corp listed on ransomlook",
        source_url="https://ransomlook.example/post/2",
    )
    second = await process_raw_detection(raw_rl, db, keywords)
    # Cross-source duplicate — stored for completeness but marked "duplicate"
    assert second is not None
    assert second.status == "duplicate"
    # victim_hash must match the first detection's
    assert second.victim_hash == first.victim_hash


async def test_cross_source_dedup_does_not_affect_same_source(db):
    """Same title + same source → existing content_hash dedup path, not victim_hash."""
    keywords = [kw("acme corp", "brand")]

    raw = make_raw(
        source="ransomwatch",
        title="Acme Corp",
        content="acme corp listed on ransomwatch",
    )
    first = await process_raw_detection(raw, db, keywords)
    assert first is not None
    assert first.status == "new"

    # Exact same payload again — hits the content_hash dedup path (returns None)
    second = await process_raw_detection(raw, db, keywords)
    assert second is None  # deduped, not stored again


async def test_cross_source_dedup_different_victims_no_flag(db):
    """Different victim titles from different sources are NOT flagged as duplicates."""
    keywords = [kw("acme corp", "brand"), kw("beta inc", "brand")]

    raw_rw = make_raw(
        source="ransomwatch",
        title="Acme Corp",
        content="acme corp on ransomwatch",
    )
    raw_rl = make_raw(
        source="ransomlook",
        title="Beta Inc",
        content="beta inc on ransomlook",
    )

    first = await process_raw_detection(raw_rw, db, keywords)
    assert first is not None
    assert first.status == "new"

    second = await process_raw_detection(raw_rl, db, keywords)
    assert second is not None
    # Different victim — should be a fresh new detection, not a duplicate
    assert second.status == "new"


async def test_cross_source_dedup_three_sources_no_crash(db):
    """Regression: 3+ sources reporting the same victim within 24h must not crash.

    Previously scalar_one_or_none() raised MultipleResultsFound when the query
    returned 2+ rows. Using scalars().first() handles any number of matches.
    """
    keywords = [kw("acme corp", "brand")]

    # First detection: ransomwatch
    raw_rw = make_raw(
        source="ransomwatch",
        title="Acme Corp",
        content="acme corp listed on ransomwatch",
        source_url="https://ransomwatch.example/post/1",
    )
    first = await process_raw_detection(raw_rw, db, keywords)
    assert first is not None
    assert first.status == "new"

    # Second detection: ransomlook (same victim, different source)
    raw_rl = make_raw(
        source="ransomlook",
        title="Acme Corp",
        content="acme corp listed on ransomlook",
        source_url="https://ransomlook.example/post/2",
    )
    second = await process_raw_detection(raw_rl, db, keywords)
    assert second is not None
    assert second.status == "duplicate"

    # Third detection: darkweb_forum (same victim, yet another source)
    # Before the fix this would raise MultipleResultsFound
    raw_dw = make_raw(
        source="darkweb_forum",
        title="Acme Corp",
        content="acme corp listed on darkweb forum",
        source_url="https://darkweb.example/thread/3",
    )
    third = await process_raw_detection(raw_dw, db, keywords)
    assert third is not None
    assert third.status == "duplicate"
    assert third.victim_hash == first.victim_hash
