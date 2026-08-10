"""Collector registry — maps source names to collector classes.

Order here is the order sources show up in the Source Status UI and the
poll order. Free, no-account collectors come first, then free-with-signup,
then paid/enterprise. Sources auto-disable when their credentials are
missing — every collector is independent and any subset can be turned off.

To add a new source: implement a class extending ``BaseCollector`` (see
``base.py`` and ``docs/COLLECTORS.md``), import it below, and register it
in ``COLLECTOR_REGISTRY``. No other code needs to change.
"""

# Free, no-account sources
from app.collectors.ransomwatch import RansomWatchCollector
from app.collectors.ransomlook import RansomlookCollector
from app.collectors.cisa_kev import CISAKEVCollector

# Free, signup or auth-key required.
#
# All four abuse.ch collectors share a single Auth-Key (settings.abusech_auth_key,
# attached via app.collectors.abusech_auth.AbuseChAuth). Free signup at
# https://auth.abuse.ch — abuse.ch made Auth-Key mandatory across all feeds in 2025.
#
# NVD works without a key (rate-limited at 5 req / 30 s anonymous, 50 with
# a key). GitHub Advisories require a token to be usable in practice
# (60 req/h unauthenticated); the collector auto-disables when GITHUB_TOKEN
# is unset.
from app.collectors.threatfox import ThreatFoxCollector
from app.collectors.urlhaus import URLhausCollector
from app.collectors.malwarebazaar import MalwareBazaarCollector
from app.collectors.feodo_tracker import FeodoTrackerCollector
from app.collectors.alienvault_otx import AlienVaultOTXCollector
from app.collectors.nvd import NVDCollector
from app.collectors.github_advisory import GitHubAdvisoryCollector

# Paid / enterprise (optional)
from app.collectors.crowdstrike_recon import CrowdStrikeReconCollector
from app.collectors.crowdstrike_intel import CrowdStrikeIntelCollector

COLLECTOR_REGISTRY: dict[str, type] = {
    # Free, no account
    "ransomwatch": RansomWatchCollector,
    "ransomlook": RansomlookCollector,
    "cisa_kev": CISAKEVCollector,
    # Free with signup / auth key
    "threatfox": ThreatFoxCollector,
    "urlhaus": URLhausCollector,
    "malwarebazaar": MalwareBazaarCollector,
    "feodo_tracker": FeodoTrackerCollector,
    "alienvault_otx": AlienVaultOTXCollector,
    "nvd": NVDCollector,
    "github_advisory": GitHubAdvisoryCollector,
    # Paid (optional)
    "crowdstrike_recon": CrowdStrikeReconCollector,
    "crowdstrike_intel": CrowdStrikeIntelCollector,
}
