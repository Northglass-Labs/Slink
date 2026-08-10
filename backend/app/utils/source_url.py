"""Allowlist external investigation links emitted by threat-intel sources."""

from urllib.parse import urlsplit


_SOURCE_HOSTS: dict[str, tuple[str, ...]] = {
    "alienvault_otx": ("otx.alienvault.com",),
    "cisa_kev": ("cisa.gov", "www.cisa.gov"),
    "crowdstrike_intel": (".crowdstrike.com",),
    "crowdstrike_recon": (".crowdstrike.com",),
    "feodo_tracker": ("feodotracker.abuse.ch",),
    "github_advisory": ("github.com",),
    "malwarebazaar": ("bazaar.abuse.ch",),
    "nvd": ("nvd.nist.gov",),
    "ransomlook": ("ransomlook.io", "www.ransomlook.io"),
    "ransomwatch": ("ransomware.live", "www.ransomware.live"),
    "threatfox": ("threatfox.abuse.ch",),
    "urlhaus": ("urlhaus.abuse.ch",),
}


def _host_matches(hostname: str, pattern: str) -> bool:
    if pattern.startswith("."):
        return hostname.endswith(pattern) and hostname != pattern[1:]
    return hostname == pattern


def sanitize_source_url(source: str, url: str | None) -> str:
    """Return a safe provider URL or an empty string for an unsafe value."""
    if not url or any(ord(char) < 32 for char in url):
        return ""
    try:
        parsed = urlsplit(url.strip())
        hostname = (parsed.hostname or "").encode("idna").decode("ascii").lower()
        port = parsed.port
    except (UnicodeError, ValueError):
        return ""
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
    ):
        return ""
    patterns = _SOURCE_HOSTS.get(source, ())
    if not any(_host_matches(hostname, pattern) for pattern in patterns):
        return ""
    return url.strip()
