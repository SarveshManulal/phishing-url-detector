"""Optional domain-age lookup (requires the ``python-whois`` package and network access)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def get_domain_age_days(domain: str) -> Optional[int]:
    """Return the domain's age in days, or None if it cannot be determined."""
    try:
        import whois  # python-whois
    except ImportError:
        return None
    try:
        record = whois.whois(domain)
    except Exception:  # WHOIS servers are flaky; never crash the scan
        return None

    created = record.creation_date
    if isinstance(created, list):
        created = min((c for c in created if isinstance(c, datetime)), default=None)
    if not isinstance(created, datetime):
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - created).days)
