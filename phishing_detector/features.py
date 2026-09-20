"""URL feature extraction.

Everything here is pure string analysis (no network access), so it is fast,
deterministic and easy to unit test. Domain age is the only network-based
feature and lives in ``whois_lookup.py``.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Optional
from urllib.parse import unquote, urlparse

SUSPICIOUS_KEYWORDS = (
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "confirm", "password", "wallet", "suspend", "unlock", "invoice", "billing",
)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

# TLDs that are heavily abused (cheap or free registration).
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "work", "loan", "icu"}

# Frequently impersonated brands.
BRANDS = (
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "dropbox", "dhl", "fedex",
    "sbi", "hdfc", "icici", "paytm",
)

_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}


@dataclass
class UrlFeatures:
    url: str
    hostname: str
    registered_domain: str
    url_length: int
    hostname_length: int
    path_length: int
    num_dots: int
    num_hyphens_host: int
    digit_ratio_host: float
    subdomain_count: int
    uses_ip: bool
    has_at_symbol: bool
    uses_https: bool
    has_custom_port: bool
    is_punycode: bool
    is_shortener: bool
    suspicious_tld: bool
    double_slash_in_path: bool
    encoded_chars: int
    host_entropy: float
    host_keywords: list = field(default_factory=list)
    path_keywords: list = field(default_factory=list)
    brand_impersonation: Optional[str] = None
    domain_age_days: Optional[int] = None

    def as_dict(self) -> dict:
        return asdict(self)


# Numeric features used by the optional ML model (no network features).
FEATURE_NAMES = (
    "url_length", "hostname_length", "path_length", "num_dots",
    "num_hyphens_host", "digit_ratio_host", "subdomain_count", "uses_ip",
    "has_at_symbol", "uses_https", "has_custom_port", "is_punycode",
    "is_shortener", "suspicious_tld", "double_slash_in_path", "encoded_chars",
    "host_entropy", "n_host_keywords", "n_path_keywords", "brand_impersonation",
)


def normalize_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    return url


def _is_ip_host(host: str) -> bool:
    """True for dotted IPv4/IPv6 plus decimal (3232235777) and hex (0xC0A80101) forms."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if re.fullmatch(r"\d{8,10}", host) and int(host) <= 0xFFFFFFFF:
        return True
    return bool(re.fullmatch(r"0x[0-9a-f]+", host))


def registered_domain(host: str) -> str:
    """Approximate the registrable domain (example.co.uk, example.com)."""
    if _is_ip_host(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _find_brand(host: str, reg_domain: str) -> Optional[str]:
    """Brand name appears in the hostname but the real owner domain is someone else."""
    tokens = set()
    for token in re.split(r"[.\-_]", host):
        tokens.add(token)
        tokens.add(re.sub(r"\d+", "", token))
    owner = reg_domain.split(".")[0]
    for brand in BRANDS:
        if brand in tokens and owner != brand:
            return brand
    return None


def extract_features(url: str) -> UrlFeatures:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        port = None

    uses_ip = _is_ip_host(host)
    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    subdomains = 0 if uses_ip else max(0, len(host.split(".")) - len(reg.split(".")))
    digits = sum(ch.isdigit() for ch in host)
    path_query = parsed.path + (("?" + parsed.query) if parsed.query else "")
    decoded = unquote(path_query).lower()

    return UrlFeatures(
        url=url.strip(),
        hostname=host,
        registered_domain=reg,
        url_length=len(normalized),
        hostname_length=len(host),
        path_length=len(parsed.path),
        num_dots=host.count("."),
        num_hyphens_host=host.count("-"),
        digit_ratio_host=round(digits / len(host), 3) if host else 0.0,
        subdomain_count=subdomains,
        uses_ip=uses_ip,
        has_at_symbol="@" in parsed.netloc,
        uses_https=parsed.scheme == "https",
        has_custom_port=port not in (None, 80, 443),
        is_punycode="xn--" in host,
        is_shortener=reg in URL_SHORTENERS,
        suspicious_tld=tld in SUSPICIOUS_TLDS,
        double_slash_in_path="//" in parsed.path,
        encoded_chars=len(re.findall(r"%[0-9a-fA-F]{2}", path_query)),
        host_entropy=round(shannon_entropy(host), 3),
        host_keywords=[k for k in SUSPICIOUS_KEYWORDS if k in host],
        path_keywords=[k for k in SUSPICIOUS_KEYWORDS if k in decoded],
        brand_impersonation=None if uses_ip else _find_brand(host, reg),
    )


def feature_vector(f: UrlFeatures) -> list:
    """Numeric vector in FEATURE_NAMES order, for scikit-learn."""
    return [
        f.url_length, f.hostname_length, f.path_length, f.num_dots,
        f.num_hyphens_host, f.digit_ratio_host, f.subdomain_count,
        int(f.uses_ip), int(f.has_at_symbol), int(f.uses_https),
        int(f.has_custom_port), int(f.is_punycode), int(f.is_shortener),
        int(f.suspicious_tld), int(f.double_slash_in_path), f.encoded_chars,
        f.host_entropy, len(f.host_keywords), len(f.path_keywords),
        int(f.brand_impersonation is not None),
    ]
