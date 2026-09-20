"""Rule-based scoring engine. Every point added comes with a human-readable reason."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .features import UrlFeatures, extract_features
from .whois_lookup import get_domain_age_days

PHISHING_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 30


@dataclass
class Result:
    url: str
    score: int
    verdict: str
    reasons: list = field(default_factory=list)
    features: Optional[UrlFeatures] = None

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "score": self.score,
            "verdict": self.verdict,
            "reasons": self.reasons,
            "features": self.features.as_dict() if self.features else None,
        }


def score_features(f: UrlFeatures) -> tuple:
    score, reasons = 0, []

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(f"+{points}: {reason}")

    if f.uses_ip:
        add(35, "hostname is an IP address instead of a domain name")
    if f.has_at_symbol:
        add(20, "'@' in the URL can hide the real destination")
    if not f.uses_https:
        add(10, "does not use HTTPS")
    if f.url_length > 120:
        add(15, f"very long URL ({f.url_length} chars)")
    elif f.url_length > 75:
        add(10, f"long URL ({f.url_length} chars)")
    if f.subdomain_count >= 3:
        add(15, f"many subdomains ({f.subdomain_count})")
    if f.num_hyphens_host >= 2:
        add(8, f"{f.num_hyphens_host} hyphens in hostname")
    if f.host_keywords:
        add(min(len(f.host_keywords), 2) * 10, f"suspicious keywords in hostname: {', '.join(f.host_keywords)}")
    if f.path_keywords:
        add(min(len(f.path_keywords), 2) * 5, f"suspicious keywords in path: {', '.join(f.path_keywords)}")
    if f.brand_impersonation:
        add(25, f"mentions '{f.brand_impersonation}' but the domain belongs to '{f.registered_domain}'")
    if f.is_punycode:
        add(15, "punycode (xn--) hostname, possible lookalike characters")
    if f.is_shortener:
        add(10, "URL shortener hides the final destination")
    if f.suspicious_tld:
        add(15, "TLD is commonly abused")
    if f.has_custom_port:
        add(10, "non-standard port")
    if f.double_slash_in_path:
        add(10, "'//' in path, possible redirect trick")
    if f.encoded_chars >= 3:
        add(5, f"{f.encoded_chars} percent-encoded characters")
    if f.digit_ratio_host > 0.3 and not f.uses_ip:
        add(10, "hostname contains a high share of digits")
    if f.host_entropy > 3.8 and f.hostname_length >= 12 and not f.uses_ip:
        add(10, "hostname looks randomly generated (high entropy)")

    if f.domain_age_days is not None:
        if f.domain_age_days < 30:
            add(30, f"domain registered only {f.domain_age_days} days ago")
        elif f.domain_age_days < 180:
            add(15, f"domain is young ({f.domain_age_days} days old)")

    return min(score, 100), reasons


def analyze(url: str, check_whois: bool = False) -> Result:
    features = extract_features(url)
    if check_whois and not features.uses_ip and features.registered_domain:
        features.domain_age_days = get_domain_age_days(features.registered_domain)

    score, reasons = score_features(features)
    if score >= PHISHING_THRESHOLD:
        verdict = "PHISHING"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY SAFE"
    return Result(url=url.strip(), score=score, verdict=verdict, reasons=reasons, features=features)
