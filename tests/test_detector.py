import pytest

from phishing_detector import analyze, extract_features
from phishing_detector.features import registered_domain


def test_ip_address_host_detected():
    assert extract_features("http://192.168.10.5/login").uses_ip
    assert extract_features("http://3232235777/login").uses_ip  # decimal-encoded IP
    assert extract_features("http://0xC0A80101/x").uses_ip      # hex-encoded IP


def test_normal_domain_is_not_ip():
    assert not extract_features("https://www.example.com").uses_ip


def test_url_without_scheme_is_handled():
    f = extract_features("example.com/path")
    assert f.hostname == "example.com"
    assert not f.uses_https


def test_at_symbol_detected():
    assert extract_features("http://google.com@evil.example/").has_at_symbol


def test_registered_domain():
    assert registered_domain("mail.google.com") == "google.com"
    assert registered_domain("shop.example.co.uk") == "example.co.uk"


def test_brand_impersonation():
    assert extract_features("http://paypal-secure.evil-site.tk").brand_impersonation == "paypal"
    assert extract_features("https://google.com.evil.tk/").brand_impersonation == "google"
    assert extract_features("https://accounts.google.com/").brand_impersonation is None


def test_keywords_and_punycode():
    f = extract_features("http://xn--pypal-4ve.com/verify/login")
    assert f.is_punycode
    assert {"verify", "login"} <= set(f.path_keywords)


def test_malformed_port_does_not_crash():
    extract_features("http://example.com:notaport/")


@pytest.mark.parametrize("url", [
    "https://www.google.com",
    "https://github.com/anthropics",
    "https://en.wikipedia.org/wiki/Phishing",
])
def test_legitimate_urls_score_safe(url):
    assert analyze(url).verdict == "LIKELY SAFE"


@pytest.mark.parametrize("url", [
    "http://secure-paypal-login.verify-account.tk/update",
    "http://192.168.1.50:8080/bank/login//confirm",
    "http://apple.com@login-verify.example-secure.xyz/",
])
def test_phishing_style_urls_are_flagged(url):
    assert analyze(url).verdict == "PHISHING"


def test_score_is_capped_and_explained():
    r = analyze("http://secure-paypal-login.verify-account.tk/update")
    assert 0 <= r.score <= 100
    assert r.reasons


def test_young_domain_raises_score(monkeypatch):
    monkeypatch.setattr("phishing_detector.detector.get_domain_age_days", lambda d: 5)
    base = analyze("https://example.com").score
    assert analyze("https://example.com", check_whois=True).score == base + 30
