import pytest

from config.settings import RiskConfig
from detection.indicators import (
    check_brand_impersonation,
    check_embedded_redirect,
    check_excessive_subdomains,
    check_executable_download,
    check_high_entropy_domain,
    check_idn_punycode,
    check_ip_host,
    check_phishing_keywords_in_path,
    check_suspicious_encoding,
    check_suspicious_tld,
    check_userinfo_at_symbol,
)
from detection.reputation import NullReputationProvider, ReputationResult
from detection.risk import severity_for_risk
from detection.url_analysis import analyze_url
from urllib.parse import urlparse

RISK = RiskConfig()


def _parts(url: str):
    parsed = urlparse(url)
    return parsed, (parsed.hostname or "").lower()


@pytest.mark.parametrize(
    "check, url, should_fire",
    [
        (check_ip_host, "http://203.0.113.5/login", True),
        (check_ip_host, "http://example.com/login", False),
        (check_suspicious_tld, "http://free-stuff.tk/", True),
        (check_suspicious_tld, "http://example.com/", False),
        (check_idn_punycode, "http://xn--pple-43d.com/", True),
        (check_idn_punycode, "http://apple.com/", False),
        (check_userinfo_at_symbol, "http://real-bank.com@evil.example/", True),
        (check_userinfo_at_symbol, "http://real-bank.com/", False),
        (check_excessive_subdomains, "http://a.b.c.d.e.example.com/", True),
        (check_excessive_subdomains, "http://www.example.com/", False),
        (check_brand_impersonation, "http://paypal-login.evil-domain.com/", True),
        (check_brand_impersonation, "http://paypal.com/", False),
        (check_phishing_keywords_in_path, "http://example.com/login?verify=account&confirm=1", True),
        (check_phishing_keywords_in_path, "http://example.com/blog/post-1", False),
        (check_executable_download, "http://example.com/setup.exe", True),
        (check_executable_download, "http://example.com/index.html", False),
        (check_embedded_redirect, "http://example.com/go?redirect=http://evil.example/x", True),
        (check_embedded_redirect, "http://example.com/go?redirect=http://example.com/x", False),
        (check_embedded_redirect, "http://example.com/", False),
        (check_high_entropy_domain, "http://xk28fjqmz91plw.com/", True),
        (check_high_entropy_domain, "http://example.com/", False),
    ],
)
def test_indicator_fires_as_expected(check, url, should_fire) -> None:
    parsed, hostname = _parts(url)
    result = check(url, parsed, hostname)
    assert (result is not None) == should_fire


def test_suspicious_encoding_fires_on_heavily_encoded_url() -> None:
    url = "http://example.com/" + "%41%42%43%44%45%46" * 3
    parsed, hostname = _parts(url)
    assert check_suspicious_encoding(url, parsed, hostname) is not None


def test_suspicious_encoding_does_not_fire_on_normal_url() -> None:
    url = "http://example.com/search?q=hello%20world"
    parsed, hostname = _parts(url)
    assert check_suspicious_encoding(url, parsed, hostname) is None


def test_analyze_benign_url_has_no_detection() -> None:
    analysis = analyze_url("https://example.com/about", RISK)
    assert analysis.risk == 0
    assert analysis.severity == "informational"
    assert analysis.reasons == ["No detection"]


def test_analyze_combines_multiple_indicators_into_higher_score() -> None:
    # IP host + executable + phishing keywords combined should score
    # meaningfully higher than any single indicator alone.
    analysis = analyze_url("http://203.0.113.9/login-verify-confirm/setup.exe", RISK)
    assert analysis.risk > 20
    assert len(analysis.reasons) >= 2
    assert "No detection" not in analysis.reasons


def test_single_weak_indicator_does_not_reach_high_severity() -> None:
    # A suspicious TLD alone (15 points) must never alone push into
    # High/Critical -- matches "never claim malicious from one weak
    # heuristic."
    analysis = analyze_url("http://some-blog.tk/", RISK)
    assert analysis.severity in ("informational", "low")


def test_severe_combination_reaches_high_or_critical() -> None:
    # Suspicious TLD (15) + brand impersonation in hostname (30) +
    # phishing keywords in path (10) + executable (15) should combine
    # well past the High threshold.
    analysis = analyze_url("http://paypal.security-verify-login.tk/account/verify-login.exe", RISK)
    assert analysis.severity in ("high", "critical")


def test_null_reputation_provider_never_contributes() -> None:
    provider = NullReputationProvider()
    assert provider.lookup("example.com") is None
    analysis = analyze_url("https://example.com/", RISK, reputation_provider=provider)
    assert analysis.risk == 0


def test_reputation_provider_contributes_when_it_has_data() -> None:
    class StubProvider:
        name = "stub"

        def lookup(self, domain: str):
            return ReputationResult(known_malicious=True, score_contribution=50, reason="Seen in feed X", provider="stub")

    analysis = analyze_url("https://example.com/", RISK, reputation_provider=StubProvider())
    assert analysis.risk == 50
    assert any("stub" in reason for reason in analysis.reasons)


def test_risk_score_is_capped_at_100() -> None:
    class MaxStubProvider:
        name = "stub"

        def lookup(self, domain: str):
            return ReputationResult(known_malicious=True, score_contribution=100, reason="max", provider="stub")

    analysis = analyze_url(
        "http://203.0.113.9/paypal-login-verify/update.exe", RISK, reputation_provider=MaxStubProvider()
    )
    assert analysis.risk == 100


@pytest.mark.parametrize(
    "risk, expected",
    [(0, "informational"), (20, "informational"), (21, "low"), (40, "low"), (41, "medium"), (60, "medium"), (61, "high"), (80, "high"), (81, "critical"), (100, "critical")],
)
def test_severity_for_risk_bands(risk: int, expected: str) -> None:
    assert severity_for_risk(risk, RISK) == expected
