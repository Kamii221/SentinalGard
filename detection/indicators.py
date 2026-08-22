"""Individual local URL heuristics.

Each indicator only *contributes* points toward the overall risk score
-- none of them alone declares a URL malicious. Combinations of several
independent signals are what push a score into Medium/High/Critical;
see detection/url_analysis.py for how these are combined.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable
from urllib.parse import ParseResult, parse_qsl, urlparse

from detection.entropy import shannon_entropy

_SUSPICIOUS_TLDS = frozenset(
    {
        "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "link",
        "zip", "country", "stream", "gdn", "loan", "win", "review", "party",
        "accountant", "science", "men", "date", "faith", "kim",
    }
)

_EXECUTABLE_EXTENSIONS = frozenset(
    {".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".apk", ".jse", ".wsf", ".hta", ".dll"}
)

_BRAND_KEYWORDS = frozenset(
    {
        "paypal", "google", "microsoft", "apple", "amazon", "bank", "chase",
        "wellsfargo", "netflix", "facebook", "instagram", "office365",
        "outlook", "icloud", "coinbase", "binance",
    }
)

_PHISHING_KEYWORDS = frozenset(
    {"login", "verify", "secure", "update", "confirm", "account", "signin", "password", "billing", "suspended"}
)

_REDIRECT_PARAM_NAMES = frozenset({"url", "redirect", "next", "dest", "destination", "continue", "return"})


@dataclass(frozen=True)
class Indicator:
    points: int
    reason: str


IndicatorFn = Callable[[str, ParseResult, str], "Indicator | None"]


def _tld(hostname: str) -> str:
    parts = hostname.rstrip(".").split(".")
    return parts[-1] if parts else ""


def check_ip_host(url: str, parsed: ParseResult, hostname: str) -> Indicator | None:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return None
    return Indicator(20, f"Destination is a raw IP address ({hostname}) rather than a domain name")


def check_suspicious_tld(url: str, parsed: ParseResult, hostname: str) -> Indicator | None:
    tld = _tld(hostname)
    if tld in _SUSPICIOUS_TLDS:
        return Indicator(15, f"Domain uses a TLD often associated with abuse (.{tld})")
    return None


def check_idn_punycode(url: str, parsed: ParseResult, hostname: str) -> Indicator | None:
    if any(label.startswith("xn--") for label in hostname.split(".") if label):
        return Indicator(
            10,
            "Domain is an internationalized (punycode) name -- verify it's the site you expect; "
            "lookalike Unicode characters are a common phishing trick",
        )
    return None


def check_userinfo_at_symbol(url: str, parsed: ParseResult, hostname: str) -> Indicator | None:
    # A URL like http://real-bank.com@evil.example/ visually resembles
    # real-bank.com but actually navigates to evil.example -- urlparse
    # correctly splits "real-bank.com" out as the username.
    if parsed.username:
        return Indicator(
            25,
            f"URL disguises its real destination: text before '@' looks like a domain "
            f"('{parsed.username}') but the actual host is '{hostname}'",
        )
    return None


def check_excessive_subdomains(url: str, parsed: ParseResult, hostname: str) -> Indicator | None:
    labels = [p for p in hostname.split(".") if p]
    if len(labels) >= 5:
        return Indicator(
            10, f"Unusually long subdomain chain ({len(labels)} labels) can be used to obscure the real domain"
        )
    return None


def check_brand_impersonation(url: str, parsed: ParseResult, hostname: str) -> Indicator | None:
    labels = [p for p in hostname.split(".") if p]
    if len(labels) < 2:
        return None
    registrable = ".".join(labels[-2:])
    for brand in _BRAND_KEYWORDS:
        if brand in hostname and brand not in registrable:
            return Indicator(
                30,
                f"Hostname contains the brand name '{brand}' but is not that brand's actual domain "
                f"({hostname}) -- a common phishing pattern",
            )
    return None


def check_phishing_keywords_in_path(url: str, parsed: ParseResult, hostname: str) -> Indicator | None:
    path_and_query = (parsed.path + "?" + parsed.query).lower()
    hits = sorted(kw for kw in _PHISHING_KEYWORDS if kw in path_and_query)
    if len(hits) >= 2:
        return Indicator(10, f"URL path contains multiple phishing-associated keywords ({', '.join(hits)})")
    return None


def check_executable_download(url: str, parsed: ParseResult, hostname: str) -> Indicator | None:
    path = parsed.path.lower()
    for ext in _EXECUTABLE_EXTENSIONS:
        if path.endswith(ext):
            return Indicator(15, f"Link points directly to an executable/script file ({ext})")
    return None


def check_embedded_redirect(url: str, parsed: ParseResult, hostname: str) -> Indicator | None:
    for key, value in parse_qsl(parsed.query):
        if key.lower() in _REDIRECT_PARAM_NAMES and (value.startswith("http://") or value.startswith("https://")):
            target_host = (urlparse(value).hostname or "").lower()
            if target_host and target_host != hostname:
                return Indicator(
                    15, f"URL contains an embedded redirect (parameter '{key}') to a different domain ({target_host})"
                )
    return None


def check_suspicious_encoding(url: str, parsed: ParseResult, hostname: str) -> Indicator | None:
    encoded = url.count("%")
    if encoded >= 6 and len(url) > 0 and encoded / len(url) > 0.15:
        return Indicator(10, "URL contains an unusually high proportion of percent-encoded characters")
    return None


def check_high_entropy_domain(url: str, parsed: ParseResult, hostname: str) -> Indicator | None:
    labels = [p for p in hostname.split(".") if p]
    if len(labels) < 2:
        return None
    primary = labels[-2]
    if len(primary) >= 12 and shannon_entropy(primary) >= 3.6:
        return Indicator(
            15,
            f"Primary domain label looks algorithmically generated ('{primary}': high character "
            "randomness for its length) -- a pattern seen with malware C2 domains",
        )
    return None


ALL_INDICATORS: tuple[IndicatorFn, ...] = (
    check_ip_host,
    check_suspicious_tld,
    check_idn_punycode,
    check_userinfo_at_symbol,
    check_excessive_subdomains,
    check_brand_impersonation,
    check_phishing_keywords_in_path,
    check_executable_download,
    check_embedded_redirect,
    check_suspicious_encoding,
    check_high_entropy_domain,
)
