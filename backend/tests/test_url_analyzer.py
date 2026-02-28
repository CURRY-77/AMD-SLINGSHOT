"""
Tests for the URL Analyzer precision improvements.
Run: cd /home/divyansh/AMD-SLINGSHOT/backend && source venv/bin/activate && python -m pytest tests/test_url_analyzer.py -v
"""

import sys
import os

# Add backend to path so imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.url_analyzer import analyze_url


def _get_finding(result, check_name):
    """Helper: get a specific finding by check name."""
    for f in result["findings"]:
        if f["check"] == check_name:
            return f
    return None


# ── Legitimate URLs should be LOW risk ────────────────────────

class TestLegitimateURLs:
    """These should all score LOW risk with minimal false positives."""

    def test_google(self):
        r = analyze_url("https://google.com")
        assert r["risk_level"] == "LOW", f"google.com scored {r['risk_score']} ({r['risk_level']})"

    def test_stackoverflow(self):
        """Regression: 'stackoverflow' must NOT trigger 'offer' keyword."""
        r = analyze_url("https://stackoverflow.com/questions/12345")
        kw = _get_finding(r, "Suspicious Keywords")
        assert kw["risk_contribution"] == 0, f"stackoverflow triggered keywords: {kw['result']}"
        assert r["risk_level"] == "LOW"

    def test_github(self):
        r = analyze_url("https://github.com/user/repo")
        assert r["risk_level"] == "LOW", f"github.com scored {r['risk_score']}"

    def test_amazon(self):
        r = analyze_url("https://www.amazon.com/dp/B08N5WRWNW")
        assert r["risk_level"] == "LOW"

    def test_reddit(self):
        r = analyze_url("https://www.reddit.com/r/python")
        assert r["risk_level"] == "LOW"

    def test_google_with_subdomain(self):
        """mail.google.com should not trigger excessive subdomains."""
        r = analyze_url("https://mail.google.com")
        sub = _get_finding(r, "Excessive Subdomains")
        assert sub["risk_contribution"] == 0

    def test_indian_bank(self):
        """Multi-part TLD like .co.in should work correctly."""
        r = analyze_url("https://www.sbi.co.in")
        brand = _get_finding(r, "Brand Impersonation")
        assert brand["risk_contribution"] == 0, f"sbi.co.in flagged for impersonation: {brand['result']}"


# ── Phishing URLs should be HIGH/CRITICAL ────────────────────

class TestPhishingURLs:
    """Known phishing patterns must trigger high risk."""

    def test_brand_impersonation_xyz(self):
        r = analyze_url("http://paypal-secure.xyz/login")
        assert r["risk_score"] >= 35, f"Phishing URL scored only {r['risk_score']}"

    def test_homoglyph_attack(self):
        r = analyze_url("http://g00gle.com")
        hg = _get_finding(r, "Look-alike Characters")
        assert hg["risk_contribution"] > 0, "Homoglyph attack not detected"

    def test_ip_based_url(self):
        r = analyze_url("http://192.168.1.1/admin")
        ip = _get_finding(r, "IP Address Domain")
        assert ip["risk_contribution"] > 0

    def test_typosquatting(self):
        r = analyze_url("http://googel.com")
        brand = _get_finding(r, "Brand Impersonation")
        assert brand["risk_contribution"] > 0, "Typosquatting not detected"

    def test_long_phishing_url(self):
        long_url = "http://evil.com/" + "a" * 250
        r = analyze_url(long_url)
        length = _get_finding(r, "URL Length")
        assert length["risk_contribution"] > 0


# ── URL Shortener Detection ──────────────────────────────────

class TestShortenerDetection:
    def test_bitly(self):
        r = analyze_url("https://bit.ly/abc123")
        sh = _get_finding(r, "URL Shortener")
        assert sh["risk_contribution"] > 0, "bit.ly not detected as shortener"

    def test_tinyurl(self):
        r = analyze_url("https://tinyurl.com/y6abc")
        sh = _get_finding(r, "URL Shortener")
        assert sh["risk_contribution"] > 0

    def test_normal_url_not_shortener(self):
        r = analyze_url("https://github.com")
        sh = _get_finding(r, "URL Shortener")
        assert sh["risk_contribution"] == 0


# ── Punycode / IDN Detection ─────────────────────────────────

class TestPunycodeDetection:
    def test_punycode_domain(self):
        r = analyze_url("http://xn--ppal-mxa.com")
        idn = _get_finding(r, "Internationalized Domain (IDN)")
        assert idn["risk_contribution"] > 0, "Punycode domain not detected"

    def test_normal_ascii_domain(self):
        r = analyze_url("https://example.com")
        idn = _get_finding(r, "Internationalized Domain (IDN)")
        assert idn["risk_contribution"] == 0


# ── Dangerous URI Scheme Detection ───────────────────────────

class TestDangerousSchemes:
    def test_javascript_uri(self):
        r = analyze_url("javascript:alert(1)")
        ds = _get_finding(r, "Dangerous URI Scheme")
        assert ds["risk_contribution"] > 0

    def test_data_uri(self):
        r = analyze_url("data:text/html,<h1>phish</h1>")
        ds = _get_finding(r, "Dangerous URI Scheme")
        assert ds["risk_contribution"] > 0


# ── Domain Info Enrichment ───────────────────────────────────

class TestDomainInfo:
    def test_enriched_domain_info(self):
        r = analyze_url("https://mail.google.com/inbox")
        info = r["domain_info"]
        assert "registered_domain" in info
        assert "tld" in info
        assert "subdomain" in info
        assert info["registered_domain"] == "google.com"
        assert info["tld"] == "com"

    def test_multi_part_tld(self):
        r = analyze_url("https://www.sbi.co.in")
        info = r["domain_info"]
        assert info["tld"] == "co.in"


# ── Keyword Precision ────────────────────────────────────────

class TestKeywordPrecision:
    def test_login_in_path_flags(self):
        """login in the path should still flag."""
        r = analyze_url("https://evil.com/login")
        kw = _get_finding(r, "Suspicious Keywords")
        assert kw["risk_contribution"] > 0

    def test_password_in_query_flags(self):
        r = analyze_url("https://evil.com/page?password=reset")
        kw = _get_finding(r, "Suspicious Keywords")
        assert kw["risk_contribution"] > 0

    def test_no_false_positive_on_domain(self):
        """Keywords in domain names should not trigger."""
        r = analyze_url("https://loginova.com")
        kw = _get_finding(r, "Suspicious Keywords")
        assert kw["risk_contribution"] == 0, f"Domain keyword false positive: {kw['result']}"
