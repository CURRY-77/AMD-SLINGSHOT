"""
Mini Kalpana – URL Phishing Detection Analyzer
Analyzes URLs for phishing indicators using heuristic-based scoring.

Checks performed:
 1. Dangerous URI scheme detection (javascript:, data:, etc.)
 2. HTTPS validation
 3. Brand impersonation (typosquatting via tldextract + Levenshtein)
 4. Suspicious keywords (word-boundary matching, path/query only)
 5. Suspicious TLD
 6. URL entropy (domain-only)
 7. Homoglyph / look-alike character detection
 8. IP address as domain
 9. Excessive subdomains (tldextract-aware)
10. URL shortener detection
11. Punycode / IDN detection
12. URL length
13. Suspicious path patterns
14. VirusTotal reputation (optional, requires API key)
"""

import re
import os
import math
import json
import base64
import hashlib
import urllib.request
import urllib.error
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List

import tldextract

from engine.explainability import generate_explanation

# ── VirusTotal API (optional) ────────────────────────────────
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

# ── Known brand domains for similarity checking ──────────────
BRAND_DOMAINS = [
    "google.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "paypal.com", "amazon.com", "apple.com", "microsoft.com", "netflix.com",
    "linkedin.com", "youtube.com", "yahoo.com", "outlook.com", "gmail.com",
    "dropbox.com", "icloud.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "citibank.com", "americanexpress.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "github.com", "reddit.com", "whatsapp.com", "telegram.org",
    "spotify.com", "uber.com", "steam.com", "twitch.tv",
]

# Pre-extract brand names once for fast lookups
_BRAND_NAMES = {b.split(".")[0] for b in BRAND_DOMAINS}

# ── Suspicious keywords (split into high / moderate risk) ────
HIGH_RISK_KEYWORDS = [
    "password", "credential", "suspended", "locked", "expire",
    "urgent", "wallet", "bitcoin", "crypto", "restore",
]

MODERATE_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "bank", "signin", "signup", "alert", "reset",
    "winner", "prize", "gift", "offer", "bonus", "click", "free",
]

# ── Suspicious TLDs ──────────────────────────────────────────
SUSPICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "buzz",
    "club", "work", "link", "click", "surf", "icu", "cam",
    "monster", "quest", "fun", "rest", "cyou", "bar",
}

# ── URL shortener domains ───────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "short.link", "rb.gy", "cutt.ly", "shorturl.at",
    "tiny.cc", "lnkd.in", "rebrand.ly", "bl.ink", "surl.li",
}

# ── Homoglyph map ────────────────────────────────────────────
HOMOGLYPHS = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', '$': 's',
}

# ── Dangerous URI schemes ────────────────────────────────────
DANGEROUS_SCHEMES = {"javascript", "data", "blob", "vbscript"}


def analyze_url(url: str) -> Dict[str, Any]:
    """Main entry point: analyze a URL and return structured results."""
    findings: List[Dict[str, Any]] = []
    total_risk = 0.0

    # Normalize
    url_stripped = url.strip()

    # ── Check 1: Dangerous URI schemes (before adding http) ──
    risk, finding = _check_dangerous_scheme(url_stripped)
    total_risk += risk
    findings.append(finding)
    if risk > 0:
        # Short-circuit: these are inherently malicious
        risk_score = min(max(total_risk, 0), 100)
        risk_level = _score_to_level(risk_score)
        explanation = generate_explanation(
            threat_type="url", findings=findings,
            risk_score=risk_score, extra_context={"url": url_stripped}
        )
        return {
            "url": url_stripped,
            "risk_score": round(risk_score, 1),
            "risk_level": risk_level,
            "findings": findings,
            "explanation": explanation,
            "domain_info": {"full_domain": "", "registered_domain": "",
                            "subdomain": "", "tld": "", "scheme": url_stripped.split(":")[0],
                            "path": ""},
        }

    # Ensure URL has a scheme
    if not url_stripped.startswith(("http://", "https://")):
        url_stripped = "http://" + url_stripped

    parsed = urlparse(url_stripped)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    # Domain intelligence via tldextract
    ext = tldextract.extract(url_stripped)
    registered_domain = ext.top_domain_under_public_suffix  # e.g. "google.com"
    domain_name = ext.domain                   # e.g. "google"
    tld_suffix = ext.suffix                    # e.g. "co.in", "com"
    subdomain = ext.subdomain                  # e.g. "www.mail"

    # ── Check 2: HTTPS validation ──
    risk, finding = _check_https(parsed)
    total_risk += risk
    findings.append(finding)

    # ── Check 3: Domain similarity (brand impersonation) ──
    risk, finding = _check_brand_similarity(domain, domain_name, registered_domain, ext)
    total_risk += risk
    findings.append(finding)

    # ── Check 4: Suspicious keywords (path + query only, word boundaries) ──
    risk, finding = _check_suspicious_keywords(path, query)
    total_risk += risk
    findings.append(finding)

    # ── Check 5: Suspicious TLD ──
    risk, finding = _check_tld(tld_suffix)
    total_risk += risk
    findings.append(finding)

    # ── Check 6: Domain entropy ──
    risk, finding = _check_entropy(domain_name)
    total_risk += risk
    findings.append(finding)

    # ── Check 7: Homoglyph detection ──
    risk, finding = _check_homoglyphs(domain_name)
    total_risk += risk
    findings.append(finding)

    # ── Check 8: IP address as domain ──
    risk, finding = _check_ip_domain(domain)
    total_risk += risk
    findings.append(finding)

    # ── Check 9: Excessive subdomains (tldextract-aware) ──
    risk, finding = _check_subdomains(subdomain)
    total_risk += risk
    findings.append(finding)

    # ── Check 10: URL shortener detection ──
    risk, finding = _check_shortener(registered_domain, domain)
    total_risk += risk
    findings.append(finding)

    # ── Check 11: Punycode / IDN detection ──
    risk, finding = _check_punycode(domain)
    total_risk += risk
    findings.append(finding)

    # ── Check 12: URL length ──
    risk, finding = _check_url_length(url_stripped)
    total_risk += risk
    findings.append(finding)

    # ── Check 13: Suspicious path patterns ──
    risk, finding = _check_path_patterns(path, parse_qs(parsed.query))
    total_risk += risk
    findings.append(finding)

    # ── Check 14: VirusTotal reputation (optional) ──
    risk, finding = _check_virustotal_url(url_stripped)
    total_risk += risk
    findings.append(finding)

    # Clamp to 0-100
    risk_score = min(max(total_risk, 0), 100)
    risk_level = _score_to_level(risk_score)

    # Generate explanation
    explanation = generate_explanation(
        threat_type="url",
        findings=findings,
        risk_score=risk_score,
        extra_context={"url": url_stripped}
    )

    return {
        "url": url_stripped,
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "findings": findings,
        "explanation": explanation,
        "domain_info": {
            "full_domain": domain,
            "registered_domain": registered_domain,
            "subdomain": subdomain,
            "tld": tld_suffix,
            "scheme": parsed.scheme,
            "path": parsed.path,
        }
    }


# ── Individual checks ─────────────────────────────────────────

def _check_dangerous_scheme(url: str) -> tuple:
    """Detect javascript:, data:, blob:, vbscript: URIs."""
    scheme = url.split(":")[0].lower().strip()
    if scheme in DANGEROUS_SCHEMES:
        return 30, {
            "check": "Dangerous URI Scheme",
            "result": f"URL uses '{scheme}:' scheme. This is commonly used for cross-site scripting (XSS) and phishing attacks. Never click such links.",
            "risk_contribution": 30,
        }
    return 0, {
        "check": "Dangerous URI Scheme",
        "result": "URL uses a standard web protocol.",
        "risk_contribution": 0,
    }


def _check_https(parsed) -> tuple:
    if parsed.scheme == "https":
        return 0, {"check": "HTTPS Validation", "result": "Site uses HTTPS (encrypted connection).", "risk_contribution": 0}
    else:
        return 15, {"check": "HTTPS Validation", "result": "Site does NOT use HTTPS. Data sent to this site is not encrypted and can be intercepted.", "risk_contribution": 15}


def _check_brand_similarity(domain: str, domain_name: str, registered_domain: str, ext) -> tuple:
    """Check if domain looks similar to a known brand (typosquatting).
    Uses tldextract for accurate domain component extraction."""
    # Strip port from raw domain
    domain_clean = domain.split(":")[0]

    for brand in BRAND_DOMAINS:
        brand_ext = tldextract.extract(brand)
        brand_name = brand_ext.domain  # e.g. "paypal"

        # Exact match = safe (including subdomains of real brand)
        if registered_domain == brand or domain_clean == brand or domain_clean.endswith("." + brand):
            return 0, {"check": "Brand Impersonation", "result": f"Domain matches legitimate brand: {brand}.", "risk_contribution": 0}

        # Brand name contained in domain but different registrable domain
        # e.g. "paypal-secure.com" contains "paypal" but is not paypal.com
        if brand_name in domain_name and registered_domain != brand:
            return 25, {
                "check": "Brand Impersonation",
                "result": f"Domain contains '{brand_name}' but is NOT the official {brand} website. This is likely impersonation.",
                "risk_contribution": 25,
            }

        # Levenshtein distance check (typosquatting)
        dist = _levenshtein(brand_name, domain_name)
        if 0 < dist <= 2 and len(brand_name) > 3:
            return 20, {
                "check": "Brand Impersonation",
                "result": f"Domain name '{domain_name}' is suspiciously similar to '{brand_name}' (possible typosquatting, edit distance: {dist}).",
                "risk_contribution": 20,
            }

    return 0, {"check": "Brand Impersonation", "result": "No brand impersonation detected.", "risk_contribution": 0}


def _check_suspicious_keywords(path: str, query: str) -> tuple:
    """Match suspicious keywords using word boundaries in path + query only.
    This avoids false positives from domain names like 'stackoverflow.com'."""
    check_target = path + "?" + query

    high_found = [kw for kw in HIGH_RISK_KEYWORDS if re.search(r'(?:^|[/\-_=&?.])' + re.escape(kw) + r'(?:[/\-_=&?.]|$)', check_target)]
    mod_found = [kw for kw in MODERATE_KEYWORDS if re.search(r'(?:^|[/\-_=&?.])' + re.escape(kw) + r'(?:[/\-_=&?.]|$)', check_target)]

    all_found = high_found + mod_found

    if high_found and len(all_found) >= 2:
        risk = 20
        return risk, {"check": "Suspicious Keywords", "result": f"Multiple high-risk keywords in URL path: {', '.join(all_found[:6])}. Phishing sites use these to create urgency.", "risk_contribution": risk}
    elif high_found:
        risk = 12
        return risk, {"check": "Suspicious Keywords", "result": f"High-risk keyword(s) found in URL path: {', '.join(high_found)}.", "risk_contribution": risk}
    elif len(mod_found) >= 3:
        risk = 15
        return risk, {"check": "Suspicious Keywords", "result": f"Multiple suspicious keywords in URL path: {', '.join(mod_found[:6])}.", "risk_contribution": risk}
    elif mod_found:
        risk = 5
        return risk, {"check": "Suspicious Keywords", "result": f"Keyword(s) found in URL path: {', '.join(mod_found)}. This is common on legitimate sites too.", "risk_contribution": risk}

    return 0, {"check": "Suspicious Keywords", "result": "No suspicious keywords detected in URL path.", "risk_contribution": 0}


def _check_tld(tld_suffix: str) -> tuple:
    """Check TLD using the properly extracted suffix from tldextract."""
    if tld_suffix.lower() in SUSPICIOUS_TLDS:
        return 15, {"check": "Domain Extension (TLD)", "result": f"Uses '.{tld_suffix}' domain extension, which is commonly abused by malicious websites.", "risk_contribution": 15}
    return 0, {"check": "Domain Extension (TLD)", "result": f"Domain extension '.{tld_suffix}' appears normal.", "risk_contribution": 0}


def _check_entropy(domain_name: str) -> tuple:
    """High entropy in the domain name (not the full URL) suggests auto-generated domains."""
    if not domain_name or len(domain_name) < 4:
        return 0, {"check": "Domain Randomness", "result": "Domain name too short to assess randomness.", "risk_contribution": 0}

    entropy = _shannon_entropy(domain_name)
    if entropy > 3.5 and len(domain_name) > 10:
        return 12, {"check": "Domain Randomness", "result": f"Domain name '{domain_name}' has high randomness (entropy: {entropy:.1f}). Auto-generated domains are common in phishing.", "risk_contribution": 12}
    elif entropy > 3.0 and len(domain_name) > 8:
        return 5, {"check": "Domain Randomness", "result": f"Domain name has moderate randomness (entropy: {entropy:.1f}).", "risk_contribution": 5}
    return 0, {"check": "Domain Randomness", "result": "Domain name randomness is within normal range.", "risk_contribution": 0}


def _check_homoglyphs(domain_name: str) -> tuple:
    """Detect look-alike characters (e.g., g00gle, paypa1) in the domain name."""
    normalized = ""
    substitutions = []

    for char in domain_name:
        if char in HOMOGLYPHS:
            normalized += HOMOGLYPHS[char]
            substitutions.append(f"'{char}' → '{HOMOGLYPHS[char]}'")
        else:
            normalized += char

    if substitutions:
        for brand in BRAND_DOMAINS:
            brand_name = brand.split(".")[0]
            if brand_name in normalized:
                return 25, {"check": "Look-alike Characters", "result": f"Domain uses deceptive characters ({', '.join(substitutions)}) to mimic '{brand_name}'. This is a common phishing technique.", "risk_contribution": 25}
        return 10, {"check": "Look-alike Characters", "result": f"Domain contains character substitutions: {', '.join(substitutions)}.", "risk_contribution": 10}

    return 0, {"check": "Look-alike Characters", "result": "No look-alike character tricks detected.", "risk_contribution": 0}


def _check_ip_domain(domain: str) -> tuple:
    """Using raw IP address instead of domain name."""
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    if ip_pattern.match(domain.split(":")[0]):
        return 20, {"check": "IP Address Domain", "result": "Website uses a raw IP address instead of a domain name. Legitimate sites almost always use domain names.", "risk_contribution": 20}
    return 0, {"check": "IP Address Domain", "result": "Uses a proper domain name.", "risk_contribution": 0}


def _check_subdomains(subdomain: str) -> tuple:
    """Check excessive subdomains using tldextract's subdomain field.
    This properly handles multi-part TLDs like .co.in and doesn't
    count 'www' as suspicious."""
    if not subdomain:
        return 0, {"check": "Excessive Subdomains", "result": "Normal subdomain structure.", "risk_contribution": 0}

    # Filter out 'www' since it's standard
    parts = [p for p in subdomain.split(".") if p and p != "www"]
    count = len(parts)

    if count >= 3:
        return 15, {"check": "Excessive Subdomains", "result": f"Domain has {count} non-standard subdomains ({subdomain}). Phishing sites use many subdomains to hide the real domain.", "risk_contribution": 15}
    elif count >= 2:
        return 5, {"check": "Excessive Subdomains", "result": f"Domain has extra subdomains ({subdomain}).", "risk_contribution": 5}
    return 0, {"check": "Excessive Subdomains", "result": "Normal subdomain structure.", "risk_contribution": 0}


def _check_shortener(registered_domain: str, domain: str) -> tuple:
    """Detect URL shortener services that hide the real destination."""
    domain_clean = domain.split(":")[0]
    if registered_domain in URL_SHORTENERS or domain_clean in URL_SHORTENERS:
        return 10, {
            "check": "URL Shortener",
            "result": f"URL uses shortener service '{domain_clean}'. Shortened URLs hide the real destination and are frequently used in phishing attacks.",
            "risk_contribution": 10,
        }
    return 0, {"check": "URL Shortener", "result": "URL is not shortened.", "risk_contribution": 0}


def _check_punycode(domain: str) -> tuple:
    """Detect internationalized domain names (IDN) using punycode encoding.
    Attackers use look-alike Unicode characters to create deceptive domains."""
    domain_clean = domain.split(":")[0]
    if domain_clean.startswith("xn--") or ".xn--" in domain_clean:
        return 20, {
            "check": "Internationalized Domain (IDN)",
            "result": "Domain uses punycode encoding (xn--), indicating internationalized characters. This technique is used in homograph attacks to mimic legitimate domains with look-alike Unicode characters.",
            "risk_contribution": 20,
        }
    return 0, {"check": "Internationalized Domain (IDN)", "result": "Domain uses standard ASCII characters.", "risk_contribution": 0}


def _check_url_length(url: str) -> tuple:
    length = len(url)
    if length > 200:
        return 12, {"check": "URL Length", "result": f"URL is unusually long ({length} characters). Long URLs are often used to hide malicious destinations.", "risk_contribution": 12}
    elif length > 100:
        return 5, {"check": "URL Length", "result": f"URL is somewhat long ({length} characters).", "risk_contribution": 5}
    return 0, {"check": "URL Length", "result": f"URL length is normal ({length} characters).", "risk_contribution": 0}


def _check_path_patterns(path: str, query_params: dict) -> tuple:
    """Check for suspicious patterns in URL path and parameters."""
    suspicious_patterns = [
        (r'\.php', "Contains PHP script execution"),
        (r'redirect|redir\b|returnurl|returnto|goto|next=', "Contains redirect mechanism"),
        (r'\.exe|\.bat|\.scr|\.cmd|\.msi|\.ps1', "Links to executable file"),
        (r'base64|encode|decrypt|obfusc', "Contains encoding/obfuscation terms"),
        (r'@', "Contains @ symbol (may hide real destination)"),
        (r'wp-admin|wp-login|wp-content/uploads', "References WordPress admin (may be compromised)"),
        (r'\.html\?|\.htm\?', "HTML page with query parameters (common in phishing kits)"),
    ]

    # Check for credential-harvesting query params
    sensitive_params = {"token", "session", "auth", "key", "secret", "pass", "pwd", "ssn", "credit"}

    found = []
    for pattern, desc in suspicious_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            found.append(desc)

    if query_params:
        if len(query_params) > 5:
            found.append(f"Excessive URL parameters ({len(query_params)} parameters)")
        harvesting_params = sensitive_params.intersection(k.lower() for k in query_params.keys())
        if harvesting_params:
            found.append(f"Contains sensitive parameter names: {', '.join(harvesting_params)}")

    if found:
        risk = min(len(found) * 7, 20)
        return risk, {"check": "URL Path Analysis", "result": "; ".join(found), "risk_contribution": risk}

    return 0, {"check": "URL Path Analysis", "result": "URL path appears normal.", "risk_contribution": 0}


def _check_virustotal_url(url: str) -> tuple:
    """Check URL reputation against VirusTotal's 90+ security vendor database.
    Optional: only runs if VIRUSTOTAL_API_KEY environment variable is set."""
    # VT GUI link uses SHA-256 of the URL
    url_sha256 = hashlib.sha256(url.encode()).hexdigest()
    vt_gui_link = f"https://www.virustotal.com/gui/url/{url_sha256}"

    if not VIRUSTOTAL_API_KEY:
        return 0, {
            "check": "VirusTotal Reputation",
            "result": "VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY environment variable for reputation lookups.",
            "risk_contribution": 0,
        }

    try:
        # VT v3 URL identifier: base64(url) without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        req = urllib.request.Request(api_url, headers={"x-apikey": VIRUSTOTAL_API_KEY})

        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            if malicious >= 5:
                return 35, {
                    "check": "VirusTotal Reputation",
                    "result": f"MALICIOUS: {malicious}/{total} security vendors flagged this URL as malicious. This URL is very likely dangerous.",
                    "risk_contribution": 35,
                    "vt_link": vt_gui_link,
                }
            elif malicious >= 1 or suspicious >= 3:
                return 20, {
                    "check": "VirusTotal Reputation",
                    "result": f"Suspicious: {malicious} malicious + {suspicious} suspicious detections out of {total} vendors.",
                    "risk_contribution": 20,
                    "vt_link": vt_gui_link,
                }
            elif suspicious >= 1:
                return 8, {
                    "check": "VirusTotal Reputation",
                    "result": f"Low-confidence flag: {suspicious} vendor(s) marked as suspicious out of {total} scanned.",
                    "risk_contribution": 8,
                    "vt_link": vt_gui_link,
                }
            else:
                return 0, {
                    "check": "VirusTotal Reputation",
                    "result": f"Clean: 0/{total} security vendors detected any threat.",
                    "risk_contribution": 0,
                    "vt_link": vt_gui_link,
                }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 0, {
                "check": "VirusTotal Reputation",
                "result": "URL not found in VirusTotal database (not previously scanned).",
                "risk_contribution": 0,
                "vt_link": vt_gui_link,
            }
        return 0, {
            "check": "VirusTotal Reputation",
            "result": f"VirusTotal lookup failed (HTTP {e.code}).",
            "risk_contribution": 0,
        }
    except Exception:
        return 0, {
            "check": "VirusTotal Reputation",
            "result": "VirusTotal lookup timed out or failed.",
            "risk_contribution": 0,
        }


# ── Utility functions ─────────────────────────────────────────

def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _score_to_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"
