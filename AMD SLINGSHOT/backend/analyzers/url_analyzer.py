"""
Mini Kalpana – URL Phishing Detection Analyzer
Analyzes URLs for phishing indicators using heuristic-based scoring.
"""

import re
import math
import hashlib
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List

from engine.explainability import generate_explanation

# ── Known brand domains for similarity checking ──────────────
BRAND_DOMAINS = [
    "google.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "paypal.com", "amazon.com", "apple.com", "microsoft.com", "netflix.com",
    "linkedin.com", "youtube.com", "yahoo.com", "outlook.com", "gmail.com",
    "dropbox.com", "icloud.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "citibank.com", "americanexpress.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
]

# ── Suspicious keywords in URLs ──────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "bank", "password", "credential", "signin", "signup", "wallet",
    "suspended", "locked", "expire", "urgent", "alert", "free",
    "winner", "prize", "gift", "offer", "bonus", "click",
    "paypal", "bitcoin", "crypto", "reset", "restore",
]

# ── Suspicious TLDs ──────────────────────────────────────────
SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz",
    ".club", ".work", ".link", ".click", ".surf", ".icu", ".cam",
    ".monster", ".quest",
]

# ── Homoglyph map ────────────────────────────────────────────
HOMOGLYPHS = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', '$': 's',
}


def analyze_url(url: str) -> Dict[str, Any]:
    """Main entry point: analyze a URL and return structured results."""
    findings: List[Dict[str, Any]] = []
    total_risk = 0.0

    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full_url = url.lower()

    # ── Check 1: HTTPS validation ──
    risk, finding = _check_https(parsed)
    total_risk += risk
    findings.append(finding)

    # ── Check 2: Domain similarity (brand impersonation) ──
    risk, finding = _check_brand_similarity(domain)
    total_risk += risk
    findings.append(finding)

    # ── Check 3: Suspicious keywords ──
    risk, finding = _check_suspicious_keywords(full_url)
    total_risk += risk
    findings.append(finding)

    # ── Check 4: Suspicious TLD ──
    risk, finding = _check_tld(domain)
    total_risk += risk
    findings.append(finding)

    # ── Check 5: URL entropy ──
    risk, finding = _check_entropy(full_url)
    total_risk += risk
    findings.append(finding)

    # ── Check 6: Homoglyph detection ──
    risk, finding = _check_homoglyphs(domain)
    total_risk += risk
    findings.append(finding)

    # ── Check 7: IP address as domain ──
    risk, finding = _check_ip_domain(domain)
    total_risk += risk
    findings.append(finding)

    # ── Check 8: Excessive subdomains ──
    risk, finding = _check_subdomains(domain)
    total_risk += risk
    findings.append(finding)

    # ── Check 9: URL length ──
    risk, finding = _check_url_length(full_url)
    total_risk += risk
    findings.append(finding)

    # ── Check 10: Suspicious path patterns ──
    risk, finding = _check_path_patterns(path, parse_qs(parsed.query))
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
        extra_context={"url": url}
    )

    return {
        "url": url,
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "findings": findings,
        "explanation": explanation,
        "domain_info": {
            "domain": domain,
            "scheme": parsed.scheme,
            "path": parsed.path,
        }
    }


# ── Individual checks ─────────────────────────────────────────

def _check_https(parsed) -> tuple:
    if parsed.scheme == "https":
        return 0, {"check": "HTTPS Validation", "result": "Site uses HTTPS (encrypted connection).", "risk_contribution": 0}
    else:
        return 15, {"check": "HTTPS Validation", "result": "Site does NOT use HTTPS. Data sent to this site is not encrypted and can be intercepted.", "risk_contribution": 15}


def _check_brand_similarity(domain: str) -> tuple:
    """Check if domain looks similar to a known brand (typosquatting)."""
    # Strip port
    domain_clean = domain.split(":")[0]

    for brand in BRAND_DOMAINS:
        brand_name = brand.split(".")[0]
        domain_name = domain_clean.split(".")[-2] if "." in domain_clean else domain_clean

        # Exact match = safe
        if domain_clean == brand or domain_clean.endswith("." + brand):
            return 0, {"check": "Brand Impersonation", "result": f"Domain matches legitimate brand: {brand}.", "risk_contribution": 0}

        # Check if brand name is contained but domain is different
        if brand_name in domain_clean and domain_clean != brand and not domain_clean.endswith("." + brand):
            return 25, {"check": "Brand Impersonation", "result": f"Domain contains '{brand_name}' but is NOT the official {brand} website. This may be impersonation.", "risk_contribution": 25}

        # Levenshtein distance check
        dist = _levenshtein(brand_name, domain_name)
        if 0 < dist <= 2 and len(brand_name) > 3:
            return 20, {"check": "Brand Impersonation", "result": f"Domain name '{domain_name}' is suspiciously similar to '{brand_name}' (possible typosquatting).", "risk_contribution": 20}

    return 0, {"check": "Brand Impersonation", "result": "No brand impersonation detected.", "risk_contribution": 0}


def _check_suspicious_keywords(url: str) -> tuple:
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url]
    if len(found) >= 3:
        return 20, {"check": "Suspicious Keywords", "result": f"Multiple suspicious keywords found: {', '.join(found[:6])}. Phishing sites often use these words to create urgency.", "risk_contribution": 20}
    elif len(found) >= 1:
        return 8, {"check": "Suspicious Keywords", "result": f"Suspicious keyword(s) found: {', '.join(found)}.", "risk_contribution": 8}
    return 0, {"check": "Suspicious Keywords", "result": "No suspicious keywords detected.", "risk_contribution": 0}


def _check_tld(domain: str) -> tuple:
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return 15, {"check": "Domain Extension (TLD)", "result": f"Uses '{tld}' domain extension, which is commonly abused by malicious websites.", "risk_contribution": 15}
    return 0, {"check": "Domain Extension (TLD)", "result": "Domain extension appears normal.", "risk_contribution": 0}


def _check_entropy(url: str) -> tuple:
    """High entropy URLs are often auto-generated phishing links."""
    entropy = _shannon_entropy(url)
    if entropy > 4.5:
        return 12, {"check": "URL Randomness", "result": f"URL has high randomness (entropy: {entropy:.1f}). Auto-generated URLs are common in phishing attacks.", "risk_contribution": 12}
    elif entropy > 3.8:
        return 5, {"check": "URL Randomness", "result": f"URL has moderate randomness (entropy: {entropy:.1f}).", "risk_contribution": 5}
    return 0, {"check": "URL Randomness", "result": "URL randomness is within normal range.", "risk_contribution": 0}


def _check_homoglyphs(domain: str) -> tuple:
    """Detect look-alike characters (e.g., g00gle, paypa1)."""
    domain_clean = domain.split(":")[0]
    normalized = ""
    substitutions = []

    for char in domain_clean:
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


def _check_subdomains(domain: str) -> tuple:
    parts = domain.split(":")[0].split(".")
    if len(parts) > 4:
        return 15, {"check": "Excessive Subdomains", "result": f"Domain has {len(parts) - 2} subdomains. Phishing sites use many subdomains to hide the real domain.", "risk_contribution": 15}
    elif len(parts) > 3:
        return 5, {"check": "Excessive Subdomains", "result": f"Domain has extra subdomains.", "risk_contribution": 5}
    return 0, {"check": "Excessive Subdomains", "result": "Normal subdomain structure.", "risk_contribution": 0}


def _check_url_length(url: str) -> tuple:
    length = len(url)
    if length > 200:
        return 12, {"check": "URL Length", "result": f"URL is unusually long ({length} characters). Long URLs are often used to hide malicious destinations.", "risk_contribution": 12}
    elif length > 100:
        return 5, {"check": "URL Length", "result": f"URL is somewhat long ({length} characters).", "risk_contribution": 5}
    return 0, {"check": "URL Length", "result": f"URL length is normal ({length} characters).", "risk_contribution": 0}


def _check_path_patterns(path: str, query_params: dict) -> tuple:
    suspicious_patterns = [
        (r'\.php', "Contains PHP script execution"),
        (r'redirect', "Contains redirect mechanism"),
        (r'\.exe|\.bat|\.scr', "Links to executable file"),
        (r'base64|encode|decrypt', "Contains encoding/obfuscation terms"),
        (r'@', "Contains @ symbol (may hide real destination)"),
    ]

    found = []
    for pattern, desc in suspicious_patterns:
        if re.search(pattern, path):
            found.append(desc)

    if query_params and len(query_params) > 5:
        found.append(f"Excessive URL parameters ({len(query_params)} parameters)")

    if found:
        risk = min(len(found) * 7, 20)
        return risk, {"check": "URL Path Analysis", "result": "; ".join(found), "risk_contribution": risk}

    return 0, {"check": "URL Path Analysis", "result": "URL path appears normal.", "risk_contribution": 0}


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
