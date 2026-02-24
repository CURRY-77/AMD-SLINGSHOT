"""
Mini Kalpana – Email/SMS Scam Detection Analyzer
Analyzes email and SMS content for scam/phishing patterns.
"""

import re
from typing import Dict, Any, List, Optional

from engine.explainability import generate_explanation
from analyzers.url_analyzer import analyze_url

# ── Urgency keywords ─────────────────────────────────────────
URGENCY_KEYWORDS = [
    "immediately", "urgent", "act now", "right away", "limited time",
    "expires today", "time sensitive", "don't delay", "hurry",
    "account suspended", "account locked", "unauthorized access",
    "security alert", "verify immediately", "confirm now",
    "within 24 hours", "within 48 hours", "last chance", "final notice",
    "action required", "response required",
]

# ── Financial manipulation keywords ──────────────────────────
FINANCIAL_KEYWORDS = [
    "wire transfer", "bitcoin", "cryptocurrency", "gift card",
    "prize", "lottery", "winner", "won", "million dollars",
    "inheritance", "beneficiary", "processing fee", "advance fee",
    "money order", "western union", "bank transfer", "payment",
    "investment opportunity", "guaranteed returns", "risk-free",
    "credit card", "social security", "ssn", "tax refund",
    "unclaimed funds", "insurance claim",
]

# ── Authority impersonation keywords ─────────────────────────
AUTHORITY_KEYWORDS = [
    "irs", "internal revenue", "fbi", "cia", "police",
    "microsoft support", "apple support", "google security",
    "amazon security", "paypal security", "bank of america",
    "hr department", "human resources", "it department",
    "tech support", "customer service", "legal department",
    "compliance team", "fraud department", "investigation team",
    "your employer", "government", "federal", "court order",
]

# ── Pressure tactics ─────────────────────────────────────────
PRESSURE_PATTERNS = [
    r'click\s+(here|below|this|the\s+link)',
    r'call\s+(this|the)\s+number',
    r'do\s+not\s+(ignore|share|tell)',
    r'keep\s+this\s+(confidential|secret|private)',
    r'failure\s+to\s+(comply|respond|act)',
    r'legal\s+action',
    r'arrest\s+warrant',
    r'account\s+will\s+be\s+(closed|terminated|suspended)',
    r'you\s+have\s+been\s+selected',
    r'you\s+are\s+the\s+winner',
    r'congratulations',
]

# ── Email URL extraction pattern ─────────────────────────────
URL_PATTERN = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.IGNORECASE)


def analyze_email(
    content: str,
    sender: Optional[str] = None,
    subject: Optional[str] = None
) -> Dict[str, Any]:
    """Main entry point: analyze email/SMS content for scam indicators."""
    findings: List[Dict[str, Any]] = []
    total_risk = 0.0
    full_text = _combine_text(content, sender, subject)
    full_text_lower = full_text.lower()

    # ── Check 1: Urgency detection ──
    risk, finding = _check_urgency(full_text_lower)
    total_risk += risk
    findings.append(finding)

    # ── Check 2: Financial manipulation ──
    risk, finding = _check_financial(full_text_lower)
    total_risk += risk
    findings.append(finding)

    # ── Check 3: Authority impersonation ──
    risk, finding = _check_authority(full_text_lower)
    total_risk += risk
    findings.append(finding)

    # ── Check 4: Pressure tactics ──
    risk, finding = _check_pressure(full_text_lower)
    total_risk += risk
    findings.append(finding)

    # ── Check 5: Grammar/style red flags ──
    risk, finding = _check_grammar_style(content)
    total_risk += risk
    findings.append(finding)

    # ── Check 6: Sender analysis ──
    if sender:
        risk, finding = _check_sender(sender)
        total_risk += risk
        findings.append(finding)

    # ── Check 7: Embedded links ──
    urls = URL_PATTERN.findall(full_text)
    embedded_urls_analysis = []
    if urls:
        risk, finding, url_results = _check_embedded_urls(urls)
        total_risk += risk
        findings.append(finding)
        embedded_urls_analysis = url_results

    # ── Check 8: Too-good-to-be-true ──
    risk, finding = _check_too_good(full_text_lower)
    total_risk += risk
    findings.append(finding)

    # Clamp
    risk_score = min(max(total_risk, 0), 100)
    risk_level = _score_to_level(risk_score)
    manipulation_type = _determine_manipulation_type(findings)

    explanation = generate_explanation(
        threat_type="email",
        findings=findings,
        risk_score=risk_score,
        extra_context={"manipulation_type": manipulation_type}
    )

    return {
        "scam_probability": round(risk_score, 1),
        "risk_level": risk_level,
        "manipulation_type": manipulation_type,
        "findings": findings,
        "explanation": explanation,
        "embedded_urls_analysis": embedded_urls_analysis if embedded_urls_analysis else None,
    }


# ── Individual checks ─────────────────────────────────────────

def _check_urgency(text: str) -> tuple:
    found = [kw for kw in URGENCY_KEYWORDS if kw in text]
    if len(found) >= 3:
        return 25, {"category": "Urgency Manipulation", "detail": f"Multiple urgency triggers detected: {', '.join(found[:5])}. Scammers create false urgency to prevent you from thinking clearly.", "risk_contribution": 25}
    elif len(found) >= 1:
        return 12, {"category": "Urgency Manipulation", "detail": f"Urgency language detected: {', '.join(found)}.", "risk_contribution": 12}
    return 0, {"category": "Urgency Manipulation", "detail": "No urgency manipulation detected.", "risk_contribution": 0}


def _check_financial(text: str) -> tuple:
    found = [kw for kw in FINANCIAL_KEYWORDS if kw in text]
    if len(found) >= 3:
        return 25, {"category": "Financial Manipulation", "detail": f"Multiple financial keywords detected: {', '.join(found[:5])}. This message may be trying to steal money or financial information.", "risk_contribution": 25}
    elif len(found) >= 1:
        return 12, {"category": "Financial Manipulation", "detail": f"Financial terms detected: {', '.join(found)}.", "risk_contribution": 12}
    return 0, {"category": "Financial Manipulation", "detail": "No financial manipulation detected.", "risk_contribution": 0}


def _check_authority(text: str) -> tuple:
    found = [kw for kw in AUTHORITY_KEYWORDS if kw in text]
    if len(found) >= 2:
        return 20, {"category": "Authority Impersonation", "detail": f"Multiple authority references detected: {', '.join(found[:4])}. Scammers often impersonate trusted organizations.", "risk_contribution": 20}
    elif len(found) >= 1:
        return 10, {"category": "Authority Impersonation", "detail": f"Authority reference detected: {', '.join(found)}.", "risk_contribution": 10}
    return 0, {"category": "Authority Impersonation", "detail": "No authority impersonation detected.", "risk_contribution": 0}


def _check_pressure(text: str) -> tuple:
    found = []
    for pattern in PRESSURE_PATTERNS:
        if re.search(pattern, text):
            found.append(pattern.replace(r'\s+', ' ').replace(r'\s*', ''))
    if len(found) >= 2:
        return 20, {"category": "Pressure Tactics", "detail": f"Multiple psychological pressure tactics detected ({len(found)} patterns). The message is trying to force you into action.", "risk_contribution": 20}
    elif len(found) >= 1:
        return 10, {"category": "Pressure Tactics", "detail": "Pressure tactic detected in the message.", "risk_contribution": 10}
    return 0, {"category": "Pressure Tactics", "detail": "No pressure tactics detected.", "risk_contribution": 0}


def _check_grammar_style(text: str) -> tuple:
    issues = []
    # Excessive caps
    words = text.split()
    caps_words = sum(1 for w in words if w.isupper() and len(w) > 2)
    if caps_words > 5:
        issues.append(f"Excessive use of CAPITAL LETTERS ({caps_words} words)")

    # Excessive exclamation marks
    excl_count = text.count("!")
    if excl_count > 3:
        issues.append(f"Excessive exclamation marks ({excl_count})")

    # Multiple dollar signs / emoji-like patterns
    dollar_count = text.count("$")
    if dollar_count > 2:
        issues.append(f"Multiple currency symbols")

    # Spelling-like patterns (common in scams) - simplified
    scam_patterns = [r'u\s+have', r'ur\s+account', r'plz', r'kindly\s+do']
    for p in scam_patterns:
        if re.search(p, text, re.IGNORECASE):
            issues.append("Informal/suspicious language patterns")
            break

    if len(issues) >= 2:
        return 15, {"category": "Writing Style", "detail": "; ".join(issues) + ". Poor grammar and aggressive formatting are common in scam messages.", "risk_contribution": 15}
    elif issues:
        return 5, {"category": "Writing Style", "detail": "; ".join(issues) + ".", "risk_contribution": 5}
    return 0, {"category": "Writing Style", "detail": "Writing style appears normal.", "risk_contribution": 0}


def _check_sender(sender: str) -> tuple:
    sender_lower = sender.lower()

    # Check for free email providers used for impersonation
    suspicious_patterns = [
        (r'@(gmail|yahoo|hotmail|outlook)\.\w+', "Uses free email provider"),
        (r'noreply.*@', "Uses 'noreply' address"),
        (r'\d{4,}@', "Has many numbers in address"),
        (r'@.*\.(xyz|tk|ml|ga|cf|gq|top|buzz)', "Uses suspicious domain extension"),
    ]

    issues = []
    for pattern, desc in suspicious_patterns:
        if re.search(pattern, sender_lower):
            issues.append(desc)

    # Check for display name spoofing patterns
    if re.search(r'(admin|support|security|help|service).*@', sender_lower):
        if re.search(r'@(gmail|yahoo|hotmail|outlook)', sender_lower):
            issues.append("Claims to be official support but uses personal email")

    if issues:
        risk = min(len(issues) * 8, 20)
        return risk, {"category": "Sender Analysis", "detail": "; ".join(issues) + ".", "risk_contribution": risk}
    return 0, {"category": "Sender Analysis", "detail": "Sender address has no obvious red flags.", "risk_contribution": 0}


def _check_embedded_urls(urls: list) -> tuple:
    """Run URL analyzer on embedded links."""
    results = []
    max_url_risk = 0

    for url in urls[:5]:  # Limit to 5 URLs
        url_result = analyze_url(url)
        results.append({
            "url": url,
            "risk_score": url_result["risk_score"],
            "risk_level": url_result["risk_level"],
        })
        max_url_risk = max(max_url_risk, url_result["risk_score"])

    if max_url_risk >= 60:
        risk = 20
        detail = f"Contains {len(urls)} link(s), with at least one highly suspicious URL (risk: {max_url_risk}%). Clicking could lead to a phishing site."
    elif max_url_risk >= 35:
        risk = 10
        detail = f"Contains {len(urls)} link(s), some appear moderately suspicious."
    elif urls:
        risk = 3
        detail = f"Contains {len(urls)} link(s), which appear relatively safe."
    else:
        risk = 0
        detail = "No embedded links found."

    return risk, {"category": "Embedded Links", "detail": detail, "risk_contribution": risk}, results


def _check_too_good(text: str) -> tuple:
    patterns = [
        r'you\s+(have\s+)?(won|win)',
        r'claim\s+(your|the)\s+(prize|reward|money)',
        r'free\s+(gift|money|iphone|laptop|trip)',
        r'(100|thousand|million)\s*(dollars|\$|pounds|£|euros|€)',
        r'congratulations.*selected',
        r'no\s+(risk|obligation|cost)',
    ]
    found = sum(1 for p in patterns if re.search(p, text))
    if found >= 2:
        return 20, {"category": "Too-Good-To-Be-True", "detail": "Message contains multiple unrealistic promises. If it sounds too good to be true, it probably is.", "risk_contribution": 20}
    elif found >= 1:
        return 10, {"category": "Too-Good-To-Be-True", "detail": "Message contains a potentially unrealistic promise or offer.", "risk_contribution": 10}
    return 0, {"category": "Too-Good-To-Be-True", "detail": "No unrealistic promises detected.", "risk_contribution": 0}


# ── Helpers ───────────────────────────────────────────────────

def _combine_text(content: str, sender: Optional[str], subject: Optional[str]) -> str:
    parts = []
    if subject:
        parts.append(subject)
    parts.append(content)
    if sender:
        parts.append(f"From: {sender}")
    return " ".join(parts)


def _determine_manipulation_type(findings: list) -> Optional[str]:
    """Determine the primary manipulation tactic."""
    max_risk = 0
    primary = None
    for f in findings:
        if f.get("risk_contribution", 0) > max_risk and f.get("risk_contribution", 0) > 0:
            max_risk = f["risk_contribution"]
            primary = f.get("category", "Unknown")
    return primary


def _score_to_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"
