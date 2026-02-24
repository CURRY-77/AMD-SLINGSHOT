"""
Mini Kalpana – Explainability Engine
Generates human-readable threat explanations for every alert.
"""

from typing import List, Dict, Any


def generate_explanation(
    threat_type: str,
    findings: List[Dict[str, Any]],
    risk_score: float,
    extra_context: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Core explainability function.
    Takes raw findings and produces a structured, human-readable explanation.
    """
    if extra_context is None:
        extra_context = {}

    severity = _get_severity_label(risk_score)
    what_happened = _build_what_happened(threat_type, findings, extra_context, severity)
    why_risky = _build_why_risky(findings)
    what_it_means = _build_what_it_means(threat_type, risk_score, extra_context)
    what_to_do = _build_what_to_do(threat_type, risk_score)

    return {
        "what_happened": what_happened,
        "why_risky": why_risky,
        "what_it_means": what_it_means,
        "what_to_do": what_to_do,
    }


def _get_severity_label(risk_score: float) -> str:
    if risk_score >= 80:
        return "critical"
    elif risk_score >= 60:
        return "high"
    elif risk_score >= 35:
        return "medium"
    return "low"


# ── What Happened ─────────────────────────────────────────────

_WHAT_TEMPLATES = {
    "url": {
        "critical": "We scanned this URL and detected multiple strong indicators of a phishing or malicious website. This site is very likely designed to steal your information.",
        "high": "We scanned this URL and found several warning signs. This website appears suspicious and may be attempting to deceive you.",
        "medium": "We scanned this URL and noticed some potentially concerning characteristics. The site may not be entirely trustworthy.",
        "low": "We scanned this URL and it appears relatively safe. No major threats were detected.",
    },
    "email": {
        "critical": "We analyzed this message and detected strong patterns consistent with a scam or phishing attempt. This message is very likely trying to manipulate you.",
        "high": "We analyzed this message and found several red flags commonly seen in scam messages. Proceed with extreme caution.",
        "medium": "We analyzed this message and found some suspicious elements. It may be a low-effort scam or unwanted spam.",
        "low": "We analyzed this message and it appears mostly safe. No major scam indicators were found.",
    },
    "file": {
        "critical": "We analyzed this file and detected multiple high-risk characteristics. This file is very likely malicious and could harm your system.",
        "high": "We analyzed this file and found several suspicious traits. This file may contain malware or harmful scripts.",
        "medium": "We analyzed this file and noticed some concerning properties. Exercise caution before opening it.",
        "low": "We analyzed this file and it appears relatively safe. No major threats were detected.",
    },
}


def _build_what_happened(threat_type: str, findings: list, extra_context: dict, severity: str) -> str:
    templates = _WHAT_TEMPLATES.get(threat_type, _WHAT_TEMPLATES["url"])
    base = templates.get(severity, templates["low"])

    if threat_type == "url" and "url" in extra_context:
        base = f"The URL \"{extra_context['url']}\" was analyzed. {base}"
    elif threat_type == "file" and "filename" in extra_context:
        base = f"The file \"{extra_context['filename']}\" was analyzed. {base}"

    return base


# ── Why Risky ─────────────────────────────────────────────────

def _build_why_risky(findings: list) -> list:
    reasons = []
    for f in findings:
        risk = f.get("risk_contribution", 0)
        if risk <= 0:
            continue

        # Adapt field name based on finding type
        detail = f.get("result") or f.get("detail") or f.get("description", "")
        check = f.get("check") or f.get("category", "Check")

        if risk >= 15:
            reasons.append(f"⚠️ {check}: {detail}")
        elif risk >= 5:
            reasons.append(f"🔸 {check}: {detail}")
        else:
            reasons.append(f"ℹ️ {check}: {detail}")

    if not reasons:
        reasons.append("✅ No significant risk factors were identified.")

    return reasons


# ── What It Means ─────────────────────────────────────────────

_MEANING_TEMPLATES = {
    "url": {
        "critical": "This is very likely a phishing website. Phishing sites impersonate trusted brands to trick you into entering passwords, credit card numbers, or personal details. Anything you enter on this site could be stolen by attackers.",
        "high": "This website shows signs of being deceptive. It may be trying to impersonate a legitimate service to collect your personal information or install malware on your device.",
        "medium": "This website has some characteristics that are sometimes associated with unsafe sites. While it may be legitimate, you should verify its identity before sharing any personal information.",
        "low": "This website appears to be safe for normal use. However, always be cautious about sharing sensitive information online.",
    },
    "email": {
        "critical": "This message is very likely a scam. Scammers use urgency, fear, and fake authority to pressure you into acting quickly without thinking. They want you to click dangerous links, send money, or reveal personal information.",
        "high": "This message contains patterns commonly used in scam and phishing emails. The sender may be impersonating a trusted organization to manipulate you into taking a harmful action.",
        "medium": "This message has some elements that are common in spam or low-effort scams. While it may be harmless, be cautious about any links or requests it contains.",
        "low": "This message appears to be normal. No significant manipulation tactics were detected.",
    },
    "file": {
        "critical": "This file has characteristics strongly associated with malware. Opening it could allow attackers to take control of your computer, steal your data, or install ransomware that locks your files.",
        "high": "This file has suspicious properties that are commonly seen in malicious software. It may try to execute harmful code when opened.",
        "medium": "This file has some unusual properties. While it may be legitimate, you should verify its source before opening it.",
        "low": "This file appears to be safe. Its properties are consistent with normal, non-malicious files.",
    },
}


def _build_what_it_means(threat_type: str, risk_score: float, extra_context: dict) -> str:
    severity = _get_severity_label(risk_score)
    templates = _MEANING_TEMPLATES.get(threat_type, _MEANING_TEMPLATES["url"])
    base = templates.get(severity, templates["low"])

    if threat_type == "email" and extra_context.get("manipulation_type"):
        base += f" The primary manipulation tactic detected is: {extra_context['manipulation_type']}."

    return base


# ── What To Do ────────────────────────────────────────────────

_ACTION_TEMPLATES = {
    "url": {
        "critical": [
            "🚫 Do NOT enter any personal information on this website.",
            "❌ Close the browser tab immediately.",
            "🔒 If you already entered a password, change it right away.",
            "📢 Report this URL to your institution's IT department.",
        ],
        "high": [
            "⚠️ Avoid entering passwords or personal data on this site.",
            "🔍 Verify the website's identity through an official source.",
            "🔒 If you clicked any links, run an antivirus scan.",
            "📢 Consider reporting this to your IT administrator.",
        ],
        "medium": [
            "🔍 Double-check the website URL for any misspellings.",
            "🛡️ Make sure the site uses HTTPS (look for the padlock icon).",
            "⚠️ Avoid sharing sensitive information unless you're sure it's legitimate.",
        ],
        "low": [
            "✅ This site appears safe for normal browsing.",
            "🛡️ As always, avoid sharing unnecessary personal information.",
        ],
    },
    "email": {
        "critical": [
            "🚫 Do NOT click any links in this message.",
            "🚫 Do NOT reply to this message or provide any information.",
            "🗑️ Delete this message immediately.",
            "📢 Report it as phishing to your email provider and IT department.",
            "🔒 If you already clicked a link, change your passwords immediately.",
        ],
        "high": [
            "⚠️ Do not click links or download attachments from this message.",
            "🔍 Verify the sender through official channels (don't use contact info from the message itself).",
            "📢 Mark this message as spam or phishing.",
        ],
        "medium": [
            "🔍 Verify the sender's identity before responding.",
            "⚠️ Be cautious of any links or attachments.",
            "🗑️ If unsure, it's safer to ignore or delete the message.",
        ],
        "low": [
            "✅ This message appears safe.",
            "🛡️ As always, be cautious with unexpected attachments or requests.",
        ],
    },
    "file": {
        "critical": [
            "🚫 Do NOT open this file.",
            "🗑️ Delete it immediately.",
            "🔒 Run a full antivirus scan on your system.",
            "📢 Report this file to your IT department.",
            "⚠️ If you already opened it, disconnect from the network and seek IT help.",
        ],
        "high": [
            "⚠️ Do not open this file until verified.",
            "🔍 Scan it with an antivirus tool before opening.",
            "🔍 Verify the file source – did you expect to receive this?",
            "📢 Consider reporting it to your IT administrator.",
        ],
        "medium": [
            "🔍 Verify that you expected to receive this file.",
            "🛡️ Scan it with antivirus software before opening.",
            "⚠️ Be cautious if the file was from an unknown source.",
        ],
        "low": [
            "✅ This file appears safe to open.",
            "🛡️ Keeping your antivirus up to date is always recommended.",
        ],
    },
}


def _build_what_to_do(threat_type: str, risk_score: float) -> list:
    severity = _get_severity_label(risk_score)
    templates = _ACTION_TEMPLATES.get(threat_type, _ACTION_TEMPLATES["url"])
    return templates.get(severity, templates["low"])
