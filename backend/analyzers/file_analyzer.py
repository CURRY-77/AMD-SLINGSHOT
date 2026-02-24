"""
Mini Kalpana – File Risk Analyzer
Analyzes uploaded files for malware/risk indicators using static heuristics.
"""

import os
import hashlib
import re
import json
import urllib.request
from typing import Dict, Any, List

from engine.explainability import generate_explanation

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


# ── High-risk file extensions ────────────────────────────────
HIGH_RISK_EXTENSIONS = {
    '.exe': 'Windows Executable',
    '.bat': 'Batch Script',
    '.cmd': 'Command Script',
    '.scr': 'Screensaver (often malware)',
    '.pif': 'Program Information File',
    '.vbs': 'Visual Basic Script',
    '.vbe': 'Encoded VBS Script',
    '.js': 'JavaScript File',
    '.jse': 'Encoded JavaScript',
    '.wsf': 'Windows Script File',
    '.wsh': 'Windows Script Host',
    '.ps1': 'PowerShell Script',
    '.msi': 'Windows Installer',
    '.com': 'DOS Executable',
    '.reg': 'Registry Modification File',
    '.inf': 'Setup Information File',
    '.lnk': 'Shortcut (can run commands)',
    '.dll': 'Dynamic Link Library',
    '.sys': 'System File',
    '.drv': 'Device Driver',
}

# ── Medium-risk extensions ───────────────────────────────────
MEDIUM_RISK_EXTENSIONS = {
    '.pdf': 'PDF Document (can contain scripts)',
    '.doc': 'Word Document (can contain macros)',
    '.docx': 'Word Document',
    '.docm': 'Macro-enabled Word Document',
    '.xls': 'Excel Spreadsheet (can contain macros)',
    '.xlsx': 'Excel Spreadsheet',
    '.xlsm': 'Macro-enabled Excel',
    '.ppt': 'PowerPoint Presentation',
    '.pptm': 'Macro-enabled PowerPoint',
    '.zip': 'Compressed Archive',
    '.rar': 'Compressed Archive',
    '.7z': 'Compressed Archive',
    '.tar': 'Archive File',
    '.gz': 'Compressed File',
    '.iso': 'Disk Image',
    '.html': 'HTML File (can contain scripts)',
    '.htm': 'HTML File',
    '.jar': 'Java Archive',
    '.apk': 'Android Application',
    '.dmg': 'macOS Disk Image',
}

# ── Low-risk extensions ──────────────────────────────────────
LOW_RISK_EXTENSIONS = {
    '.txt': 'Plain Text',
    '.csv': 'Comma Separated Values',
    '.jpg': 'JPEG Image',
    '.jpeg': 'JPEG Image',
    '.png': 'PNG Image',
    '.gif': 'GIF Image',
    '.bmp': 'Bitmap Image',
    '.svg': 'Vector Image',
    '.mp3': 'Audio File',
    '.mp4': 'Video File',
    '.wav': 'Audio File',
    '.avi': 'Video File',
    '.mkv': 'Video File',
    '.json': 'JSON Data',
    '.xml': 'XML Data',
    '.md': 'Markdown Document',
}

# ── Suspicious filename patterns ─────────────────────────────
SUSPICIOUS_FILENAME_PATTERNS = [
    (r'invoice', 'Contains "invoice" – commonly used in malware campaigns'),
    (r'receipt', 'Contains "receipt" – often used in phishing attachments'),
    (r'payment', 'Contains "payment" – financial lure'),
    (r'urgent', 'Contains "urgent" – urgency-based social engineering'),
    (r'order.*confirm', 'Contains "order confirmation" pattern'),
    (r'resume|cv', 'Contains "resume/CV" – used in targeted attacks'),
    (r'scan|document\d+', 'Looks like an auto-generated scan filename'),
    (r'(crack|keygen|patch|hack|exploit)', 'Contains hacking-related terms – very likely malware'),
]


def analyze_file(
    filename: str,
    file_content: bytes,
    file_size: int
) -> Dict[str, Any]:
    """Main entry point: analyze a file for risk indicators."""
    findings: List[Dict[str, Any]] = []
    total_risk = 0.0

    # Generate hashes
    md5_hash = hashlib.md5(file_content).hexdigest()
    sha256_hash = hashlib.sha256(file_content).hexdigest()

    # Detect MIME type from content (basic magic bytes detection)
    detected_mime = _detect_mime_type(file_content)

    # Get extension
    _, ext = os.path.splitext(filename.lower())

    # ── Check 1: Extension risk ──
    risk, finding = _check_extension_risk(ext)
    total_risk += risk
    findings.append(finding)

    # ── Check 2: Double extension ──
    risk, finding = _check_double_extension(filename)
    total_risk += risk
    findings.append(finding)

    # ── Check 3: MIME type mismatch ──
    risk, finding = _check_mime_mismatch(ext, detected_mime)
    total_risk += risk
    findings.append(finding)

    # ── Check 4: File size anomaly ──
    risk, finding = _check_file_size(ext, file_size)
    total_risk += risk
    findings.append(finding)

    # ── Check 5: Suspicious filename ──
    risk, finding = _check_suspicious_filename(filename)
    total_risk += risk
    findings.append(finding)

    # ── Check 6: Content analysis (basic) ──
    risk, finding = _check_content_patterns(file_content, ext)
    total_risk += risk
    findings.append(finding)

    # ── Check 7: Hidden extension (spaces/unicode) ──
    risk, finding = _check_hidden_extension(filename)
    total_risk += risk
    findings.append(finding)

    # ── Check 8: VirusTotal hash lookup ──
    risk, finding = _check_virustotal(sha256_hash)
    total_risk += risk
    findings.append(finding)

    # Clamp
    risk_score = min(max(total_risk, 0), 100)
    risk_level = _score_to_level(risk_score)

    explanation = generate_explanation(
        threat_type="file",
        findings=findings,
        risk_score=risk_score,
        extra_context={"filename": filename}
    )

    return {
        "filename": filename,
        "file_size": file_size,
        "md5_hash": md5_hash,
        "sha256_hash": sha256_hash,
        "mime_type": detected_mime,
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "findings": findings,
        "explanation": explanation,
    }


# ── Individual checks ─────────────────────────────────────────

def _check_extension_risk(ext: str) -> tuple:
    if ext in HIGH_RISK_EXTENSIONS:
        desc = HIGH_RISK_EXTENSIONS[ext]
        return 30, {"check": "File Type", "description": f"High-risk file type: {desc} ({ext}). These files can execute code on your computer.", "risk_contribution": 30}
    elif ext in MEDIUM_RISK_EXTENSIONS:
        desc = MEDIUM_RISK_EXTENSIONS[ext]
        return 10, {"check": "File Type", "description": f"Medium-risk file type: {desc} ({ext}). These files can potentially contain embedded code.", "risk_contribution": 10}
    elif ext in LOW_RISK_EXTENSIONS:
        desc = LOW_RISK_EXTENSIONS[ext]
        return 0, {"check": "File Type", "description": f"Low-risk file type: {desc} ({ext}).", "risk_contribution": 0}
    else:
        return 5, {"check": "File Type", "description": f"Unknown file type ({ext}). Cannot determine risk level.", "risk_contribution": 5}


def _check_double_extension(filename: str) -> tuple:
    """Detect double extensions like document.pdf.exe"""
    parts = filename.split(".")
    if len(parts) >= 3:
        real_ext = "." + parts[-1].lower()
        fake_ext = "." + parts[-2].lower()
        if real_ext in HIGH_RISK_EXTENSIONS and fake_ext in {**MEDIUM_RISK_EXTENSIONS, **LOW_RISK_EXTENSIONS}:
            return 30, {"check": "Double Extension", "description": f"File uses double extension ({fake_ext}{real_ext}). It appears to be a {fake_ext} file but is actually a {real_ext} executable. This is a very common malware trick.", "risk_contribution": 30}
        elif len(parts) >= 3:
            return 5, {"check": "Double Extension", "description": "File has multiple extensions, which is unusual.", "risk_contribution": 5}
    return 0, {"check": "Double Extension", "description": "No double extension detected.", "risk_contribution": 0}


def _check_mime_mismatch(ext: str, detected_mime: str) -> tuple:
    """Check if the file extension matches its actual content type."""
    if not detected_mime or detected_mime == "application/octet-stream":
        return 0, {"check": "Content Verification", "description": "Unable to verify file content type.", "risk_contribution": 0}

    # Simple extension-to-mime mapping for validation
    expected_mimes = {
        '.pdf': ['application/pdf'],
        '.jpg': ['image/jpeg'],
        '.jpeg': ['image/jpeg'],
        '.png': ['image/png'],
        '.gif': ['image/gif'],
        '.zip': ['application/zip'],
        '.exe': ['application/x-dosexec', 'application/x-msdownload'],
    }

    if ext in expected_mimes:
        if detected_mime not in expected_mimes[ext]:
            return 20, {"check": "Content Verification", "description": f"File extension is {ext} but content appears to be {detected_mime}. The file may be disguised.", "risk_contribution": 20}
        return 0, {"check": "Content Verification", "description": f"File content matches its extension ({ext} → {detected_mime}).", "risk_contribution": 0}

    return 0, {"check": "Content Verification", "description": "Content type appears consistent.", "risk_contribution": 0}


def _check_file_size(ext: str, size: int) -> tuple:
    """Check for anomalous file sizes."""
    if ext in HIGH_RISK_EXTENSIONS and size < 10_000:
        return 10, {"check": "File Size", "description": f"Very small executable ({_format_size(size)}). Small executables are often dropper malware that downloads larger payloads.", "risk_contribution": 10}
    elif ext in ('.pdf', '.doc', '.docx') and size < 500:
        return 8, {"check": "File Size", "description": f"Suspiciously small document ({_format_size(size)}). May be a decoy file.", "risk_contribution": 8}
    elif size > 100_000_000:
        return 5, {"check": "File Size", "description": f"Very large file ({_format_size(size)}). Could be used to evade scanning.", "risk_contribution": 5}
    return 0, {"check": "File Size", "description": f"File size ({_format_size(size)}) is within normal range.", "risk_contribution": 0}


def _check_suspicious_filename(filename: str) -> tuple:
    name_lower = filename.lower()
    found = []
    for pattern, desc in SUSPICIOUS_FILENAME_PATTERNS:
        if re.search(pattern, name_lower):
            found.append(desc)

    if len(found) >= 2:
        return 15, {"check": "Filename Analysis", "description": "; ".join(found) + ". Multiple suspicious filename indicators found.", "risk_contribution": 15}
    elif found:
        return 7, {"check": "Filename Analysis", "description": found[0] + ".", "risk_contribution": 7}
    return 0, {"check": "Filename Analysis", "description": "Filename appears normal.", "risk_contribution": 0}


def _check_content_patterns(content: bytes, ext: str) -> tuple:
    """Basic content analysis – look for suspicious strings in file content."""
    try:
        text = content[:10000].decode('utf-8', errors='ignore')
    except Exception:
        return 0, {"check": "Content Analysis", "description": "Unable to analyze file content.", "risk_contribution": 0}

    suspicious = []
    patterns = [
        (r'<script', 'Contains embedded JavaScript'),
        (r'powershell|cmd\.exe|command\.com', 'References command-line tools'),
        (r'eval\s*\(|exec\s*\(', 'Contains code execution functions'),
        (r'base64_decode|atob\(', 'Contains encoding/decoding functions'),
        (r'http[s]?://\S+\.exe', 'Contains URL pointing to executable'),
        (r'password|credential|login', 'References password/credential data'),
    ]

    for pattern, desc in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            suspicious.append(desc)

    # Only flag if not expected (e.g., scripts in .html are normal)
    if ext in ('.html', '.htm', '.js', '.php'):
        suspicious = [s for s in suspicious if 'JavaScript' not in s]

    if len(suspicious) >= 2:
        return 15, {"check": "Content Analysis", "description": "Suspicious content detected: " + "; ".join(suspicious) + ".", "risk_contribution": 15}
    elif suspicious:
        return 7, {"check": "Content Analysis", "description": suspicious[0] + ".", "risk_contribution": 7}
    return 0, {"check": "Content Analysis", "description": "No suspicious content patterns detected.", "risk_contribution": 0}


def _check_hidden_extension(filename: str) -> tuple:
    """Check for Unicode tricks or excessive spaces to hide real extension."""
    if '\u200e' in filename or '\u200f' in filename or '\u202e' in filename:
        return 25, {"check": "Hidden Extension", "description": "File name contains Unicode control characters that can be used to reverse or hide the real file extension. This is a sophisticated malware technique.", "risk_contribution": 25}
    if '  ' in filename or filename != filename.strip():
        return 10, {"check": "Hidden Extension", "description": "File name contains unusual spacing that may be used to hide the extension.", "risk_contribution": 10}
    return 0, {"check": "Hidden Extension", "description": "No hidden extension tricks detected.", "risk_contribution": 0}


def _check_virustotal(sha256: str) -> tuple:
    """Check file hash against VirusTotal database."""
    if not VIRUSTOTAL_API_KEY:
        return 0, {"check": "VirusTotal Lookup", "description": "VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY environment variable for malware database lookups.", "risk_contribution": 0}

    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        req = urllib.request.Request(url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            if malicious > 5:
                return 40, {"check": "VirusTotal Lookup", "description": f"MALWARE DETECTED: {malicious}/{total} antivirus engines flagged this file as malicious.", "risk_contribution": 40}
            elif malicious > 0 or suspicious > 2:
                return 20, {"check": "VirusTotal Lookup", "description": f"Suspicious: {malicious} malicious + {suspicious} suspicious detections out of {total} engines.", "risk_contribution": 20}
            else:
                return 0, {"check": "VirusTotal Lookup", "description": f"File is clean: 0/{total} engines detected any threat.", "risk_contribution": 0}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 0, {"check": "VirusTotal Lookup", "description": "File hash not found in VirusTotal database (first submission).", "risk_contribution": 0}
        return 0, {"check": "VirusTotal Lookup", "description": f"VirusTotal lookup failed (HTTP {e.code}).", "risk_contribution": 0}
    except Exception:
        return 0, {"check": "VirusTotal Lookup", "description": "VirusTotal lookup timed out or failed.", "risk_contribution": 0}


# ── Utility ───────────────────────────────────────────────────

def _detect_mime_type(content: bytes) -> str:
    """Basic magic-byte based MIME detection."""
    if len(content) < 4:
        return "application/octet-stream"

    signatures = {
        b'%PDF': 'application/pdf',
        b'\x89PNG': 'image/png',
        b'\xff\xd8\xff': 'image/jpeg',
        b'GIF87a': 'image/gif',
        b'GIF89a': 'image/gif',
        b'PK\x03\x04': 'application/zip',
        b'MZ': 'application/x-dosexec',
        b'\x7fELF': 'application/x-elf',
        b'Rar!': 'application/x-rar',
        b'\x1f\x8b': 'application/gzip',
    }

    for sig, mime in signatures.items():
        if content[:len(sig)] == sig:
            return mime

    return "application/octet-stream"


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size} bytes"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    return f"{size / (1024 * 1024 * 1024):.1f} GB"


def _score_to_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"
