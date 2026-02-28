"""
Mini Kalpana – Pydantic Models
Request/response schemas for all threat detection endpoints.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatExplanation(BaseModel):
    """Core explainability model – every alert includes this."""
    what_happened: str = Field(..., description="Plain-English description of what was detected")
    why_risky: List[str] = Field(..., description="List of specific risk factors found")
    what_it_means: str = Field(..., description="Contextualized threat meaning for students")
    what_to_do: List[str] = Field(..., description="Actionable recommendations")


# ── URL Scanning ──────────────────────────────────────────────

class URLScanRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze")


class URLFinding(BaseModel):
    check: str
    result: str
    risk_contribution: float = Field(0.0, ge=0, le=100)
    vt_link: Optional[str] = None


class URLScanResponse(BaseModel):
    url: str
    risk_score: float = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    findings: List[URLFinding]
    explanation: ThreatExplanation
    domain_info: Optional[dict] = None


# ── Email / SMS Scanning ──────────────────────────────────────

class EmailScanRequest(BaseModel):
    content: str = Field(..., description="Email or SMS body text")
    sender: Optional[str] = Field(None, description="Sender address or phone number")
    subject: Optional[str] = Field(None, description="Email subject line")


class EmailFinding(BaseModel):
    category: str
    detail: str
    risk_contribution: float = Field(0.0, ge=0, le=100)


class EmailScanResponse(BaseModel):
    scam_probability: float = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    manipulation_type: Optional[str] = None
    findings: List[EmailFinding]
    explanation: ThreatExplanation
    embedded_urls_analysis: Optional[List[dict]] = None


# ── File Analysis ─────────────────────────────────────────────

class FileScanResponse(BaseModel):
    filename: str
    file_size: int
    md5_hash: str
    sha256_hash: str
    mime_type: Optional[str] = None
    risk_score: float = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    findings: List[dict]
    explanation: ThreatExplanation


# ── Network Scanning ──────────────────────────────────────────

class PortInfo(BaseModel):
    port: int
    service: str
    description: str
    risk_level: str


class NetworkDevice(BaseModel):
    ip: str
    mac: str = "Unknown"
    hostname: str = "Unknown"
    is_local: bool = False
    device_type: str = "Unknown"
    open_ports: List[PortInfo] = []
    risk_level: str = "LOW"
    risk_score: float = 0


class NetworkInfo(BaseModel):
    local_ip: str
    gateway: str
    subnet: str
    interface: str = "Unknown"


class NetworkScanResponse(BaseModel):
    network_info: Optional[NetworkInfo] = None
    devices: List[NetworkDevice]
    device_count: int
    open_ports_total: int
    risk_score: float = Field(0, ge=0, le=100)
    risk_level: str = "LOW"
    scan_duration: float = 0
    explanation: ThreatExplanation
    findings: List[dict]
    error: Optional[str] = None


# ── Packet Monitor ────────────────────────────────────────────

class ConnectionInfo(BaseModel):
    pid: int = 0
    process: str = "Unknown"
    protocol: str = "TCP"
    local_addr: str = "*:*"
    remote_addr: str = "*:*"
    remote_ip: str = ""
    remote_port: int = 0
    remote_hostname: str = ""
    status: str = "NONE"
    risk_level: str = "LOW"
    risk_reason: str = ""


class TrafficStats(BaseModel):
    interface: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    errors_in: int = 0
    errors_out: int = 0
    speed_up: float = 0.0
    speed_down: float = 0.0


class PacketAlert(BaseModel):
    alert_type: str
    severity: str
    message: str
    process: str = ""
    remote_addr: str = ""


class MonitorSummary(BaseModel):
    total_connections: int = 0
    established: int = 0
    listening: int = 0
    high_risk_connections: int = 0
    alert_count: int = 0
    bandwidth_up: float = 0.0
    bandwidth_down: float = 0.0


class PacketMonitorResponse(BaseModel):
    connections: List[ConnectionInfo]
    traffic_stats: List[TrafficStats]
    alerts: List[PacketAlert]
    summary: MonitorSummary
    timestamp: str


class TrafficOnlyResponse(BaseModel):
    traffic_stats: List[TrafficStats]
    bandwidth_up: float = 0.0
    bandwidth_down: float = 0.0
    timestamp: str


# ── History & Export ──────────────────────────────────────────

class ScanHistoryItem(BaseModel):
    id: int
    scan_type: str
    target: str
    risk_level: str
    risk_score: float = 0
    created_at: str

class AlertHistoryItem(BaseModel):
    id: int
    alert_type: str
    severity: str
    message: str
    process: str = ""
    remote_addr: str = ""
    created_at: str

class ScanStatsResponse(BaseModel):
    total_scans: int = 0
    threats_detected: int = 0
    safe_results: int = 0
    by_type: dict = {}
    by_risk: dict = {}


# ── Dashboard / Generic ──────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    modules: List[str] = ["url_analyzer", "email_analyzer", "file_analyzer", "network_scanner", "packet_monitor", "explainability_engine"]

