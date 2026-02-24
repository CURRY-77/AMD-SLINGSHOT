"""
Mini Kalpana – FastAPI Backend Server
Main entry point for the Explainable AI Cyber Guardian API.
"""

import os
import sys
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from models import (
    URLScanRequest, URLScanResponse, URLFinding,
    EmailScanRequest, EmailScanResponse, EmailFinding,
    FileScanResponse,
    NetworkScanResponse, NetworkDevice, PortInfo, NetworkInfo,
    PacketMonitorResponse, ConnectionInfo, TrafficStats, PacketAlert, MonitorSummary, TrafficOnlyResponse,
    ScanHistoryItem, AlertHistoryItem, ScanStatsResponse,
    HealthResponse, ThreatExplanation, RiskLevel,
)
from analyzers.url_analyzer import analyze_url
from analyzers.email_analyzer import analyze_email
from analyzers.file_analyzer import analyze_file
from analyzers.network_scanner import scan_network
from analyzers.packet_monitor import get_monitor_snapshot, get_traffic_only
from database import init_db, save_scan, get_scan_history, get_scan_by_id, save_alerts, get_alerts_history, get_scan_stats

# ── App setup ─────────────────────────────────────────────────

app = FastAPI(
    title="Mini Kalpana – AI Cyber Guardian",
    description="Explainable AI-powered cybersecurity assistant for students and academic institutions.",
    version="1.0.0",
)

# CORS – allow all origins for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Serve frontend (if directory exists) ──────────────────────
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

# ── Initialize database ──────────────────────────────────────
init_db()


# ── Health check ──────────────────────────────────────────────

@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse()


# ── URL Scanning ──────────────────────────────────────────────

@app.post("/api/scan/url", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    """Analyze a URL for phishing and malicious indicators."""
    try:
        result = analyze_url(request.url)
        response = URLScanResponse(
            url=result["url"],
            risk_score=result["risk_score"],
            risk_level=RiskLevel(result["risk_level"]),
            findings=[URLFinding(**f) for f in result["findings"]],
            explanation=ThreatExplanation(**result["explanation"]),
            domain_info=result.get("domain_info"),
        )
        save_scan("url", request.url, result["risk_level"], result["risk_score"], result)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ── Email / SMS Scanning ─────────────────────────────────────

@app.post("/api/scan/email", response_model=EmailScanResponse)
async def scan_email(request: EmailScanRequest):
    """Analyze email or SMS content for scam/phishing patterns."""
    try:
        result = analyze_email(
            content=request.content,
            sender=request.sender,
            subject=request.subject,
        )
        response = EmailScanResponse(
            scam_probability=result["scam_probability"],
            risk_level=RiskLevel(result["risk_level"]),
            manipulation_type=result.get("manipulation_type"),
            findings=[EmailFinding(**f) for f in result["findings"]],
            explanation=ThreatExplanation(**result["explanation"]),
            embedded_urls_analysis=result.get("embedded_urls_analysis"),
        )
        target = request.subject or request.content[:50]
        save_scan("email", target, result["risk_level"], result["scam_probability"], result)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ── File Analysis ────────────────────────────────────────────

@app.post("/api/scan/file", response_model=FileScanResponse)
async def scan_file(file: UploadFile = File(...)):
    """Analyze an uploaded file for malware risk indicators."""
    try:
        content = await file.read()
        file_size = len(content)

        if file_size > 50 * 1024 * 1024:  # 50MB limit
            raise HTTPException(status_code=413, detail="File too large. Maximum size is 50MB.")

        result = analyze_file(
            filename=file.filename or "unknown",
            file_content=content,
            file_size=file_size,
        )

        response = FileScanResponse(
            filename=result["filename"],
            file_size=result["file_size"],
            md5_hash=result["md5_hash"],
            sha256_hash=result["sha256_hash"],
            mime_type=result.get("mime_type"),
            risk_score=result["risk_score"],
            risk_level=RiskLevel(result["risk_level"]),
            findings=result["findings"],
            explanation=ThreatExplanation(**result["explanation"]),
        )
        save_scan("file", file.filename or "unknown", result["risk_level"], result["risk_score"], result)
        return response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ── Network Scanning ─────────────────────────────────────────

@app.post("/api/scan/network", response_model=NetworkScanResponse)
async def network_scan():
    """Scan the local network for devices, open ports, and security risks."""
    try:
        result = scan_network()

        # Build response
        devices = []
        for d in result.get("devices", []):
            ports = [PortInfo(**p) for p in d.get("open_ports", [])]
            devices.append(NetworkDevice(
                ip=d["ip"],
                mac=d.get("mac", "Unknown"),
                hostname=d.get("hostname", "Unknown"),
                is_local=d.get("is_local", False),
                device_type=d.get("device_type", "Unknown"),
                open_ports=ports,
                risk_level=d.get("risk_level", "LOW"),
                risk_score=d.get("risk_score", 0),
            ))

        net_info = None
        if result.get("network_info"):
            net_info = NetworkInfo(**result["network_info"])

        response = NetworkScanResponse(
            network_info=net_info,
            devices=devices,
            device_count=result.get("device_count", 0),
            open_ports_total=result.get("open_ports_total", 0),
            risk_score=result.get("risk_score", 0),
            risk_level=result.get("risk_level", "LOW"),
            scan_duration=result.get("scan_duration", 0),
            explanation=ThreatExplanation(**result["explanation"]),
            findings=result.get("findings", []),
            error=result.get("error"),
        )
        subnet = result.get("network_info", {}).get("subnet", "local")
        save_scan("network", subnet, result.get("risk_level", "LOW"), result.get("risk_score", 0), result)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Network scan failed: {str(e)}")


# ── Packet Monitor ───────────────────────────────────────────

@app.get("/api/monitor/snapshot", response_model=PacketMonitorResponse)
async def monitor_snapshot():
    """Get real-time monitoring snapshot: connections, traffic, and alerts."""
    try:
        result = get_monitor_snapshot()
        # Save any alerts to history
        if result.get("alerts"):
            save_alerts(result["alerts"])
        return PacketMonitorResponse(
            connections=[ConnectionInfo(**c) for c in result["connections"]],
            traffic_stats=[TrafficStats(**s) for s in result["traffic_stats"]],
            alerts=[PacketAlert(**a) for a in result["alerts"]],
            summary=MonitorSummary(**result["summary"]),
            timestamp=result["timestamp"],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Monitor failed: {str(e)}")


@app.get("/api/monitor/stats", response_model=TrafficOnlyResponse)
async def monitor_stats():
    """Lightweight traffic stats endpoint for frequent polling."""
    try:
        result = get_traffic_only()
        return TrafficOnlyResponse(
            traffic_stats=[TrafficStats(**s) for s in result["traffic_stats"]],
            bandwidth_up=result["bandwidth_up"],
            bandwidth_down=result["bandwidth_down"],
            timestamp=result["timestamp"],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stats failed: {str(e)}")


# ── History & Export ───────────────────────────────────────

@app.get("/api/history")
async def history(limit: int = 50):
    """Get recent scan history from database."""
    return get_scan_history(limit)


@app.get("/api/history/stats", response_model=ScanStatsResponse)
async def history_stats():
    """Get aggregate scan statistics."""
    return ScanStatsResponse(**get_scan_stats())


@app.get("/api/alerts/history")
async def alerts_history_endpoint(limit: int = 100):
    """Get recent security alerts history."""
    return get_alerts_history(limit)


@app.get("/api/export/{scan_id}")
async def export_scan(scan_id: int):
    """Export a single scan result as JSON."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(
        content=scan,
        headers={"Content-Disposition": f"attachment; filename=kalpana_scan_{scan_id}.json"}
    )


# ── Serve frontend index ─────────────────────────────────────

@app.get("/")
async def serve_frontend():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return {"message": "Mini Kalpana API is running. Frontend not found at expected location."}


# ── Run with uvicorn ──────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
