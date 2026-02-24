"""
Mini Kalpana – Packet Monitor (Real-time Connection & Traffic Analyzer)
Monitors active network connections, traffic stats, and detects anomalies.
Uses psutil for real system data — no root/sudo required.
"""

import time
import socket
import psutil
from typing import Dict, Any, List, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ── In-memory state for delta calculations ───────────────────
_prev_io_counters = {}
_prev_io_time = 0
_connection_history = []  # rolling window for anomaly detection
_MAX_HISTORY = 300  # ~5 minutes at 1/s


# ── Suspicious ports ─────────────────────────────────────────
HIGH_RISK_PORTS = {
    23: ("Telnet", "Unencrypted remote access – often exploited by botnets"),
    135: ("MS-RPC", "Windows RPC – commonly targeted by worms"),
    445: ("SMB", "Windows file sharing – major attack vector (WannaCry, EternalBlue)"),
    1433: ("MSSQL", "Database port – should not be publicly accessible"),
    3306: ("MySQL", "Database port – target for data theft"),
    3389: ("RDP", "Remote Desktop – brute-force target"),
    4444: ("Metasploit", "Default Metasploit reverse shell port"),
    5900: ("VNC", "Screen sharing – often poorly secured"),
    6667: ("IRC", "Chat protocol – used by botnets for C&C"),
    6697: ("IRC-TLS", "Encrypted IRC – botnet communication channel"),
    8080: ("HTTP-Alt", "Alternative HTTP – often used by proxies/malware"),
    9090: ("WebSocket", "Management interface – may expose admin panels"),
    31337: ("Elite", "Classic backdoor port"),
}

MEDIUM_RISK_PORTS = {
    21: ("FTP", "Unencrypted file transfer"),
    25: ("SMTP", "Email sending – may indicate spam"),
    110: ("POP3", "Unencrypted email retrieval"),
    143: ("IMAP", "Email access"),
    161: ("SNMP", "Network management – info disclosure risk"),
    389: ("LDAP", "Directory access"),
    5432: ("PostgreSQL", "Database port"),
    6379: ("Redis", "In-memory database – often left open"),
    27017: ("MongoDB", "NoSQL database – frequently misconfigured"),
}

SAFE_PORTS = {
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    587: "SMTP-TLS",
    8000: "Dev Server",
    8443: "HTTPS-Alt",
}


# ── Process name cache ───────────────────────────────────────
_process_cache: Dict[int, str] = {}


def _get_process_name(pid: int) -> str:
    """Get process name from PID with caching."""
    if pid in _process_cache:
        return _process_cache[pid]
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        _process_cache[pid] = name
        return name
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown"


def _resolve_hostname(ip: str) -> str:
    """Reverse DNS lookup with timeout."""
    if not ip or ip in ("0.0.0.0", "::", "127.0.0.1", "::1", "*"):
        return "localhost"
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname[:50]  # truncate long hostnames
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _assess_connection_risk(remote_port: int, remote_ip: str, status: str, process: str) -> tuple:
    """Assess risk level for a single connection."""
    if remote_port in HIGH_RISK_PORTS:
        svc, reason = HIGH_RISK_PORTS[remote_port]
        return "HIGH", f"{svc}: {reason}"
    if remote_port in MEDIUM_RISK_PORTS:
        svc, reason = MEDIUM_RISK_PORTS[remote_port]
        return "MEDIUM", f"{svc}: {reason}"
    if status == "LISTEN" and remote_port == 0:
        return "LOW", "Listening for connections"
    if remote_port > 49152:
        return "LOW", "Ephemeral port"
    if remote_port in SAFE_PORTS:
        return "LOW", f"{SAFE_PORTS[remote_port]}"
    return "LOW", "Standard connection"


# ── Core functions ───────────────────────────────────────────

def get_active_connections() -> List[Dict[str, Any]]:
    """Get all active TCP/UDP connections with enriched metadata."""
    connections = []
    seen = set()

    try:
        raw_conns = psutil.net_connections(kind='inet')
    except (psutil.AccessDenied, PermissionError):
        # On macOS, might need to fall back to TCP only
        try:
            raw_conns = psutil.net_connections(kind='tcp')
        except Exception:
            return []

    # Resolve hostnames concurrently for remote IPs
    remote_ips = set()
    for conn in raw_conns:
        if conn.raddr:
            remote_ips.add(conn.raddr.ip)

    hostname_map = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {ip: executor.submit(_resolve_hostname, ip) for ip in list(remote_ips)[:20]}
        for ip, future in futures.items():
            try:
                hostname_map[ip] = future.result(timeout=1)
            except Exception:
                hostname_map[ip] = ""

    for conn in raw_conns:
        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "*:*"
        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "*:*"
        remote_ip = conn.raddr.ip if conn.raddr else ""
        remote_port = conn.raddr.port if conn.raddr else 0

        # Dedup key
        key = (local_addr, remote_addr, conn.status, conn.pid or 0)
        if key in seen:
            continue
        seen.add(key)

        process_name = _get_process_name(conn.pid) if conn.pid else "System"
        status = conn.status if hasattr(conn, 'status') else "NONE"
        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

        risk_level, risk_reason = _assess_connection_risk(remote_port, remote_ip, status, process_name)

        connections.append({
            "pid": conn.pid or 0,
            "process": process_name,
            "protocol": protocol,
            "local_addr": local_addr,
            "remote_addr": remote_addr,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "remote_hostname": hostname_map.get(remote_ip, ""),
            "status": status,
            "risk_level": risk_level,
            "risk_reason": risk_reason,
        })

    # Sort: HIGH risk first, then ESTABLISHED, then rest
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    connections.sort(key=lambda c: (risk_order.get(c["risk_level"], 3), c["status"] != "ESTABLISHED"))

    return connections


def get_traffic_stats() -> List[Dict[str, Any]]:
    """Get per-interface traffic statistics with speed calculation."""
    global _prev_io_counters, _prev_io_time

    current_time = time.time()
    current_counters = psutil.net_io_counters(pernic=True)
    stats = []

    for iface, counters in current_counters.items():
        # Skip loopback and inactive interfaces
        if iface.startswith("lo") or (counters.bytes_sent == 0 and counters.bytes_recv == 0):
            continue

        speed_up = 0.0
        speed_down = 0.0

        if iface in _prev_io_counters and _prev_io_time > 0:
            dt = current_time - _prev_io_time
            if dt > 0:
                prev = _prev_io_counters[iface]
                speed_up = (counters.bytes_sent - prev.bytes_sent) / dt
                speed_down = (counters.bytes_recv - prev.bytes_recv) / dt

        stats.append({
            "interface": iface,
            "bytes_sent": counters.bytes_sent,
            "bytes_recv": counters.bytes_recv,
            "packets_sent": counters.packets_sent,
            "packets_recv": counters.packets_recv,
            "errors_in": counters.errin,
            "errors_out": counters.errout,
            "speed_up": round(speed_up, 1),
            "speed_down": round(speed_down, 1),
        })

    _prev_io_counters = current_counters
    _prev_io_time = current_time

    # Sort by total traffic, most active first
    stats.sort(key=lambda s: s["bytes_sent"] + s["bytes_recv"], reverse=True)
    return stats


def detect_anomalies(connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect anomalous network patterns in current connections."""
    alerts = []

    # 1. High-risk port connections
    for conn in connections:
        if conn["risk_level"] == "HIGH" and conn["status"] == "ESTABLISHED":
            alerts.append({
                "alert_type": "SUSPICIOUS_PORT",
                "severity": "HIGH",
                "message": f"Active connection to high-risk port {conn['remote_port']} ({conn['risk_reason']}) by process '{conn['process']}'",
                "process": conn["process"],
                "remote_addr": conn["remote_addr"],
            })

    # 2. Process with excessive connections
    process_conn_count: Dict[str, int] = {}
    for conn in connections:
        if conn["status"] == "ESTABLISHED":
            process_conn_count[conn["process"]] = process_conn_count.get(conn["process"], 0) + 1

    for process, count in process_conn_count.items():
        if count > 50:
            alerts.append({
                "alert_type": "EXCESSIVE_CONNECTIONS",
                "severity": "MEDIUM",
                "message": f"Process '{process}' has {count} active connections – may indicate scanning or data exfiltration",
                "process": process,
                "remote_addr": "",
            })

    # 3. Listening on unusual ports
    for conn in connections:
        if conn["status"] == "LISTEN":
            local_port = int(conn["local_addr"].split(":")[-1]) if ":" in conn["local_addr"] else 0
            if local_port > 0 and local_port not in SAFE_PORTS and local_port < 49152:
                if local_port in HIGH_RISK_PORTS:
                    svc, _ = HIGH_RISK_PORTS[local_port]
                    alerts.append({
                        "alert_type": "RISKY_LISTENER",
                        "severity": "HIGH",
                        "message": f"System listening on high-risk port {local_port} ({svc}) via process '{conn['process']}'",
                        "process": conn["process"],
                        "remote_addr": conn["local_addr"],
                    })

    # 4. Unknown processes with network access
    for conn in connections:
        if conn["process"] == "Unknown" and conn["status"] == "ESTABLISHED":
            alerts.append({
                "alert_type": "UNKNOWN_PROCESS",
                "severity": "MEDIUM",
                "message": f"Unknown process (PID {conn['pid']}) has active network connection to {conn['remote_addr']}",
                "process": "Unknown",
                "remote_addr": conn["remote_addr"],
            })

    # 5. Traffic errors (check stats)
    try:
        net_io = psutil.net_io_counters()
        if net_io.errin > 100 or net_io.errout > 100:
            alerts.append({
                "alert_type": "NETWORK_ERRORS",
                "severity": "LOW",
                "message": f"Network interface errors detected: {net_io.errin} in / {net_io.errout} out – may indicate hardware or driver issues",
                "process": "System",
                "remote_addr": "",
            })
    except Exception:
        pass

    # Deduplicate by message
    seen_messages = set()
    unique_alerts = []
    for alert in alerts:
        if alert["message"] not in seen_messages:
            seen_messages.add(alert["message"])
            unique_alerts.append(alert)

    # Sort by severity
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    unique_alerts.sort(key=lambda a: severity_order.get(a["severity"], 3))

    return unique_alerts


def get_monitor_snapshot() -> Dict[str, Any]:
    """Get a complete monitoring snapshot: connections + traffic + anomalies."""
    connections = get_active_connections()
    traffic_stats = get_traffic_stats()
    alerts = detect_anomalies(connections)

    # Summary stats
    established = sum(1 for c in connections if c["status"] == "ESTABLISHED")
    listening = sum(1 for c in connections if c["status"] == "LISTEN")
    high_risk = sum(1 for c in connections if c["risk_level"] == "HIGH")

    # Total bandwidth across all interfaces
    total_up = sum(s["speed_up"] for s in traffic_stats)
    total_down = sum(s["speed_down"] for s in traffic_stats)

    return {
        "connections": connections,
        "traffic_stats": traffic_stats,
        "alerts": alerts,
        "summary": {
            "total_connections": len(connections),
            "established": established,
            "listening": listening,
            "high_risk_connections": high_risk,
            "alert_count": len(alerts),
            "bandwidth_up": round(total_up, 1),
            "bandwidth_down": round(total_down, 1),
        },
        "timestamp": datetime.now().isoformat(),
    }


def get_traffic_only() -> Dict[str, Any]:
    """Lightweight endpoint: just traffic stats (for frequent polling)."""
    traffic_stats = get_traffic_stats()
    total_up = sum(s["speed_up"] for s in traffic_stats)
    total_down = sum(s["speed_down"] for s in traffic_stats)

    return {
        "traffic_stats": traffic_stats,
        "bandwidth_up": round(total_up, 1),
        "bandwidth_down": round(total_down, 1),
        "timestamp": datetime.now().isoformat(),
    }
