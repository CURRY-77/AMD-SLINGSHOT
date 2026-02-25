"""
Mini Kalpana – Network Scanner Module
Discovers devices on the local network, scans ports, and classifies risks.
"""

import socket
import subprocess
import re
import platform
import ipaddress
import concurrent.futures
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from engine.explainability import generate_explanation

# ── Common ports to scan (top 25) ─────────────────────────────
COMMON_PORTS = {
    21: ("FTP", "File Transfer Protocol – often unencrypted"),
    22: ("SSH", "Secure Shell – remote access"),
    23: ("Telnet", "Unencrypted remote access – very insecure"),
    25: ("SMTP", "Email sending service"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Web server – unencrypted"),
    110: ("POP3", "Email retrieval – often unencrypted"),
    135: ("RPC", "Remote Procedure Call – Windows"),
    139: ("NetBIOS", "Windows file sharing – legacy"),
    143: ("IMAP", "Email retrieval"),
    443: ("HTTPS", "Secure web server"),
    445: ("SMB", "Windows file sharing"),
    993: ("IMAPS", "Secure email retrieval"),
    995: ("POP3S", "Secure email retrieval"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1723: ("PPTP", "VPN – outdated protocol"),
    3306: ("MySQL", "MySQL database"),
    3389: ("RDP", "Remote Desktop Protocol"),
    5432: ("PostgreSQL", "PostgreSQL database"),
    5900: ("VNC", "Virtual Network Computing"),
    6379: ("Redis", "Redis database"),
    8080: ("HTTP-Alt", "Alternative web server"),
    8443: ("HTTPS-Alt", "Alternative secure web server"),
    8888: ("HTTP-Alt2", "Alternative web server / Jupyter"),
    27017: ("MongoDB", "MongoDB database"),
}

# ── Port risk classification ──────────────────────────────────
HIGH_RISK_PORTS = {23, 21, 135, 139, 445, 3389, 5900, 1723}
MEDIUM_RISK_PORTS = {80, 25, 110, 143, 1433, 3306, 5432, 6379, 27017, 8080, 8888}
LOW_RISK_PORTS = {22, 53, 443, 993, 995, 8443}

# ── Device type heuristics ────────────────────────────────────
GATEWAY_SUFFIXES = [".1", ".254"]


def scan_network() -> Dict[str, Any]:
    """Main entry point: scan the local network for devices and open ports."""
    start_time = datetime.now()

    # Step 1: Get local network info
    local_info = _get_local_network_info()
    if not local_info:
        return _error_response("Could not determine local network configuration. Make sure you are connected to a network.")

    # Step 2: Discover devices
    devices_raw = _discover_devices(local_info["gateway"])

    # Always include local machine
    local_entry = {
        "ip": local_info["local_ip"],
        "mac": local_info.get("local_mac", "Unknown"),
        "hostname": _get_hostname(local_info["local_ip"]),
        "is_local": True,
    }

    # Deduplicate and add local
    device_ips = {d["ip"] for d in devices_raw}
    if local_info["local_ip"] not in device_ips:
        devices_raw.append(local_entry)

    # Step 3: Port scan all devices (parallel)
    devices = _scan_all_ports(devices_raw)

    # Step 4: Classify devices and assess risk
    for device in devices:
        device["device_type"] = _classify_device(device, local_info)
        device["risk_level"], device["risk_score"] = _assess_device_risk(device)

    # Step 5: Overall network risk
    network_risk_score, network_risk_level = _assess_network_risk(devices)

    # Step 6: Generate explanation
    findings = _build_network_findings(devices, local_info)
    explanation = generate_explanation(
        threat_type="url",  # reuse url template structure
        findings=findings,
        risk_score=network_risk_score,
        extra_context={"url": f"Local Network ({local_info['subnet']})"}
    )

    # Override explanation for network context
    explanation["what_happened"] = _build_network_what_happened(devices, local_info)
    explanation["what_it_means"] = _build_network_meaning(network_risk_score, devices)
    explanation["what_to_do"] = _build_network_actions(network_risk_score, devices)

    elapsed = (datetime.now() - start_time).total_seconds()

    return {
        "network_info": {
            "local_ip": local_info["local_ip"],
            "gateway": local_info["gateway"],
            "subnet": local_info["subnet"],
            "interface": local_info.get("interface", "Unknown"),
        },
        "devices": devices,
        "device_count": len(devices),
        "open_ports_total": sum(len(d.get("open_ports", [])) for d in devices),
        "risk_score": round(network_risk_score, 1),
        "risk_level": network_risk_level,
        "scan_duration": round(elapsed, 1),
        "explanation": explanation,
        "findings": findings,
    }


# ── Network Info ──────────────────────────────────────────────

def _get_local_network_info() -> Optional[Dict[str, str]]:
    """Get local IP, gateway, and subnet info."""
    try:
        # Get local IP by connecting to a public DNS (doesn't actually send data)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Get gateway
        gateway = _get_default_gateway()

        # Determine subnet (assume /24 for home networks)
        ip_obj = ipaddress.IPv4Address(local_ip)
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)

        return {
            "local_ip": local_ip,
            "gateway": gateway or str(network.network_address + 1),
            "subnet": str(network),
            "interface": _get_interface_name(),
        }
    except Exception:
        return None


def _get_default_gateway() -> Optional[str]:
    """Get default gateway IP."""
    try:
        if platform.system() == "Darwin":  # macOS
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "gateway:" in line:
                    return line.strip().split("gateway:")[-1].strip()
        else:  # Linux
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'default via (\S+)', result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


def _get_interface_name() -> str:
    """Get active network interface name."""
    try:
        if platform.system() == "Darwin":
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "interface:" in line:
                    return line.strip().split("interface:")[-1].strip()
    except Exception:
        pass
    return "Unknown"


# ── Device Discovery ──────────────────────────────────────────

def _discover_devices(gateway: str) -> List[Dict[str, Any]]:
    """Discover devices on the local network using ARP table."""
    devices = []

    try:
        # Method 1: Parse ARP table
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10
        )

        for line in result.stdout.splitlines():
            parsed = _parse_arp_line(line)
            if parsed:
                devices.append(parsed)

    except Exception:
        pass

    # Method 2: Ping sweep the full subnet for thorough discovery
    try:
        gateway_base = ".".join(gateway.split(".")[:3])
        _ping_sweep(gateway_base, devices)
    except Exception:
        pass

    return devices


def _parse_arp_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single line from `arp -a` output."""
    # macOS format: host (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    # Linux format: host (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
    match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)', line)
    if match:
        ip = match.group(1)
        mac = match.group(2)
        if mac == "(incomplete)" or mac == "<incomplete>":
            return None
        hostname = _extract_hostname_from_arp(line, ip)
        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "is_local": False,
        }
    return None


def _extract_hostname_from_arp(line: str, ip: str) -> str:
    """Try to extract hostname from ARP line or via reverse DNS."""
    # Check if hostname is at the start of arp line
    match = re.match(r'^(\S+)\s+\(', line)
    if match:
        name = match.group(1)
        if name != "?" and not re.match(r'^\d+\.\d+\.\d+\.\d+$', name):
            return name
    return _get_hostname(ip)


def _get_hostname(ip: str) -> str:
    """Reverse DNS lookup for hostname."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"


def _ping_sweep(base_ip: str, existing_devices: List[Dict]) -> None:
    """Quick ping sweep to discover additional devices."""
    known_ips = {d["ip"] for d in existing_devices}
    targets = [f"{base_ip}.{i}" for i in range(1, 255) if f"{base_ip}.{i}" not in known_ips]

    def ping_one(ip):
        try:
            param = "-c" if platform.system() != "Windows" else "-n"
            result = subprocess.run(
                ["ping", param, "1", "-W", "1", ip],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                return {"ip": ip, "mac": "Unknown", "hostname": _get_hostname(ip), "is_local": False}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        results = pool.map(ping_one, targets)
        for r in results:
            if r:
                existing_devices.append(r)


# ── Port Scanning ─────────────────────────────────────────────

def _scan_all_ports(devices: List[Dict]) -> List[Dict]:
    """Scan ports on all devices in parallel."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_scan_device_ports, d["ip"]): d for d in devices}
        for future in concurrent.futures.as_completed(futures):
            device = futures[future]
            try:
                device["open_ports"] = future.result()
            except Exception:
                device["open_ports"] = []
    return devices


def _scan_device_ports(ip: str) -> List[Dict[str, Any]]:
    """Scan common ports on a single device."""
    open_ports = []

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                service_name, service_desc = COMMON_PORTS.get(port, ("Unknown", "Unknown service"))
                risk = _port_risk_level(port)
                return {
                    "port": port,
                    "service": service_name,
                    "description": service_desc,
                    "risk_level": risk,
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as pool:
        results = pool.map(scan_port, COMMON_PORTS.keys())
        for r in results:
            if r:
                open_ports.append(r)

    return open_ports


def _port_risk_level(port: int) -> str:
    if port in HIGH_RISK_PORTS:
        return "HIGH"
    elif port in MEDIUM_RISK_PORTS:
        return "MEDIUM"
    return "LOW"


# ── Device Classification ─────────────────────────────────────

def _classify_device(device: Dict, local_info: Dict) -> str:
    """Classify device type based on heuristics."""
    ip = device["ip"]
    ports = {p["port"] for p in device.get("open_ports", [])}
    hostname = device.get("hostname", "").lower()

    # Gateway / Router
    if ip == local_info["gateway"] or any(ip.endswith(s) for s in GATEWAY_SUFFIXES):
        return "Router/Gateway"

    # Local machine
    if device.get("is_local") or ip == local_info["local_ip"]:
        return "This Computer"

    # Server indicators
    server_ports = {80, 443, 8080, 8443, 25, 53, 3306, 5432, 27017}
    if len(ports & server_ports) >= 2:
        return "Server"

    # Printer indicators
    if 9100 in ports or 631 in ports or "printer" in hostname or "canon" in hostname or "hp" in hostname:
        return "Printer"

    # Smart device / IoT
    if "alexa" in hostname or "echo" in hostname or "google-home" in hostname or "smart" in hostname:
        return "IoT Device"

    # Phone
    if "iphone" in hostname or "android" in hostname or "galaxy" in hostname or "pixel" in hostname:
        return "Mobile Device"

    # If has common ports, likely a computer
    if ports:
        return "Workstation"

    return "Unknown Device"


# ── Risk Assessment ───────────────────────────────────────────

def _assess_device_risk(device: Dict) -> Tuple[str, float]:
    """Assess risk level for a single device."""
    risk_score = 0.0
    open_ports = device.get("open_ports", [])

    for port_info in open_ports:
        port = port_info["port"]
        if port in HIGH_RISK_PORTS:
            risk_score += 20
        elif port in MEDIUM_RISK_PORTS:
            risk_score += 8
        else:
            risk_score += 2

    # Extra risk for many open ports
    if len(open_ports) >= 8:
        risk_score += 15
    elif len(open_ports) >= 5:
        risk_score += 8

    risk_score = min(risk_score, 100)

    if risk_score >= 80:
        return "CRITICAL", risk_score
    elif risk_score >= 60:
        return "HIGH", risk_score
    elif risk_score >= 35:
        return "MEDIUM", risk_score
    return "LOW", risk_score


def _assess_network_risk(devices: List[Dict]) -> Tuple[float, str]:
    """Assess overall network risk."""
    if not devices:
        return 0, "LOW"

    total_risk = 0
    high_risk_ports_found = 0
    total_open_ports = 0

    for device in devices:
        for port_info in device.get("open_ports", []):
            total_open_ports += 1
            if port_info["port"] in HIGH_RISK_PORTS:
                high_risk_ports_found += 1

    # Base risk from open ports
    total_risk += min(total_open_ports * 3, 40)

    # High risk ports add extra
    total_risk += min(high_risk_ports_found * 12, 40)

    # Many devices = larger attack surface
    if len(devices) >= 15:
        total_risk += 15
    elif len(devices) >= 8:
        total_risk += 8

    total_risk = min(total_risk, 100)

    if total_risk >= 80:
        return total_risk, "CRITICAL"
    elif total_risk >= 60:
        return total_risk, "HIGH"
    elif total_risk >= 35:
        return total_risk, "MEDIUM"
    return total_risk, "LOW"


# ── Findings & Explanation ────────────────────────────────────

def _build_network_findings(devices: List[Dict], local_info: Dict) -> List[Dict]:
    """Build findings list for the network scan."""
    findings = []

    # Finding 1: Device count
    count = len(devices)
    findings.append({
        "check": "Connected Devices",
        "result": f"Found {count} device(s) on the network {local_info['subnet']}.",
        "risk_contribution": 0 if count < 10 else 5 if count < 20 else 10,
    })

    # Finding 2: High-risk ports
    high_risk_devices = []
    for d in devices:
        hr_ports = [p for p in d.get("open_ports", []) if p["port"] in HIGH_RISK_PORTS]
        if hr_ports:
            port_names = ", ".join(f"{p['service']} ({p['port']})" for p in hr_ports)
            high_risk_devices.append(f"{d['ip']} – {port_names}")

    if high_risk_devices:
        findings.append({
            "check": "High-Risk Ports Detected",
            "result": "Dangerous ports are open on: " + "; ".join(high_risk_devices[:5]) + ". These services are commonly exploited by attackers.",
            "risk_contribution": min(len(high_risk_devices) * 15, 30),
        })
    else:
        findings.append({
            "check": "High-Risk Ports",
            "result": "No high-risk ports (Telnet, FTP, RDP, etc.) were found open on any device.",
            "risk_contribution": 0,
        })

    # Finding 3: Database ports
    db_ports = {3306, 5432, 27017, 6379, 1433}
    db_exposed = []
    for d in devices:
        exposed = [p for p in d.get("open_ports", []) if p["port"] in db_ports]
        if exposed:
            names = ", ".join(p["service"] for p in exposed)
            db_exposed.append(f"{d['ip']} ({names})")

    if db_exposed:
        findings.append({
            "check": "Exposed Databases",
            "result": f"Database services are accessible on the network: {'; '.join(db_exposed[:3])}. Databases should not be exposed on a network.",
            "risk_contribution": 20,
        })

    # Finding 4: Unknown devices
    unknown = [d for d in devices if d.get("device_type") == "Unknown Device"]
    if unknown:
        ips = ", ".join(d["ip"] for d in unknown[:5])
        findings.append({
            "check": "Unidentified Devices",
            "result": f"{len(unknown)} unidentified device(s) found: {ips}. Unknown devices may be unauthorized.",
            "risk_contribution": min(len(unknown) * 5, 15),
        })

    # Finding 5: Gateway security
    gateway_device = next((d for d in devices if d["ip"] == local_info["gateway"]), None)
    if gateway_device:
        gw_ports = [p for p in gateway_device.get("open_ports", []) if p["port"] in HIGH_RISK_PORTS]
        if gw_ports:
            names = ", ".join(p["service"] for p in gw_ports)
            findings.append({
                "check": "Router Security",
                "result": f"Your router ({local_info['gateway']}) has risky ports open: {names}. This could allow external attacks.",
                "risk_contribution": 20,
            })
        else:
            findings.append({
                "check": "Router Security",
                "result": f"Your router ({local_info['gateway']}) has no high-risk ports exposed. Good configuration.",
                "risk_contribution": 0,
            })

    return findings


def _build_network_what_happened(devices: List[Dict], local_info: Dict) -> str:
    total_ports = sum(len(d.get("open_ports", [])) for d in devices)
    return (
        f"We scanned your local network ({local_info['subnet']}) and discovered "
        f"{len(devices)} connected device(s) with a total of {total_ports} open port(s). "
        f"Your computer's IP address is {local_info['local_ip']} and your router is at {local_info['gateway']}."
    )


def _build_network_meaning(risk_score: float, devices: List[Dict]) -> str:
    if risk_score >= 80:
        return "Your network has significant security vulnerabilities. Multiple dangerous services are exposed, which means attackers on the same network could potentially access sensitive data, take control of devices, or intercept communications."
    elif risk_score >= 60:
        return "Your network has several security concerns. Some risky services are exposed that could be exploited by attackers who gain access to your network."
    elif risk_score >= 35:
        return "Your network has some areas that could be improved. While no critical vulnerabilities were found, reducing the number of open ports and services would strengthen your security posture."
    return "Your network appears well-configured. The number of exposed services is minimal, reducing the potential attack surface."


def _build_network_actions(risk_score: float, devices: List[Dict]) -> List[str]:
    actions = []

    # Check for specific risky ports
    has_telnet = any(p["port"] == 23 for d in devices for p in d.get("open_ports", []))
    has_ftp = any(p["port"] == 21 for d in devices for p in d.get("open_ports", []))
    has_rdp = any(p["port"] == 3389 for d in devices for p in d.get("open_ports", []))
    has_db = any(p["port"] in {3306, 5432, 27017, 6379} for d in devices for p in d.get("open_ports", []))

    if has_telnet:
        actions.append("🚫 Disable Telnet (port 23) immediately – it sends data unencrypted. Use SSH instead.")
    if has_ftp:
        actions.append("⚠️ Disable FTP (port 21) or switch to SFTP – FTP transmits passwords in plain text.")
    if has_rdp:
        actions.append("🔒 Secure RDP (port 3389) with strong passwords and consider using a VPN instead.")
    if has_db:
        actions.append("🛡️ Restrict database access – databases should not be accessible from the network without authentication.")

    if risk_score >= 60:
        actions.append("🔍 Review all devices on the network and remove any you don't recognize.")
        actions.append("📢 Report security concerns to your IT administrator.")
    elif risk_score >= 35:
        actions.append("🔍 Close unnecessary open ports on your devices.")
        actions.append("🔒 Ensure your WiFi uses WPA3 or WPA2 encryption.")

    actions.append("✅ Regularly scan your network to detect unauthorized devices.")

    return actions


def _error_response(message: str) -> Dict[str, Any]:
    return {
        "network_info": None,
        "devices": [],
        "device_count": 0,
        "open_ports_total": 0,
        "risk_score": 0,
        "risk_level": "LOW",
        "scan_duration": 0,
        "explanation": {
            "what_happened": message,
            "why_risky": ["Unable to perform network scan."],
            "what_it_means": "The scan could not be completed. Please ensure you are connected to a network.",
            "what_to_do": ["Connect to a WiFi or Ethernet network and try again."],
        },
        "findings": [],
        "error": message,
    }
