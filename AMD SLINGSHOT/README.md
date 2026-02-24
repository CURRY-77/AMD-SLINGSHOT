# Mini Kalpana – Explainable AI Cyber Guardian

An AI-powered cybersecurity assistant built for students and academic institutions. Every threat detected comes with a plain-English explanation of **what happened**, **why it's risky**, **what it means**, and **what to do**.

## Features

| Module | Description |
|--------|------------|
| **URL Scanner** | 10 heuristic checks – HTTPS, brand impersonation, homoglyphs, entropy, suspicious TLDs |
| **Email/SMS Scanner** | 8 pattern-based checks – urgency keywords, financial manipulation, authority impersonation |
| **File Analyzer** | 7 risk checks + VirusTotal hash lookup – extension analysis, MIME magic bytes, content patterns |
| **Network Map** | ARP device discovery + 25-port TCP scan – risk-scored topology visualization |
| **Packet Monitor** | Real-time connection monitoring – live bandwidth chart, anomaly detection, security alerts |
| **Dark/Light Mode** | Theme toggle with localStorage persistence |
| **Persistent History** | SQLite database – all scan results stored permanently with export capability |

## Quick Start

```bash
# 1. Install dependencies
cd backend
pip install fastapi uvicorn psutil pydantic

# 2. Start the server
python main.py

# 3. Open in browser
open http://localhost:8000
```

### Optional: VirusTotal Integration

```bash
export VIRUSTOTAL_API_KEY="your_api_key_here"
python main.py
```

Get a free API key at [virustotal.com](https://www.virustotal.com/gui/join-us).

### Optional: Full Connection Visibility (macOS)

```bash
sudo python3 main.py
```

This enables process-level connection data in the Packet Monitor.

## Architecture

```
mini-kalpana/
├── backend/
│   ├── main.py                 # FastAPI server + all API endpoints
│   ├── models.py               # Pydantic request/response schemas
│   ├── database.py             # SQLite persistence layer
│   ├── analyzers/
│   │   ├── url_analyzer.py     # URL phishing detection (10 checks)
│   │   ├── email_analyzer.py   # Email/SMS scam detection (8 checks)
│   │   ├── file_analyzer.py    # File malware analysis + VirusTotal
│   │   ├── network_scanner.py  # ARP/TCP network discovery
│   │   └── packet_monitor.py   # Real-time connection monitoring
│   └── engine/
│       └── explainability.py   # Human-readable threat explanations
├── frontend/
│   ├── index.html              # SPA shell
│   ├── styles.css              # Design system (dark + light modes)
│   ├── components.js           # Reusable UI components
│   └── app.js                  # Router, page renderers, API layer
└── README.md
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|------------|
| GET | `/api/health` | Health check + module list |
| POST | `/api/scan/url` | Analyze a URL |
| POST | `/api/scan/email` | Analyze email/SMS content |
| POST | `/api/scan/file` | Analyze an uploaded file |
| POST | `/api/scan/network` | Scan local network |
| GET | `/api/monitor/snapshot` | Real-time connection + traffic data |
| GET | `/api/monitor/stats` | Lightweight traffic stats |
| GET | `/api/history` | Get scan history |
| GET | `/api/history/stats` | Aggregate scan statistics |
| GET | `/api/alerts/history` | Security alerts history |
| GET | `/api/export/{id}` | Export scan result as JSON |

## Tech Stack

- **Backend**: Python, FastAPI, psutil, SQLite
- **Frontend**: Vanilla HTML/CSS/JS, Chart.js
- **Analysis**: Heuristic-based scoring, pattern matching, VirusTotal API

## License

Academic use. Built as a cybersecurity education tool.
