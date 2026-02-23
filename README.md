<div align="center">

# 🌊 TSUNAMI

### Advanced Cyber Intelligence & Threat Analysis Platform

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1-green?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![CI/CD](https://github.com/lydianai/tsunami/actions/workflows/ci.yml/badge.svg)](https://github.com/lydianai/tsunami/actions/workflows/ci.yml)
[![Security](https://img.shields.io/badge/Security-OWASP%20Hardened-red?style=flat-square)](SECURITY.md)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=flat-square&logo=docker)](docker-compose.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)
[![Code of Conduct](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg?style=flat-square)](CODE_OF_CONDUCT.md)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.0-85EA2D?style=flat-square&logo=swagger)](openapi.yaml)
[![White-Hat](https://img.shields.io/badge/White--Hat-Only-green?style=flat-square)](LEGAL.md)

**Real-time cyber intelligence platform with SIGINT/OSINT, threat hunting, AI-powered anomaly detection, and live WebSocket dashboards.**

[Features](#features) • [Quick Start](#quick-start) • [Architecture](#architecture) • [API Docs](#api-documentation) • [Contributing](#contributing)

</div>

---

## Overview

TSUNAMI is a production-grade cyber intelligence platform built for security operations centers (SOCs), red teams, and security researchers. It combines network intelligence, OSINT, threat feeds, AI anomaly detection, and real-time monitoring into a single unified platform.

> **White-Hat Only.** All capabilities are designed for authorized security testing, defensive operations, and research purposes.

## Features

### Core Intelligence
- **SIGINT / OSINT** — Network intelligence, open source intelligence gathering, IP/domain analysis
- **Threat Intelligence** — Real-time threat feeds, IOC analysis, VirusTotal/OTX/AbuseIPDB integration
- **DEFCON System** — Multi-level alert and defense posture management (1–5)
- **Geolocation** — IP, cell tower, and satellite tracking with Leaflet map visualization

### Detection & Response
- **Sinkhole & Honeypot** — Traffic interception and attacker behavioral analysis
- **Shannon Intelligence** — Entropy analysis and encryption detection
- **MITRE ATT&CK Mapping** — Automatic technique classification and response playbooks
- **SOAR/XDR** — Security orchestration, automated response, and extended detection

### AI & Automation
- **AI Anomaly Detection** — ML-based behavioral anomaly detection with threat prediction
- **LLM Integration** — Groq LLM and local model support for natural language threat queries
- **Graph Neural Network** — Relationship analysis between threat actors, infrastructure, and TTPs
- **Agentic SOC** — Autonomous security event triage and response recommendations

### Infrastructure
- **Real-time Dashboard** — WebSocket-powered live monitoring (Flask-SocketIO)
- **530+ API Endpoints** — RESTful API with Swagger/OpenAPI documentation
- **Multi-Database** — SQLite (dev), PostgreSQL (prod), Redis (cache/queue), MongoDB (optional)
- **Celery Task Queue** — 24/7 autonomous background threat hunting and enrichment
- **React Frontend** — Modern SPA with D3.js visualizations and Leaflet maps

---

## Quick Start

### Prerequisites

- Python 3.10+
- Git
- Redis (optional — falls back to in-memory)
- Node.js 18+ (for React frontend)

### 1. Clone & Setup

```bash
git clone https://github.com/lydianai/tsunami.git
cd tsunami

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy example config
cp .env.example .env

# Edit .env with your API keys (all optional — platform works without them)
nano .env
```

> **Minimum required:** Only `SECRET_KEY` is required. All API keys are optional — the platform degrades gracefully without them.

### 3. Run

```bash
# Development server
python3 dalga_web.py
# → http://localhost:8082

# Production server (Gunicorn)
./run_production.sh
# → http://localhost:8080
```

### 4. React Frontend (optional)

```bash
cd tsunam-react
npm install
npm start
# → http://localhost:3001
```

---

## Docker

```bash
# Full stack: web + redis + prometheus + grafana + nginx
docker-compose up -d

# Services
# TSUNAMI web:  http://localhost:8080
# Grafana:      http://localhost:3000
# Prometheus:   http://localhost:9090
```

---

## Architecture

```
tsunami/
├── dalga_web.py              # Main Flask app (530+ routes, WebSocket)
├── dalga_auth.py             # Authentication & JWT security
├── dalga_beyin.py            # AI brain module (LLM, anomaly detection)
├── dalga_hardening.py        # Security hardening middleware
├── dalga_stealth.py          # Stealth/anonymization layer
├── dalga_security.py         # Core security engine
├── dalga_osint.py            # OSINT intelligence gathering
├── dalga_geo.py              # Geolocation engine
├── dalga_threat_intel.py     # Threat intelligence feeds
├── dalga_gnn.py              # Graph Neural Network analysis
│
├── modules/                  # Feature modules
│   ├── shannon/              # Entropy & encryption analysis
│   ├── sinkhole/             # Traffic sinkhole system
│   ├── honeypot/             # Honeypot framework
│   ├── agentic_soc/          # Autonomous SOC agent
│   ├── mitre_attack/         # MITRE ATT&CK integration
│   ├── soar_xdr/             # SOAR/XDR orchestration
│   ├── threat_intelligence/  # Threat intel aggregation
│   ├── wireless_defense/     # Wireless security analysis
│   ├── quantum_crypto/       # Post-quantum cryptography
│   └── darkweb_intel/        # Dark web monitoring
│
├── routes/                   # Blueprint route handlers
├── config/                   # Service configurations
├── migrations/               # Database migration scripts
├── tests/                    # pytest test suite
├── tsunam-react/             # React SPA frontend
├── docker-compose.yml        # Full stack Docker setup
└── run_production.sh         # Gunicorn production launcher
```

### Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, Flask 3.1, Flask-SocketIO |
| Authentication | JWT (PyJWT), bcrypt, Argon2id |
| Database | SQLite / PostgreSQL + SQLAlchemy 2.0 |
| Cache / Queue | Redis 7, Celery 5 |
| Frontend | React 19, D3.js, Leaflet |
| AI/ML | Groq LLM, scikit-learn, Graph Neural Networks |
| Security | Flask-Talisman, Flask-Limiter, CSRF protection |
| Monitoring | Prometheus, Grafana, Sentry |
| CI/CD | GitHub Actions (security scan, tests, Docker build) |

---

## API Documentation

Swagger/OpenAPI docs: `http://localhost:8082/apidocs`

Key API namespaces:

| Namespace | Description |
|-----------|-------------|
| `/api/auth/` | Authentication, JWT, 2FA |
| `/api/threats/` | Threat intelligence, IOC lookup |
| `/api/osint/` | OSINT queries, IP/domain analysis |
| `/api/geo/` | Geolocation, cell tower mapping |
| `/api/shannon/` | Entropy analysis |
| `/api/sinkhole/` | Traffic sinkhole management |
| `/api/honeypot/` | Honeypot events |
| `/api/mitre/` | ATT&CK technique mapping |
| `/api/ai/` | AI/ML threat prediction |
| `/api/defcon/` | DEFCON level management |

Full documentation: [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

---

## Configuration

All configuration via environment variables. See [`.env.example`](.env.example) for the complete list.

### Required

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Flask secret key — generate with `openssl rand -hex 32` |

### Optional (enable additional features)

| Variable | Service | Free Tier |
|----------|---------|-----------|
| `SHODAN_API_KEY` | IoT/network device search | ✅ |
| `VIRUSTOTAL_API_KEY` | Malware/IOC analysis | ✅ |
| `OTX_KEY` | AlienVault threat feeds | ✅ |
| `ABUSEIPDB_KEY` | IP reputation | ✅ |
| `GROQ_API_KEY` | LLM queries | ✅ |
| `OPENCELLID_API_KEY` | Cell tower geolocation | ✅ |

---

## Testing

```bash
# Run all tests
python3 -m pytest tests/ -v

# With coverage report
python3 -m pytest tests/ --cov=. --cov-report=html
open htmlcov/index.html

# Security-specific tests
python3 -m pytest tests/test_dalga_auth.py -v
```

---

## Security

This project is designed with security-first principles:

- **OWASP Top 10** compliance (2021)
- **Flask-Talisman** for security headers (HSTS, CSP, X-Frame)
- **Flask-Limiter** for rate limiting
- **Argon2id** password hashing
- **JWT** with short-lived access tokens + refresh tokens
- **CSRF** protection on all state-changing endpoints
- **Pre-commit hooks** with `detect-secrets` and `bandit`
- **Dependency scanning** via `safety` and `pip-audit` in CI

To report a vulnerability, see [SECURITY.md](SECURITY.md).

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/lydianai/tsunami.git
cd tsunami
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
pre-commit install
```

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

Built by [AILYDIAN](https://ailydian.com) · [Report a Vulnerability](SECURITY.md) · [Contribute](CONTRIBUTING.md)

</div>
