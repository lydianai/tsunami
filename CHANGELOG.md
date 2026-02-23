# Changelog

All notable changes to TSUNAMI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- OpenAPI 3.0 interactive documentation
- Docker Hub automated image publishing
- GitHub Security Advisories integration
- OpenSSF Scorecard badge
- SBOM (Software Bill of Materials) generation

---

## [6.0.0] - 2026-02-22

### Added
- **Open Source Release**: TSUNAMI v6.0 released as open-source under MIT License
- **OSINT Suite**: Integrated 15+ reconnaissance tools (Sherlock, Maigret, theHarvester, Subfinder, Amass, DNSRecon, holehe, h8mail, phoneinfoga, social-analyzer, WhatsmyName)
- **Real-time Intelligence Dashboard**: Flask-SocketIO powered live threat feeds with 29 WebSocket events
- **DALGA SIGINT Architecture**: Signal intelligence framework for white-hat network monitoring
- **Shannon Entropy Module**: Advanced entropy analysis for anomaly detection
- **Threat Intelligence Integration**: Multi-source threat feed aggregation (VirusTotal, AbuseIPDB, Shodan, etc.)
- **Geolocation Engine**: IP/domain geolocation with MaxMind GeoIP2 integration
- **MITRE ATT&CK Mapping**: Technique identification and threat classification
- **AI/LLM Analysis**: Groq-powered threat analysis and natural language reporting
- **Sinkhole Management**: Traffic sinkhole monitoring and management interface
- **React Frontend** (`tsunam-react/`): D3.js + Leaflet interactive threat visualization SPA
- **Rate Limiting**: Flask-Limiter per-endpoint rate limiting (default: 60 req/min)
- **Session Security**: CSRF protection, secure session cookies, JWT authentication
- **Docker Support**: Multi-stage Dockerfile with production-optimized image
- **CI/CD Pipeline**: GitHub Actions workflow with security scanning (Trivy + TruffleHog + pytest)
- **Security Policy**: SECURITY.md with responsible disclosure guidelines
- **Contributing Guide**: CONTRIBUTING.md with white-hat discipline requirements

### Security
- SESSION_COOKIE_SECURE is now environment-aware (True in production, configurable in development)
- All secrets managed via environment variables (no hardcoded credentials)
- Added `.env.example` template with documented security variables
- Integrated TruffleHog secret scanning in CI pipeline
- Integrated Trivy vulnerability scanning for Docker images
- Added OWASP-compliant input validation throughout

### Infrastructure
- Gunicorn + eventlet WSGI server configuration
- PostgreSQL, SQLite, and Redis multi-database support
- Celery task queue for background intelligence processing
- Multi-environment configuration (development/production/testing)

---

## [5.x.x] - 2024-2025

### Added
- TSUNAMI v5 Otonom Siber Intelligence upgrade
- Enhanced threat correlation engine
- Multi-source OSINT pipeline
- Advanced anomaly detection algorithms
- Web scraping intelligence modules
- Expanded MITRE ATT&CK coverage

### Changed
- Major architecture refactor for scalability
- Improved WebSocket event handling
- Enhanced authentication system

---

## [4.x.x] - 2023-2024

### Added
- Initial DALGA signal intelligence module
- Basic OSINT tool integrations
- Flask-SocketIO real-time dashboard

---

## [3.x.x] - 2022-2023

### Added
- Core threat intelligence platform
- IP geolocation and WHOIS lookups
- Basic threat scoring engine

---

## [2.x.x] - 2021-2022

### Added
- Initial threat feed aggregation
- Basic web dashboard

---

## [1.0.0] - 2021

### Added
- Initial release
- Basic cyber monitoring capabilities

---

[Unreleased]: https://github.com/lydianai/tsunami/compare/v6.0.0...HEAD
[6.0.0]: https://github.com/lydianai/tsunami/releases/tag/v6.0.0
