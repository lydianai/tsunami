# Changelog

All notable changes to TSUNAMI are documented here.

## [6.0.0] - 2026-02-07

### Added
- Flask-Limiter global rate limiting (200/min, 5000/hour)
- Per-endpoint rate limits on auth routes (login: 5/min, 2FA: 3-5/min)
- Gunicorn production launcher (`run_production.sh`)
- Nginx reverse proxy config with SSL, rate limiting, WebSocket support
- Prometheus scrape configuration for multi-service monitoring
- Grafana dashboard provisioning with overview dashboard
- README.md, LICENSE, CHANGELOG.md, CONTRIBUTING.md

### Fixed
- `SESSION_COOKIE_SECURE` now environment-aware (was hardcoded `True`)
- Missing `modules/shannon/__init__.py` causing import errors

### Security
- Global rate limiting prevents brute force attacks
- Nginx rate limiting zones (login: 5r/m, api: 30r/s, general: 10r/s)
- Security headers (X-Frame-Options, CSP, HSTS) in nginx config

## [5.0.0] - 2026-02-04

### Added
- Vault, sinkhole, hardening, defender status API endpoints
- Full test suite (402 tests passing)
- CI/CD pipeline (GitHub Actions)
- Docker Compose orchestration
- Prometheus metrics integration
- Sentry error tracking

### Fixed
- Turkish character matching in password validation tests
- 11 critical bugs across auth and core modules
- Flask compatibility issues in test suite

## [4.0.0] - 2025

### Added
- Initial TSUNAMI platform
- SIGINT/OSINT intelligence modules
- DEFCON alert system
- Shannon entropy analysis
- Sinkhole and honeypot systems
- AI/LLM integration (Groq, local models)
- Real-time WebSocket dashboard
