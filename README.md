# TSUNAMI v6.0 - NEPTUNE_GHOST

Advanced Cyber Intelligence & Threat Analysis Platform.

## Features

- **SIGINT / OSINT**: Network intelligence, open source intelligence gathering
- **Threat Intelligence**: Real-time threat feeds, IOC analysis, malware scanning
- **DEFCON System**: Multi-level alert/defense posture management
- **Sinkhole & Honeypot**: Traffic interception and attacker analysis
- **Geolocation**: IP/cell tower/satellite tracking with map visualization
- **AI Integration**: Groq LLM, local LLM support, anomaly detection
- **Shannon Intelligence**: Entropy analysis, encryption detection
- **Real-time Dashboard**: WebSocket-powered live monitoring via Flask-SocketIO

## Requirements

- Python 3.10+
- Redis (optional, for caching/rate limiting/task queue)
- PostgreSQL (optional, SQLite default)

## Quick Start

```bash
# Clone
git clone <repo-url> && cd tsunami

# Virtual environment
python3 -m venv venv && source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy env config
cp .env.example .env
# Edit .env with your API keys

# Run database migrations
python3 -c "from dalga_web import app; app.app_context().__enter__()"

# Development server
python3 dalga_web.py

# Production server (Gunicorn)
./run_production.sh
```

Server starts at `http://localhost:8080`

## Docker

```bash
docker-compose up -d
```

Services: tsunami-web (8080), redis (6379), prometheus (9090), grafana (3000), nginx (80/443)

## Project Structure

```
tsunami/
  dalga_web.py          # Main Flask app (routes, WebSocket, API)
  dalga_auth.py         # Authentication & security
  dalga_hardening.py    # Security hardening middleware
  dalga_beyin.py        # AI brain module
  dalga_stealth.py      # Stealth/anonymization layer
  modules/              # Feature modules
    shannon/            # Entropy/encryption analysis
    sinkhole/           # Traffic sinkhole
    honeypot/           # Honeypot system
    hunter/             # Threat hunting
    wireless/           # Wireless intelligence
    federated/          # Federated operations
    soar/               # Security orchestration
  config/               # Docker service configs (nginx, prometheus, grafana)
  migrations/           # Database migration SQL files
  tests/                # Test suite (pytest)
  run_production.sh     # Gunicorn production launcher
```

## Testing

```bash
# Run all tests
python3 -m pytest tests/ -v

# With coverage
python3 -m pytest tests/ --cov=. --cov-report=html

# Specific module
python3 -m pytest tests/test_dalga_auth.py -v
```

## Configuration

All configuration via environment variables. See `.env.example` for full list.

Key variables:
- `SECRET_KEY` - Flask secret (required in production)
- `DATABASE_URL` - Database connection string
- `REDIS_URL` - Redis connection for caching/queues
- `FLASK_ENV` - `production` or `development`
- `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, etc. - External API keys

## API Documentation

Swagger/OpenAPI docs available at `/apidocs` when Flasgger is enabled.

## License

Proprietary. See [LICENSE](LICENSE) for details.
