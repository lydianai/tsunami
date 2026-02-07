# TSUNAMI STIX 2.1 / TAXII 2.1 Threat Intelligence Module v5.0

Real threat intelligence integration for TSUNAMI cybersecurity platform.

## Features

- **Real Threat Feeds**: Connects to actual public threat intelligence sources
- **STIX 2.1 Support**: Full STIX 2.1 bundle parsing and indicator extraction
- **TAXII 2.1 Support**: TAXII 2.1 server connectivity (optional taxii2-client)
- **MITRE ATT&CK Mapping**: Automatic technique mapping
- **Real-time Correlation**: Fast indicator matching against threat data
- **Alert Generation**: Automatic alerts for high-severity threats

## Supported Feeds (No API Key Required)

| Feed | Description | Update Interval |
|------|-------------|-----------------|
| abuse_ch_urlhaus | Malicious URLs | 30 min |
| abuse_ch_malwarebazaar | Malware samples | 1 hour |
| abuse_ch_threatfox | IOCs | 30 min |
| abuse_ch_feodo | Botnet C2 IPs | 1 hour |
| abuse_ch_sslbl | SSL Blacklist | 1 hour |
| cisa_kev | Known Exploited Vulnerabilities | 24 hours |
| emerging_threats | Compromised IPs | 24 hours |
| blocklist_de | Attack IPs | 1 hour |

## Supported Feeds (API Key Required)

| Feed | Description | API Key Env Var |
|------|-------------|-----------------|
| alienvault_otx | AlienVault OTX | OTX_API_KEY |

## Installation

```bash
# Required packages
pip install requests

# Optional for TAXII support
pip install taxii2-client

# Optional for full STIX support
pip install stix2
```

## Quick Start

### 1. Check an Indicator

```python
from modules.threat_intel import get_correlator

correlator = get_correlator()
result = correlator.check_ip('8.8.8.8')

print(f"Is threat: {result.is_threat}")
print(f"Score: {result.score}")
print(f"Severity: {result.severity.value}")
```

### 2. Check Multiple Indicators

```python
from modules.threat_intel import get_correlator

correlator = get_correlator()
results = correlator.check_batch([
    {'value': '192.168.1.1', 'type': 'ip'},
    {'value': 'malware.com', 'type': 'domain'},
    {'value': 'd41d8cd98f00b204e9800998ecf8427e', 'type': 'hash'}
])

for result in results:
    if result.is_threat:
        print(f"THREAT: {result.indicator_value} ({result.severity.value})")
```

### 3. Extract Indicators from Text

```python
from modules.threat_intel import STIXParser

parser = STIXParser()
indicators = parser.extract_indicators_from_text("""
    Attack originated from 192.168.1.100
    Downloaded malware from https://evil.com/payload.exe
    File hash: d41d8cd98f00b204e9800998ecf8427e
""")

for ind in indicators:
    print(f"{ind.type}: {ind.value}")
```

### 4. Parse STIX Bundle

```python
from modules.threat_intel import STIXParser

parser = STIXParser()
result = parser.parse_bundle(stix_bundle_json)

print(f"Indicators: {result['statistics']['indicators_count']}")
print(f"Malware: {result['statistics']['malware_count']}")
```

## Flask Integration

Add to dalga_web.py:

```python
from modules.threat_intel import threat_intel_bp

# Register blueprint
app.register_blueprint(threat_intel_bp)
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v5/threat-intel/feeds | List active feeds |
| PUT | /api/v5/threat-intel/feeds/<name> | Configure feed |
| GET | /api/v5/threat-intel/indicators | Get indicators |
| POST | /api/v5/threat-intel/check | Check single indicator |
| POST | /api/v5/threat-intel/check-batch | Check multiple indicators |
| GET | /api/v5/threat-intel/stats | Get statistics |
| GET | /api/v5/threat-intel/alerts | Get threat alerts |
| PUT | /api/v5/threat-intel/alerts/<id> | Update alert status |
| POST | /api/v5/threat-intel/refresh | Refresh feeds |
| POST | /api/v5/threat-intel/parse | Parse STIX bundle |
| POST | /api/v5/threat-intel/extract | Extract indicators from text |

## API Examples

### Check IP Address

```bash
curl -X POST http://localhost:5000/api/v5/threat-intel/check \
  -H "Content-Type: application/json" \
  -d '{"value": "192.168.1.1", "type": "ip"}'
```

### Check Multiple Indicators

```bash
curl -X POST http://localhost:5000/api/v5/threat-intel/check-batch \
  -H "Content-Type: application/json" \
  -d '{
    "indicators": [
      {"value": "1.2.3.4", "type": "ip"},
      {"value": "malware.com", "type": "domain"}
    ]
  }'
```

### Get Statistics

```bash
curl http://localhost:5000/api/v5/threat-intel/stats
```

### Configure AlienVault OTX

```bash
curl -X PUT http://localhost:5000/api/v5/threat-intel/feeds/alienvault_otx \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "api_key": "your-otx-api-key"}'
```

## Architecture

```
modules/threat_intel/
├── __init__.py           # Module exports
├── stix_taxii_client.py  # Feed fetching and caching
├── stix_parser.py        # STIX bundle parsing
├── threat_correlator.py  # Indicator correlation
├── api_routes.py         # Flask API routes
└── tests/
    └── test_threat_intel.py
```

## Performance

- **Caching**: All feeds are cached with configurable TTL
- **Rate Limiting**: API requests are rate-limited per endpoint
- **Indexed Lookup**: Fast O(1) indicator lookups using hash maps
- **CIDR Support**: Efficient IP range matching

## Testing

```bash
# Run unit tests
pytest modules/threat_intel/tests/ -v

# Run with integration tests (requires network)
pytest modules/threat_intel/tests/ -v -m integration
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| OTX_API_KEY | AlienVault OTX API key (free) |
| ABUSEIPDB_KEY | AbuseIPDB API key (optional) |

## License

Part of TSUNAMI v5.0 Security Platform
