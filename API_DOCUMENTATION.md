# TSUNAMI WEB API Documentation

**Version:** 5.0.0
**Codename:** Otonom Siber
**Generated:** 2026-02-04

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Security Features](#security-features)
4. [Health Check Endpoints](#health-check-endpoints)
5. [Core API Endpoints](#core-api-endpoints)
6. [Scanning APIs](#scanning-apis)
7. [OSINT APIs](#osint-apis)
8. [Intelligence APIs](#intelligence-apis)
9. [SIGINT APIs](#sigint-apis)
10. [GNN (Graph Neural Network) APIs](#gnn-apis)
11. [AILYDIAN AI Agent APIs](#ailydian-apis)
12. [Pentest Operations APIs](#pentest-operations-apis)
13. [Geographic APIs](#geographic-apis)
14. [VPN/Stealth APIs](#vpnstealth-apis)
15. [Security Analysis](#security-analysis)
16. [Error Handling](#error-handling)
17. [Response Formats](#response-formats)

---

## Overview

TSUNAMI WEB is a comprehensive cyber command and intelligence center providing:

- WiFi network scanning and analysis
- Bluetooth device detection
- Cell tower mapping (OpenCellID)
- IoT device discovery (Shodan)
- Vulnerability scanning
- Packet capture and analysis
- Device fingerprinting
- Signal strength heat mapping
- Real-time monitoring
- VPN integration (Mullvad)
- OSINT intelligence module
- AI-powered threat analysis

**Base URL:** `http://localhost:8080`

---

## Authentication

### Session-Based Authentication

The API uses session-based authentication with the following endpoints:

| Endpoint | Method | Description | Authentication Required |
|----------|--------|-------------|------------------------|
| `/login` | GET/POST | Login page and authentication | No |
| `/giris` | GET/POST | Turkish alias for login | No |
| `/logout` | GET | Logout and clear session | No |
| `/cikis` | GET | Turkish alias for logout | No |

### Login Request

```json
POST /login
Content-Type: application/json

{
    "username": "string",
    "password": "string",
    "totp_code": "string"  // Optional - for 2FA enabled accounts
}
```

### Login Response (Success)

```json
{
    "basarili": true,
    "yonlendir": "/panel"
}
```

### Login Response (Failure)

```json
{
    "basarili": false,
    "hata": "Gecersiz kullanici adi veya sifre"
}
```

### Protected Route Decorator

All protected endpoints use the `@login_required` decorator:

```python
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            if request.is_json:
                return jsonify({'hata': 'Oturum gerekli'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
```

---

## Security Features

### 1. Rate Limiting (Login Protection)

**Implementation:** Custom brute force protection with fallback rate limiting

- **Window:** 5 minutes (300 seconds)
- **Max Attempts:** 5 failed attempts
- **Block Duration:** 15 minutes (900 seconds) after max attempts

**Rate Limit Response (HTTP 429):**

```json
{
    "basarili": false,
    "hata": "Cok fazla basarisiz deneme. 900 saniye sonra tekrar deneyin.",
    "retry_after": 900
}
```

### 2. CSRF Protection

- CSRF token available via `/api/csrf-token` endpoint
- Session-based token generation via `_csrf_protection.generate_token()`

### 3. Input Validation

Available when `VALIDATION_AKTIF = True`:

- SQL injection detection (`check_sql_injection()`)
- XSS attack detection (`check_xss()`)
- Input sanitization (`sanitize_input()`)
- IP address validation (`is_valid_ip()`)
- Domain validation (`is_valid_domain()`)

**Injection Detection Response:**

```json
{
    "hata": "Gecersiz karakterler tespit edildi",
    "code": "INJECTION_DETECTED"
}
```

### 4. Security Headers

Applied to all responses via `@app.after_request`:

```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(self), microphone=()
Content-Security-Policy: [detailed CSP policy]
```

### 5. Session Security

```python
SESSION_COOKIE_SECURE = True  # In production (HTTPS only)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
PERMANENT_SESSION_LIFETIME = 24 hours
```

### 6. Secure Command Runner

Whitelist-based command execution with:

- Dangerous character blocking (`&`, `|`, `;`, `$`, etc.)
- Dangerous pattern detection (rm -rf, fork bomb, etc.)
- Allowed tools whitelist (nmap, nikto, wpscan, etc.)

---

## Health Check Endpoints

### Liveness Probe

```
GET /health/live

Response: 200 OK
{
    "status": "alive",
    "timestamp": "2026-02-04T12:00:00.000000"
}
```

### Readiness Probe

```
GET /health/ready

Response: 200 OK (all critical checks pass) or 503 Service Unavailable
{
    "status": "ready" | "not_ready",
    "checks": {
        "app": true,
        "database": true | false,
        "redis": true | false | null
    },
    "timestamp": "2026-02-04T12:00:00.000000"
}
```

### Simple Health Check

```
GET /health

Response: 200 OK
{
    "status": "ok"
}
```

---

## Core API Endpoints

### System Status

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/durum` | GET | Yes | System status and statistics |
| `/api/sistem/durum` | GET | Yes | Detailed system status |
| `/api/guvenlik/durum` | GET | Yes | Security modules status |
| `/api/security/status` | GET | Yes | Security module status |
| `/api/security/audit-log` | GET | Yes | Security audit logs |

**Example `/api/durum` Response:**

```json
{
    "versiyon": "5.0.0",
    "kod_adi": "Otonom Siber",
    "istatistikler": {...},
    "api_durumu": {
        "wigle": true,
        "opencellid": true,
        "shodan": false
    },
    "araclar": {...},
    "okunmamis_alarm": 5
}
```

### 2FA Setup

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/guvenlik/2fa/setup` | POST | Yes | Initialize 2FA setup |
| `/api/guvenlik/2fa/verify` | POST | Yes | Verify and activate 2FA |

### API Key Management

```
POST /api/ayarlar/api
Content-Type: application/json

{
    "servis": "shodan",  // Allowed: wigle, opencellid, shodan, virustotal, hibp, abuseipdb, otx, groq, openai, n2yo, opensky
    "anahtar": "api_key_value",
    "secret": "optional_secret"
}
```

**Validation:**

- Whitelist check for service names
- API key format validation (alphanumeric and special chars only)
- SQL injection protection

---

## Scanning APIs

### WiFi Scanning

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/wifi/tara` | POST | Yes | Scan WiFi networks |
| `/api/wifi/liste` | GET | Yes | List stored WiFi networks |
| `/api/spektrum/analiz` | GET | Yes | WiFi spectrum analysis |
| `/api/spektrum/parazit/<kanal>` | GET | Yes | Interference analysis for channel |

### Bluetooth Scanning

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/bluetooth/tara` | POST | Yes | Scan Bluetooth devices |
| `/api/bluetooth/liste` | GET | Yes | List stored Bluetooth devices |

### Port Scanning

```
POST /api/port/tara
Content-Type: application/json

{
    "hedef": "192.168.1.1",  // Target IP or domain
    "portlar": "1-1000"      // Port range (default: 1-1000)
}
```

**Input Validation:**

- SQL/Command injection detection
- Port format validation (digits, dashes, commas only)

### Vulnerability Scanning

```
POST /api/zafiyet/tara
Content-Type: application/json

{
    "hedef": "192.168.1.1"
}
```

### Location-Based Search

```
POST /api/konum/ara
Content-Type: application/json

{
    "enlem": 41.0082,   // Latitude (-90 to 90)
    "boylam": 28.9784   // Longitude (-180 to 180)
}
```

**Response:**

```json
{
    "wifi": [...],
    "bluetooth": [...],
    "baz": [...],
    "iot": [...]
}
```

---

## OSINT APIs

### Basic OSINT Lookups

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/osint/ip/<ip>` | GET | Yes | IP address lookup |
| `/api/osint/domain/<domain>` | GET | Yes | Domain lookup |
| `/api/osint/email/<email>` | GET | Yes | Email investigation |
| `/api/osint/telefon/<telefon>` | GET | Yes | Phone number lookup |
| `/api/osint/sosyal/<kullanici>` | GET | Yes | Social media search |
| `/api/osint/ip-lokasyon` | GET | Yes | Current IP geolocation |

### Advanced OSINT v2

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/osint/v2/durum` | GET | Yes | OSINT v2 status |
| `/api/osint/v2/arastir` | POST | Yes | General investigation |
| `/api/osint/v2/telefon` | POST | Yes | Phone number analysis |
| `/api/osint/v2/email` | POST | Yes | Email analysis |
| `/api/osint/v2/kullanici` | POST | Yes | Username investigation |
| `/api/osint/v2/ip` | POST | Yes | IP address analysis |
| `/api/osint/v2/domain` | POST | Yes | Domain analysis |
| `/api/osint/v2/dosya` | POST | Yes | File analysis |
| `/api/osint/v2/sifre-kontrol` | POST | Yes | Password breach check |
| `/api/osint/v2/toplu` | POST | Yes | Bulk investigation |
| `/api/osint/v2/harita` | POST | Yes | Map visualization |
| `/api/osint/v2/virustotal` | POST | Yes | VirusTotal lookup |

### Global OSINT

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/osint/global/durum` | GET | Yes | Global OSINT status |
| `/api/osint/global/infrastructure` | POST | Yes | Infrastructure mapping |
| `/api/osint/global/investigate/ip/<ip>` | GET | Yes | Deep IP investigation |
| `/api/osint/global/investigate/domain/<domain>` | GET | Yes | Deep domain investigation |
| `/api/osint/global/pastebin/search` | POST | Yes | Pastebin search |
| `/api/osint/global/countries` | GET | Yes | Country list |
| `/api/osint/global/tools/all` | GET | Yes | All OSINT tools |

### Orchestrated Investigation

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/osint/orchestrator/investigate` | POST | Yes | Orchestrated investigation |
| `/api/osint/orchestrator/analyze` | POST | Yes | Analysis pipeline |
| `/api/osint/orchestrator/tools` | GET | Yes | Available tools |
| `/api/osint/orchestrator/status` | GET | Yes | Orchestrator status |

---

## Intelligence APIs

### Shodan Integration

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/shodan/hesap` | GET | Yes | Shodan account info |
| `/api/shodan/host/<ip>` | GET | Yes | Host information |
| `/api/shodan/arama` | POST | Yes | Shodan search |
| `/api/shodan/konum` | POST | Yes | Location-based search |
| `/api/shodan/zafiyet` | POST | Yes | Vulnerability search |
| `/api/shodan/honeypot/<ip>` | GET | Yes | Honeypot detection |
| `/api/shodan/dns` | POST | Yes | DNS lookup |
| `/api/shodan/viewport` | POST | Yes | Viewport search |

### OpenCellID Integration

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/opencellid/hucre` | POST | Yes | Cell lookup |
| `/api/opencellid/baz` | POST | Yes | Base station lookup |
| `/api/opencellid/operatorler` | GET | Yes | Operator list |
| `/api/opencellid/harita` | POST | Yes | Cell tower map |
| `/api/opencellid/triangulasyon` | POST | Yes | Cell triangulation |

### Threat Intelligence

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/threat-intel/status` | GET | Yes | Threat intel status |
| `/api/threat-intel/check/ip/<ip>` | GET | Yes | IP reputation check |
| `/api/threat-intel/check/domain/<domain>` | GET | Yes | Domain reputation check |
| `/api/threat-intel/apt-groups` | GET | Yes | APT group information |
| `/api/threat-intel/correlate` | POST | Yes | Threat correlation |
| `/api/threat-intel/feeds/update` | POST | Yes | Update threat feeds |
| `/api/tehdit/guncel` | GET | Yes | Current threats |

---

## SIGINT APIs

### SIGINT Status and Scanning

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/sigint/status` | GET | Yes | SIGINT status |
| `/api/sigint/scan/wifi` | POST | Yes | WiFi SIGINT scan |
| `/api/sigint/scan/bluetooth` | POST | Yes | Bluetooth SIGINT scan |
| `/api/sigint/scan/cell` | POST | Yes | Cell SIGINT scan |
| `/api/sigint/scan/iot` | POST | Yes | IoT SIGINT scan |
| `/api/sigint/scan/all` | POST | Yes | Full SIGINT scan |

### Device Management

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/sigint/devices` | GET | Yes | All devices |
| `/api/sigint/devices/wifi` | GET | Yes | WiFi devices |
| `/api/sigint/devices/bluetooth` | GET | Yes | Bluetooth devices |
| `/api/sigint/devices/cell` | GET | Yes | Cell devices |
| `/api/sigint/devices/iot` | GET | Yes | IoT devices |
| `/api/sigint/device/<device_id>` | GET | Yes | Device details |
| `/api/sigint/search` | POST | Yes | Search devices |
| `/api/sigint/triangulate` | POST | Yes | Device triangulation |
| `/api/sigint/export/<format>` | GET | Yes | Export data (json/csv/kml) |

---

## GNN APIs

### Graph Neural Network Status

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/gnn/durum` | GET | Yes | GNN status |
| `/api/gnn/analiz` | GET | Yes | Network analysis |
| `/api/gnn/graf` | GET | Yes | Graph data |
| `/api/gnn/merkezi` | GET | Yes | Central nodes |
| `/api/gnn/topluluklar` | GET | Yes | Community detection |
| `/api/gnn/yol` | GET | Yes | Path finding |
| `/api/gnn/betweenness` | GET | Yes | Betweenness centrality |
| `/api/gnn/link-prediction` | GET | Yes | Link prediction |
| `/api/gnn/metrikler` | GET | Yes | Graph metrics |
| `/api/gnn/gpu` | GET | Yes | GPU status |
| `/api/gnn/d3` | GET | Yes | D3.js visualization data |

### GNN Operations

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/gnn/saldiri/ekle` | POST | Yes | Add attack node |
| `/api/gnn/temizle` | POST | Yes | Clear graph |
| `/api/gnn/model/kaydet` | POST | Yes | Save model |
| `/api/gnn/model/yukle` | POST | Yes | Load model |
| `/api/gnn/model/gpu` | POST | Yes | Move model to GPU |
| `/api/gnn/egitim/baslat` | POST | Yes | Start training |
| `/api/gnn/egitim/tum-modeller` | POST | Yes | Train all models |
| `/api/gnn/tehdit-feed/topla` | POST | Yes | Collect threat feeds |

---

## AILYDIAN APIs

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/ailydian/durum` | GET | Yes | System status |
| `/api/ailydian/ajanlar` | GET | Yes | List agents |
| `/api/ailydian/ajan/<ajan_id>` | GET | Yes | Agent details |
| `/api/ailydian/ajan/ara` | POST | Yes | Search agents |
| `/api/ailydian/gorev` | POST | Yes | Create task |
| `/api/ailydian/gorev/<gorev_id>/baslat` | POST | Yes | Start task |
| `/api/ailydian/gorevler` | GET | Yes | List tasks |
| `/api/ailydian/orkestrasyon` | POST | Yes | Orchestration |
| `/api/ailydian/bellek` | POST | Yes | Memory operation |
| `/api/ailydian/sorgu` | POST | Yes | Query system |
| `/api/ailydian/soru` | POST | Yes | Ask question |

### AILYDIAN v2 (Enhanced)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/ailydian/v2/status` | GET | Yes | Status |
| `/api/ailydian/v2/agents` | GET | Yes | List agents |
| `/api/ailydian/v2/agent/<agent_id>` | GET | Yes | Agent details |
| `/api/ailydian/v2/query` | POST | Yes | Query |
| `/api/ailydian/v2/execute` | POST | Yes | Execute |
| `/api/ailydian/v2/recon` | POST | Yes | Reconnaissance |
| `/api/ailydian/v2/redteam` | POST | Yes | Red team ops |
| `/api/ailydian/v2/osint` | POST | Yes | OSINT ops |
| `/api/ailydian/v2/threat` | POST | Yes | Threat analysis |
| `/api/ailydian/v2/browser` | POST | Yes | Browser automation |
| `/api/ailydian/v2/tasks` | GET | Yes | List tasks |
| `/api/ailydian/v2/memory/search` | POST | Yes | Search memory |
| `/api/ailydian/v2/memory/inject` | POST | Yes | Inject memory |
| `/api/ailydian/v2/train` | POST | Yes | Train model |
| `/api/ailydian/v2/skills/install` | POST | Yes | Install skills |
| `/api/ailydian/v2/skills/list` | GET | Yes | List skills |
| `/api/ailydian/v2/integrations/status` | GET | Yes | Integration status |

---

## Pentest Operations APIs

### Project Management

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/pentest/projeler` | GET/POST | Yes | List/Create projects |
| `/api/pentest/projeler/<proje_id>` | GET/PUT/DELETE | Yes | Project CRUD |
| `/api/pentest/bulgular` | GET/POST | Yes | List/Create findings |
| `/api/pentest/bulgular/<bulgu_id>` | GET/PUT/DELETE | Yes | Finding CRUD |
| `/api/pentest/gorevler` | GET/POST | Yes | List/Create tasks |
| `/api/pentest/gorevler/<gorev_id>` | PUT/DELETE | Yes | Task update/delete |
| `/api/pentest/istatistikler` | GET | Yes | Statistics |
| `/api/pentest/rapor/<proje_id>` | GET | Yes | Generate report |

---

## Geographic APIs

### Geographic Data

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/geo/durum` | GET | Yes | Geo module status |
| `/api/geo/kritik-altyapi` | GET | Yes | Critical infrastructure |
| `/api/geo/il-sinirlari` | GET | Yes | Province boundaries |
| `/api/geo/il-merkezleri` | GET | Yes | Province centers |
| `/api/geo/mesafe-hesapla` | POST | Yes | Distance calculation |
| `/api/geo/yakin-altyapi` | POST | Yes | Nearby infrastructure |
| `/api/geo/saldiri-ekle` | POST | Yes | Add attack marker |
| `/api/geo/saldiri-geojson` | GET | Yes | Attack GeoJSON |
| `/api/geo/hotspot-analizi` | GET | Yes | Hotspot analysis |
| `/api/geo/kmeans-clustering` | GET | Yes | K-means clustering |

### Aerospace

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/airspace/aircraft` | POST | Yes | Aircraft lookup |
| `/api/airspace/track/<icao24>` | GET | Yes | Track aircraft |
| `/api/airspace/turkey` | GET | Yes | Turkey airspace |
| `/api/satellite/iss` | GET | Yes | ISS position |
| `/api/satellite/position/<norad_id>` | GET | Yes | Satellite position |
| `/api/satellite/turksat` | GET | Yes | Turksat satellites |
| `/api/satellite/starlink` | POST | Yes | Starlink positions |
| `/api/aerospace/durum` | GET | Yes | Aerospace status |

### Weather and Seismic

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/deprem/son` | GET | Yes | Recent earthquakes |
| `/api/deprem/faylar` | GET | Yes | Fault lines |
| `/api/deprem/bildirim` | GET | Yes | Earthquake alerts |
| `/api/hava/koordinat` | POST | Yes | Weather by coordinates |
| `/api/hava/il/<il>` | GET | Yes | Weather by province |
| `/api/hava/iller` | GET | Yes | Available provinces |

---

## VPN/Stealth APIs

### VPN Management

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/vpn/durum` | GET | Yes | VPN status |
| `/api/vpn/baglan` | POST | Yes | Connect VPN |
| `/api/vpn/kes` | POST | Yes | Disconnect VPN |
| `/api/vpn/sunucular` | GET | Yes | VPN servers |
| `/api/vpn/killswitch` | POST | Yes | Toggle kill switch |

### Stealth Mode

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/stealth/durum` | GET | Yes | Stealth status |
| `/api/stealth/harita` | GET | Yes | Stealth network map |
| `/api/stealth/seviye` | POST | Yes | Set stealth level |
| `/api/stealth/dondur` | POST | Yes | Rotate stealth route |
| `/api/stealth/baslat` | POST | Yes | Start stealth |
| `/api/stealth/durdur` | POST | Yes | Stop stealth |

### Ghost Mode

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/ghost/status` | GET | Yes | Ghost mode status |
| `/api/ghost/activate` | POST | Yes | Activate ghost mode |

---

## Security Analysis

### Authentication Assessment

| Category | Status | Notes |
|----------|--------|-------|
| Session-based auth | **IMPLEMENTED** | Uses Flask sessions with secure cookies |
| Login protection | **IMPLEMENTED** | Brute force protection with rate limiting |
| 2FA support | **IMPLEMENTED** | TOTP-based two-factor authentication |
| CSRF protection | **IMPLEMENTED** | Token-based CSRF protection |
| Session security | **IMPLEMENTED** | HTTPOnly, SameSite=Strict, Secure (in production) |

### Input Validation Assessment

| Category | Status | Notes |
|----------|--------|-------|
| SQL injection protection | **IMPLEMENTED** | Via `check_sql_injection()` |
| XSS protection | **IMPLEMENTED** | Via `check_xss()` and output sanitization |
| Command injection protection | **IMPLEMENTED** | Whitelist-based command validation |
| Input sanitization | **IMPLEMENTED** | Via `sanitize_input()` |
| Type validation | **IMPLEMENTED** | Coordinate range validation, port format validation |

### Rate Limiting Assessment

| Category | Status | Notes |
|----------|--------|-------|
| Login rate limiting | **IMPLEMENTED** | 5 attempts per 5 minutes, 15-minute block |
| API rate limiting | **PARTIAL** | Module available but not applied to all endpoints |
| Redis-based rate limiting | **AVAILABLE** | Via `dalga_hardening` module when enabled |

### Protected Endpoints Summary

**Total Endpoints:** 304
**Protected with @login_required:** 289 endpoints (95%)
**Public Endpoints:** 15 endpoints (health checks, login, static)

### Unprotected Endpoints (By Design)

| Endpoint | Reason |
|----------|--------|
| `/` | Redirects to login/panel |
| `/login`, `/giris` | Authentication endpoint |
| `/logout`, `/cikis` | Logout functionality |
| `/health`, `/health/live`, `/health/ready` | Health checks for monitoring |
| `/api/csrf-token` | CSRF token retrieval |

---

## Error Handling

### Standard Error Response Format

```json
{
    "basarili": false,
    "hata": "Error message in Turkish"
}
```

Or:

```json
{
    "hata": "Error message"
}
```

### HTTP Status Codes

| Code | Meaning | Common Scenarios |
|------|---------|------------------|
| 200 | Success | Successful request |
| 400 | Bad Request | Missing parameters, invalid input |
| 401 | Unauthorized | Session required, invalid credentials |
| 403 | Forbidden | Dangerous command blocked |
| 404 | Not Found | Resource not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Module not active |

### Input Validation Errors

```json
{
    "hata": "Gecersiz karakterler tespit edildi",
    "code": "INJECTION_DETECTED"
}
```

### Module Not Active Errors

```json
{
    "basarili": false,
    "hata": "2FA modulu aktif degil"
}
```

---

## Response Formats

### Success Response (Simple)

```json
{
    "basarili": true
}
```

### Success Response (With Data)

```json
{
    "basarili": true,
    "sonuc_sayisi": 10,
    "sonuclar": [...]
}
```

### List Response

```json
[
    {"id": 1, "name": "..."},
    {"id": 2, "name": "..."}
]
```

### Status Response

```json
{
    "versiyon": "5.0.0",
    "kod_adi": "Otonom Siber",
    "zaman": "2026-02-04T12:00:00.000000",
    "istatistikler": {...},
    "moduller": {...}
}
```

---

## WebSocket Events

The application also provides WebSocket support via Socket.IO:

### Client Events (Emit to Server)

| Event | Description |
|-------|-------------|
| `tarama_baslat` | Start scan (wifi/bluetooth) |
| `konum_ara` | Location search |
| `port_tara` | Port scan |
| `zafiyet_tara` | Vulnerability scan |
| `spektrum_analiz` | Spectrum analysis |
| `trafik_izle` | Traffic monitoring |
| `cihaz_analiz` | Device fingerprinting |
| `canli_tarama` | Live scanning |
| `terminal_komut` | Terminal command |

### Server Events (Receive from Server)

| Event | Description |
|-------|-------------|
| `baglandi` | Connection established |
| `tarama_durumu` | Scan status update |
| `tarama_sonuc` | Scan results |
| `arama_ilerleme` | Search progress |
| `arama_sonuc` | Search results |
| `terminal_cikti` | Terminal output |
| `arac_basladi` | Tool started |

---

## Security Recommendations

### Current Strengths

1. **Authentication:** Comprehensive session-based auth with 2FA support
2. **Input Validation:** SQL injection and XSS protection implemented
3. **Rate Limiting:** Login rate limiting with brute force protection
4. **Security Headers:** Full set of security headers applied
5. **CSRF Protection:** Token-based CSRF protection available
6. **Command Execution:** Whitelist-based secure command runner

### Areas for Enhancement

1. **API Rate Limiting:** Apply rate limiting to all API endpoints, not just login
2. **JWT Support:** Consider adding JWT for stateless API authentication
3. **Audit Logging:** Comprehensive audit logging for all sensitive operations
4. **IP Whitelisting:** Consider IP-based access control for admin endpoints
5. **Request Signing:** Implement request signing for critical operations

---

## Module Dependencies

| Module | Status Flag | Description |
|--------|-------------|-------------|
| `dalga_secrets` | `SECRETS_MANAGER_AKTIF` | Secure API key management |
| `dalga_validation` | `VALIDATION_AKTIF` | Input validation |
| `dalga_auth` | `AUTH_SECURITY_AKTIF` | Authentication security |
| `dalga_security` | `SECURITY_AKTIF` | Security hardening |
| `dalga_hardening` | `HARDENING_AKTIF` | CSRF, HTTPS, rate limiting |
| `dalga_beyin` | `BEYIN_AKTIF` | Autonomous intelligence |
| `dalga_stealth` | `STEALTH_AKTIF` | Stealth networking |
| `dalga_geo` | `GEO_MODUL_AKTIF` | Geographic analysis |
| `dalga_gnn` | `GNN_MODUL_AKTIF` | Graph neural network |
| `dalga_threat_intel` | `THREAT_INTEL_AKTIF` | Threat intelligence |
| `dalga_vault` | `VAULT_AKTIF` | Encrypted key storage |
| `dalga_ghost` | `GHOST_MODE_AKTIF` | Military-grade encryption |
| `siber_komuta` | `SIBER_KOMUTA_AKTIF` | Cyber command center |
| `dalga_osint_global` | `GLOBAL_OSINT_AKTIF` | Global OSINT |
| `dalga_global_eagle` | `EAGLE_EYE_AKTIF` | Global monitoring |

---

**Document Version:** 1.0
**Last Updated:** 2026-02-04
**Author:** TSUNAMI Security Analysis
