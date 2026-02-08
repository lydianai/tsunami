# Blueprint Migration Plan

## Current State

`dalga_web.py` is a 22,467-line monolith with 487 route handlers.

## Target Architecture

```
blueprints/
  __init__.py          # register_blueprints()
  api_status.py        # /api/durum, /api/health (DONE)
  api_auth.py          # /login, /giris, /cikis, 2FA routes
  api_scan.py          # /api/wifi/tara, /api/port/tara, /api/zafiyet/tara
  api_threat.py        # /api/tehdit/*, threat intelligence
  api_network.py       # /api/trafik/*, /api/spektrum/*
  api_geo.py           # /api/konum/*, /api/harita/*
  api_export.py        # /api/disa-aktar/*
  api_admin.py         # Admin panel routes
  api_osint.py         # OSINT tool routes
  api_defcon.py        # DEFCON system routes
  pages.py             # HTML page routes (/, /dashboard, /harita, etc.)
```

## Migration Steps

1. **Create blueprint file** with route handlers
2. **Move route functions** from dalga_web.py to blueprint
3. **Update imports** - shared state (db, limiter) via `current_app` or function params
4. **Register blueprint** in `blueprints/__init__.py`
5. **Remove old routes** from dalga_web.py
6. **Run tests** to verify no regression

## Route Group Summary (487 total)

| Group           | Prefix               | ~Routes | Priority |
|-----------------|----------------------|---------|----------|
| Auth/Login      | /login, /giris, 2FA  | ~20     | P0       |
| Status/Health   | /api/durum, /health  | ~5      | P0 (done)|
| Scanning        | /api/*/tara          | ~15     | P1       |
| Threat Intel    | /api/tehdit/*        | ~20     | P1       |
| Network         | /api/trafik/*        | ~10     | P2       |
| OSINT           | /api/osint/*         | ~50     | P2       |
| Geolocation     | /api/konum/*         | ~10     | P2       |
| Export           | /api/disa-aktar/*    | ~5      | P3       |
| Admin           | /admin/*             | ~30     | P3       |
| Pages (HTML)    | /, /dashboard, etc.  | ~50     | P3       |
| DEFCON          | /api/defcon/*        | ~15     | P3       |
| Remaining       | Various              | ~257    | P3       |

## Shared Dependencies

These are used across routes and need to be accessible via `current_app` or dependency injection:

- `limiter` (Flask-Limiter)
- `socketio` (Flask-SocketIO)
- Database connection
- `_login_attempts` dict
- `login_required` decorator
- Various module instances (beyin, stealth, etc.)

## Notes

- Do NOT migrate all routes at once. Move one group at a time.
- Keep backward compatibility - old URLs must keep working.
- Test each migration independently before proceeding.
