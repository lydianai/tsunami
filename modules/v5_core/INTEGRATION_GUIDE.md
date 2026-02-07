# TSUNAMI v5.0 Integration Guide

## Quick Integration with dalga_web.py

Add the following code to your `dalga_web.py` file to integrate the v5 modules.

### 1. Import Section (add near other imports)

```python
# ==================== V5 MODULES ====================
# TSUNAMI v5 Module Integration
try:
    from modules import (
        initialize_all as init_v5,
        get_orchestrator,
        get_dashboard,
        get_event_pipeline,
        get_config_manager,
        get_available_modules
    )
    from modules.v5_core.api_routes import v5_core_bp
    from modules.v5_core.v5_init import quick_init as v5_quick_init
    V5_MODULES_AKTIF = True
except ImportError as e:
    V5_MODULES_AKTIF = False
    print(f"[DALGA] V5 Modules not available: {e}")
```

### 2. Flask Blueprint Registration (add after app initialization)

```python
# Register V5 API Routes
if V5_MODULES_AKTIF:
    try:
        app.register_blueprint(v5_core_bp)
        print("[DALGA] V5 API routes registered at /api/v5/")
    except Exception as e:
        print(f"[DALGA] Could not register V5 routes: {e}")
```

### 3. Initialize V5 System (add to startup section)

```python
# Initialize V5 Modules
def init_v5_modules():
    """Initialize TSUNAMI v5 modules"""
    if not V5_MODULES_AKTIF:
        return {"success": False, "error": "V5 modules not available"}

    try:
        # Full initialization with Flask app
        report = init_v5(app=app)

        if report.get("success"):
            print("[DALGA] V5 Modules initialized successfully")
            print(f"  - Modules loaded: {len(report.get('modules_initialized', {}))}")
        else:
            print(f"[DALGA] V5 initialization issues: {report.get('errors', [])}")

        return report
    except Exception as e:
        print(f"[DALGA] V5 initialization error: {e}")
        return {"success": False, "error": str(e)}
```

### 4. Add V5 Status to Main Status Endpoint

```python
@app.route('/api/status')
def get_status():
    """Get system status including V5 modules"""
    status = {
        # ... existing status fields ...
        "v5_modules": {
            "available": V5_MODULES_AKTIF,
            "status": None
        }
    }

    if V5_MODULES_AKTIF:
        try:
            orchestrator = get_orchestrator()
            status["v5_modules"]["status"] = orchestrator.get_status()
        except Exception as e:
            status["v5_modules"]["error"] = str(e)

    return jsonify(status)
```

### 5. Add V5 Dashboard Route

```python
@app.route('/api/v5-dashboard')
def get_v5_dashboard():
    """Get V5 unified dashboard data"""
    if not V5_MODULES_AKTIF:
        return jsonify({"error": "V5 modules not available"}), 503

    try:
        dashboard = get_dashboard()
        return jsonify(dashboard.get_dashboard_data())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

### 6. Main Entry Point (modify if __name__ == "__main__" section)

```python
if __name__ == "__main__":
    # Initialize V5 modules
    if V5_MODULES_AKTIF:
        v5_report = init_v5_modules()
        if v5_report.get("success"):
            print("=" * 50)
            print("V5 Module Status:")
            for module, status in v5_report.get("modules_initialized", {}).items():
                state = status.get("state", "unknown") if isinstance(status, dict) else "unknown"
                print(f"  {module}: {state}")
            print("=" * 50)

    # Start Flask app
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
```

## API Endpoints

After integration, the following endpoints are available:

### System
- `GET /api/v5/status` - Overall system status
- `GET /api/v5/health` - Health check
- `POST /api/v5/initialize` - Initialize system
- `POST /api/v5/shutdown` - Shutdown system

### Dashboard
- `GET /api/v5/dashboard` - Complete dashboard data
- `GET /api/v5/dashboard/metrics` - Metrics only
- `GET /api/v5/executive-summary` - Executive summary

### Modules
- `GET /api/v5/modules` - All module status
- `GET /api/v5/modules/<name>` - Specific module status
- `POST /api/v5/modules/<name>/toggle` - Enable/disable module

### Configuration
- `GET /api/v5/config` - Current configuration
- `POST /api/v5/config` - Update configuration
- `GET /api/v5/config/module/<name>` - Module config
- `POST /api/v5/config/api-key` - Set API key

### Events
- `GET /api/v5/events` - Recent events
- `POST /api/v5/events` - Submit event
- `GET /api/v5/pipeline/stats` - Pipeline stats
- `POST /api/v5/pipeline/start` - Start pipeline
- `POST /api/v5/pipeline/stop` - Stop pipeline

### Alerts
- `GET /api/v5/alerts` - Get alerts
- `POST /api/v5/alerts/<id>/status` - Update alert status

### Features
- `GET /api/v5/features` - Feature flags
- `POST /api/v5/features/<name>/toggle` - Toggle feature

### License
- `GET /api/v5/license` - License info
- `POST /api/v5/license/activate` - Activate license

## Example Usage

### Submit Security Event
```python
import requests

event = {
    "event_type": "network",
    "source": "firewall",
    "data": {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "port": 443,
        "action": "blocked"
    },
    "priority": "high"
}

response = requests.post("http://localhost:5000/api/v5/events", json=event)
print(response.json())
```

### Get Dashboard
```python
import requests

response = requests.get("http://localhost:5000/api/v5/dashboard")
data = response.json()

print(f"Risk Score: {data['data']['risk_assessment']['overall_score']}")
print(f"Open Alerts: {data['data']['metrics']['total_alerts']}")
```

### Toggle Module
```python
import requests

# Disable a module
response = requests.post(
    "http://localhost:5000/api/v5/modules/auto_pentest/toggle",
    json={"enabled": False}
)
print(response.json())
```

## Files Created

```
modules/v5_core/
    __init__.py           - Module exports
    v5_orchestrator.py    - Central orchestration
    unified_dashboard.py  - Dashboard aggregation
    event_pipeline.py     - Event processing
    config_manager.py     - Configuration management
    api_routes.py         - Flask API endpoints
    v5_init.py           - System initialization
    INTEGRATION_GUIDE.md  - This file
```
