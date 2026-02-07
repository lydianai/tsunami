# Integration Guide for dalga_web.py

## Quick Integration

Add this code to the imports section of `dalga_web.py`:

```python
# TSUNAMI STIX/TAXII Threat Intelligence Module v5.0
try:
    from modules.threat_intel import (
        threat_intel_bp,
        get_correlator,
        get_stix_client,
        ThreatSeverity
    )
    STIX_THREAT_INTEL_AKTIF = True
    _stix_correlator = None

    def _stix_correlator_init():
        """Initialize STIX threat correlator (lazy init)"""
        global _stix_correlator
        if _stix_correlator is None:
            _stix_correlator = get_correlator()
            # Start auto-update in background
            _stix_correlator.stix_client.start_auto_update(interval=3600)
        return _stix_correlator

except ImportError as e:
    STIX_THREAT_INTEL_AKTIF = False
    _stix_correlator = None
    def _stix_correlator_init():
        return None
    print(f"[DALGA] STIX Threat Intel modulu yuklenemedi: {e}")
```

## Register Blueprint

Add this after the Flask app is created:

```python
# Register STIX Threat Intel API routes
if STIX_THREAT_INTEL_AKTIF:
    app.register_blueprint(threat_intel_bp)
    print("[DALGA] STIX/TAXII Threat Intel API aktif: /api/v5/threat-intel/")
```

## Use in Existing Endpoints

You can add threat checking to existing OSINT endpoints:

```python
@app.route('/api/v5/osint/check-target', methods=['POST'])
def check_target():
    data = request.get_json()
    target = data.get('target', '')

    result = {'target': target}

    # Check against STIX threat intel
    if STIX_THREAT_INTEL_AKTIF:
        correlator = _stix_correlator_init()
        if correlator:
            threat_result = correlator.check_indicator(target)
            result['threat_intel'] = {
                'is_threat': threat_result.is_threat,
                'score': threat_result.score,
                'severity': threat_result.severity.value,
                'sources': threat_result.sources,
                'mitre_techniques': threat_result.mitre_techniques
            }

    return jsonify(result)
```

## SocketIO Integration

Add real-time threat alerts via WebSocket:

```python
# In imports
from modules.threat_intel.threat_correlator import ThreatAlert

# Register callback for real-time alerts
if STIX_THREAT_INTEL_AKTIF:
    def on_threat_alert(alert: ThreatAlert):
        """Emit threat alert via SocketIO"""
        socketio.emit('threat_alert', alert.to_dict(), namespace='/security')

    correlator = _stix_correlator_init()
    if correlator:
        correlator.register_alert_callback(on_threat_alert)
```

## Dashboard Integration

Add threat intel status to dashboard:

```python
@app.route('/api/v5/dashboard/status')
def dashboard_status():
    status = {
        'modules': {
            'stix_threat_intel': STIX_THREAT_INTEL_AKTIF,
            # ... other modules
        }
    }

    if STIX_THREAT_INTEL_AKTIF:
        correlator = _stix_correlator_init()
        if correlator:
            stats = correlator.get_statistics()
            status['threat_intel'] = {
                'total_indicators': stats['index_stats']['total'],
                'total_checks': stats['total_checks'],
                'total_alerts': stats['total_alerts'],
                'active_feeds': stats['feed_status']
            }

    return jsonify(status)
```

## Full Example

See the complete integration in the existing `dalga_threat_intel.py` file,
which can be extended with the new STIX/TAXII capabilities.
