#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 - Dark Web Intelligence API Routes
    Flask API endpoints for dark web monitoring and threat intelligence
================================================================================

    Endpoints:
    - POST /api/v5/darkweb/check-email - Check email in breaches
    - POST /api/v5/darkweb/check-domain - Check domain for breaches
    - POST /api/v5/darkweb/check-password - Check password exposure
    - GET  /api/v5/darkweb/threats - Current threat feed data
    - POST /api/v5/darkweb/threats/query - Query specific IOC
    - POST /api/v5/darkweb/monitor - Add keyword to monitor
    - GET  /api/v5/darkweb/monitor/rules - List monitoring rules
    - DELETE /api/v5/darkweb/monitor/rules/<rule_id> - Delete a rule
    - GET  /api/v5/darkweb/alerts - Get monitoring alerts
    - POST /api/v5/darkweb/alerts/<alert_id>/acknowledge - Acknowledge alert
    - GET  /api/v5/darkweb/feeds - Feed status
    - POST /api/v5/darkweb/feeds/update - Force feed update
    - GET  /api/v5/darkweb/tor/status - Tor connection status
    - POST /api/v5/darkweb/pastes/search - Search paste sites
    - GET  /api/v5/darkweb/stats - Overall statistics

================================================================================
"""

import os
import logging
from functools import wraps
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import asdict

from flask import Blueprint, request, jsonify, Response, current_app

# Import our modules
from .breach_checker import (
    BreachChecker, BreachResult, BreachSeverity,
    get_breach_checker
)
from .threat_feed_aggregator import (
    ThreatFeedAggregator, ThreatIOC, ThreatSeverity as ThreatSev,
    get_threat_aggregator
)
from .keyword_monitor import (
    KeywordMonitor, MonitoringRule, Alert, MonitoringCategory,
    AlertSeverity, AlertSource, get_keyword_monitor, create_organization_monitor
)
from .paste_monitor import (
    PasteMonitor, PasteResult, SensitiveDataType,
    get_paste_monitor
)
from .tor_client import TorClient, get_tor_client

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Blueprint
darkweb_bp = Blueprint("darkweb", __name__, url_prefix="/api/v5/darkweb")


# ============================================================================
# Helper Functions
# ============================================================================

def api_response(data: Any = None, error: str = None, status: int = 200) -> tuple:
    """Create standardized API response"""
    response = {
        "success": error is None,
        "timestamp": datetime.now().isoformat()
    }

    if data is not None:
        response["data"] = data
    if error:
        response["error"] = error

    return jsonify(response), status


def validate_email(email: str) -> bool:
    """Basic email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_domain(domain: str) -> bool:
    """Basic domain validation"""
    import re
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    return bool(re.match(pattern, domain))


def require_api_key(f):
    """Decorator to require API key for endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
        expected_key = os.getenv("TSUNAMI_API_KEY")

        if expected_key and api_key != expected_key:
            return api_response(error="Invalid or missing API key", status=401)

        return f(*args, **kwargs)
    return decorated


def serialize_dataclass(obj: Any) -> Dict:
    """Serialize dataclass to dict, handling enums and datetimes"""
    if hasattr(obj, '__dataclass_fields__'):
        result = {}
        for field_name in obj.__dataclass_fields__:
            value = getattr(obj, field_name)
            result[field_name] = serialize_dataclass(value)
        return result
    elif isinstance(obj, list):
        return [serialize_dataclass(item) for item in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif hasattr(obj, 'value'):  # Enum
        return obj.value
    else:
        return obj


# ============================================================================
# Breach Checker Endpoints
# ============================================================================

@darkweb_bp.route("/check-email", methods=["POST"])
@require_api_key
def check_email_breach():
    """
    Check if an email has been in any data breaches

    Request Body:
        {
            "email": "user@example.com",
            "check_pastes": true
        }

    Returns:
        Breach information including severity, affected services, and recommendations
    """
    try:
        data = request.get_json()

        if not data or "email" not in data:
            return api_response(error="Email address required", status=400)

        email = data["email"].strip().lower()

        if not validate_email(email):
            return api_response(error="Invalid email format", status=400)

        check_pastes = data.get("check_pastes", True)

        # Check breaches
        checker = get_breach_checker()
        result = checker.check_email(email, check_pastes=check_pastes)

        # Serialize result
        response_data = serialize_dataclass(result)

        logger.info(f"[API] Email breach check: {email} - {result.total_breaches} breaches found")

        return api_response(data=response_data)

    except ValueError as e:
        return api_response(error=str(e), status=400)
    except Exception as e:
        logger.error(f"[API] Email breach check error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/check-domain", methods=["POST"])
@require_api_key
def check_domain_breach():
    """
    Check if a domain has been involved in any breaches

    Request Body:
        {
            "domain": "example.com"
        }

    Returns:
        List of breaches associated with the domain
    """
    try:
        data = request.get_json()

        if not data or "domain" not in data:
            return api_response(error="Domain required", status=400)

        domain = data["domain"].strip().lower()

        if not validate_domain(domain):
            return api_response(error="Invalid domain format", status=400)

        # Check domain
        checker = get_breach_checker()
        result = checker.check_domain(domain)

        response_data = serialize_dataclass(result)

        logger.info(f"[API] Domain breach check: {domain} - {result.total_breaches} breaches found")

        return api_response(data=response_data)

    except Exception as e:
        logger.error(f"[API] Domain breach check error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/check-password", methods=["POST"])
@require_api_key
def check_password_exposure():
    """
    Check if a password has been exposed in breaches (using k-Anonymity)

    Request Body:
        {
            "password": "the_password"
        }

    Note: Password is never sent to external APIs - only first 5 chars of SHA1 hash

    Returns:
        Whether password has been pwned and how many times
    """
    try:
        data = request.get_json()

        if not data or "password" not in data:
            return api_response(error="Password required", status=400)

        password = data["password"]

        if len(password) < 1:
            return api_response(error="Password cannot be empty", status=400)

        # Check password
        checker = get_breach_checker()
        result = checker.check_password(password)

        response_data = serialize_dataclass(result)

        # Don't log password, just result
        logger.info(f"[API] Password check completed - Pwned: {result.is_pwned}")

        return api_response(data=response_data)

    except Exception as e:
        logger.error(f"[API] Password check error: {e}")
        return api_response(error="Internal server error", status=500)


# ============================================================================
# Threat Feed Endpoints
# ============================================================================

@darkweb_bp.route("/threats", methods=["GET"])
@require_api_key
def get_threats():
    """
    Get current threat intelligence data

    Query Parameters:
        - type: Filter by IOC type (url, ip, domain, hash)
        - source: Filter by source (urlhaus, threatfox, etc.)
        - min_confidence: Minimum confidence score (0.0-1.0)
        - limit: Maximum results (default 100)

    Returns:
        List of threat IOCs
    """
    try:
        ioc_type = request.args.get("type")
        source = request.args.get("source")
        min_confidence = float(request.args.get("min_confidence", 0.0))
        limit = int(request.args.get("limit", 100))

        aggregator = get_threat_aggregator()
        iocs = aggregator.get_iocs(
            ioc_type=ioc_type,
            source=source,
            min_confidence=min_confidence,
            limit=limit
        )

        response_data = [serialize_dataclass(ioc) for ioc in iocs]

        return api_response(data={
            "iocs": response_data,
            "count": len(response_data),
            "filters": {
                "type": ioc_type,
                "source": source,
                "min_confidence": min_confidence
            }
        })

    except Exception as e:
        logger.error(f"[API] Get threats error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/threats/query", methods=["POST"])
@require_api_key
def query_threat():
    """
    Query a specific IOC across all threat feeds

    Request Body:
        {
            "type": "url|ip|hash|domain",
            "value": "the_indicator"
        }

    Returns:
        Matching threat intelligence from all sources
    """
    try:
        data = request.get_json()

        if not data or "value" not in data:
            return api_response(error="IOC value required", status=400)

        ioc_type = data.get("type", "auto")
        value = data["value"].strip()

        aggregator = get_threat_aggregator()
        results = []

        # Auto-detect type if not specified
        if ioc_type == "auto":
            if value.startswith("http"):
                ioc_type = "url"
            elif len(value) in [32, 40, 64] and value.isalnum():
                ioc_type = "hash"
            elif "." in value and not "/" in value:
                # Could be IP or domain
                import re
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', value):
                    ioc_type = "ip"
                else:
                    ioc_type = "domain"

        # Query based on type
        if ioc_type == "url":
            results = aggregator.query_url(value)
        elif ioc_type == "hash":
            results = aggregator.query_hash(value)
        elif ioc_type == "ip":
            results = aggregator.query_ip(value)

        response_data = [serialize_dataclass(r) for r in results]

        return api_response(data={
            "query": value,
            "type": ioc_type,
            "found": len(results) > 0,
            "results": response_data
        })

    except Exception as e:
        logger.error(f"[API] Query threat error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/feeds", methods=["GET"])
@require_api_key
def get_feed_status():
    """
    Get status of all threat feeds

    Returns:
        Status, last update time, and IOC count for each feed
    """
    try:
        aggregator = get_threat_aggregator()
        status = aggregator.get_feed_status()

        return api_response(data=status)

    except Exception as e:
        logger.error(f"[API] Feed status error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/feeds/update", methods=["POST"])
@require_api_key
def force_feed_update():
    """
    Force update of all threat feeds

    Request Body (optional):
        {
            "feeds": ["urlhaus", "threatfox"]  // Specific feeds to update
        }

    Returns:
        Update results with counts per feed
    """
    try:
        aggregator = get_threat_aggregator()
        results = aggregator.update_all()

        return api_response(data={
            "updated": True,
            "results": results,
            "total_new_iocs": sum(results.values())
        })

    except Exception as e:
        logger.error(f"[API] Feed update error: {e}")
        return api_response(error="Internal server error", status=500)


# ============================================================================
# Keyword Monitoring Endpoints
# ============================================================================

@darkweb_bp.route("/monitor", methods=["POST"])
@require_api_key
def add_monitoring_rule():
    """
    Add a keyword monitoring rule

    Request Body:
        {
            "name": "My Company Mentions",
            "keywords": ["my company", "mycompany.com"],
            "category": "organization",  // organization, brand, executive, product, custom
            "regex_patterns": ["mycompany\\s+breach"],  // optional
            "severity_boost": 1,  // 0-2, adds to base severity
            "notify_webhook": "https://hooks.slack.com/...",  // optional
            "notify_emails": ["security@example.com"]  // optional
        }

    Returns:
        Created rule ID
    """
    try:
        data = request.get_json()

        if not data:
            return api_response(error="Request body required", status=400)

        if "name" not in data or "keywords" not in data:
            return api_response(error="Name and keywords required", status=400)

        keywords = data["keywords"]
        if not isinstance(keywords, list) or len(keywords) == 0:
            return api_response(error="Keywords must be a non-empty list", status=400)

        # Parse category
        category_str = data.get("category", "custom").lower()
        try:
            category = MonitoringCategory(category_str)
        except ValueError:
            category = MonitoringCategory.CUSTOM

        monitor = get_keyword_monitor()
        rule_id = monitor.create_rule(
            name=data["name"],
            keywords=keywords,
            category=category,
            regex_patterns=data.get("regex_patterns", []),
            severity_boost=min(int(data.get("severity_boost", 0)), 2),
            notify_emails=data.get("notify_emails", []),
            notify_webhooks=[data["notify_webhook"]] if data.get("notify_webhook") else []
        )

        logger.info(f"[API] Created monitoring rule: {data['name']} ({rule_id})")

        return api_response(data={
            "rule_id": rule_id,
            "name": data["name"],
            "keywords_count": len(keywords)
        })

    except Exception as e:
        logger.error(f"[API] Add monitoring rule error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/monitor/organization", methods=["POST"])
@require_api_key
def add_organization_monitoring():
    """
    Add comprehensive organization monitoring (convenience endpoint)

    Request Body:
        {
            "organization": "Acme Corp",
            "domains": ["acme.com", "acmecorp.com"],
            "executives": ["John Smith", "Jane Doe"],
            "products": ["AcmeProduct", "AcmeService"],
            "notify_webhook": "https://hooks.slack.com/..."
        }

    Returns:
        List of created rule IDs
    """
    try:
        data = request.get_json()

        if not data or "organization" not in data or "domains" not in data:
            return api_response(error="Organization name and domains required", status=400)

        rule_ids = create_organization_monitor(
            org_name=data["organization"],
            domains=data["domains"],
            executives=data.get("executives"),
            products=data.get("products"),
            notify_webhook=data.get("notify_webhook")
        )

        return api_response(data={
            "rule_ids": rule_ids,
            "rules_created": len(rule_ids),
            "organization": data["organization"]
        })

    except Exception as e:
        logger.error(f"[API] Add organization monitoring error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/monitor/rules", methods=["GET"])
@require_api_key
def list_monitoring_rules():
    """
    List all monitoring rules

    Query Parameters:
        - category: Filter by category

    Returns:
        List of monitoring rules
    """
    try:
        category_str = request.args.get("category")
        category = None
        if category_str:
            try:
                category = MonitoringCategory(category_str.lower())
            except ValueError:
                pass

        monitor = get_keyword_monitor()
        rules = monitor.list_rules(category=category)

        response_data = [serialize_dataclass(rule) for rule in rules]

        return api_response(data={
            "rules": response_data,
            "count": len(response_data)
        })

    except Exception as e:
        logger.error(f"[API] List rules error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/monitor/rules/<rule_id>", methods=["DELETE"])
@require_api_key
def delete_monitoring_rule(rule_id: str):
    """Delete a monitoring rule"""
    try:
        monitor = get_keyword_monitor()
        success = monitor.remove_rule(rule_id)

        if success:
            return api_response(data={"deleted": True, "rule_id": rule_id})
        else:
            return api_response(error="Rule not found", status=404)

    except Exception as e:
        logger.error(f"[API] Delete rule error: {e}")
        return api_response(error="Internal server error", status=500)


# ============================================================================
# Alerts Endpoints
# ============================================================================

@darkweb_bp.route("/alerts", methods=["GET"])
@require_api_key
def get_alerts():
    """
    Get monitoring alerts

    Query Parameters:
        - severity: Filter by severity (critical, high, medium, low, info)
        - category: Filter by category
        - source: Filter by source
        - acknowledged: Filter by acknowledgment (true/false)
        - limit: Maximum results (default 100)
        - offset: Pagination offset

    Returns:
        List of alerts
    """
    try:
        severity_str = request.args.get("severity")
        severity = None
        if severity_str:
            try:
                severity = AlertSeverity(severity_str.lower())
            except ValueError:
                pass

        category_str = request.args.get("category")
        category = None
        if category_str:
            try:
                category = MonitoringCategory(category_str.lower())
            except ValueError:
                pass

        source_str = request.args.get("source")
        source = None
        if source_str:
            try:
                source = AlertSource(source_str.lower())
            except ValueError:
                pass

        acknowledged = None
        ack_str = request.args.get("acknowledged")
        if ack_str is not None:
            acknowledged = ack_str.lower() == "true"

        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))

        monitor = get_keyword_monitor()
        alerts = monitor.get_alerts(
            severity=severity,
            category=category,
            source=source,
            acknowledged=acknowledged,
            limit=limit,
            offset=offset
        )

        response_data = [serialize_dataclass(alert) for alert in alerts]

        return api_response(data={
            "alerts": response_data,
            "count": len(response_data),
            "offset": offset,
            "limit": limit
        })

    except Exception as e:
        logger.error(f"[API] Get alerts error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/alerts/<alert_id>", methods=["GET"])
@require_api_key
def get_alert(alert_id: str):
    """Get a specific alert"""
    try:
        monitor = get_keyword_monitor()
        alert = monitor.get_alert(alert_id)

        if alert:
            return api_response(data=serialize_dataclass(alert))
        else:
            return api_response(error="Alert not found", status=404)

    except Exception as e:
        logger.error(f"[API] Get alert error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/alerts/<alert_id>/acknowledge", methods=["POST"])
@require_api_key
def acknowledge_alert(alert_id: str):
    """
    Acknowledge an alert

    Request Body (optional):
        {
            "acknowledged_by": "user@example.com"
        }
    """
    try:
        data = request.get_json() or {}
        acknowledged_by = data.get("acknowledged_by")

        monitor = get_keyword_monitor()
        success = monitor.acknowledge_alert(alert_id, acknowledged_by=acknowledged_by)

        if success:
            return api_response(data={"acknowledged": True, "alert_id": alert_id})
        else:
            return api_response(error="Alert not found", status=404)

    except Exception as e:
        logger.error(f"[API] Acknowledge alert error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/alerts/<alert_id>/false-positive", methods=["POST"])
@require_api_key
def mark_false_positive(alert_id: str):
    """Mark an alert as false positive"""
    try:
        monitor = get_keyword_monitor()
        success = monitor.mark_false_positive(alert_id)

        if success:
            return api_response(data={"marked_false_positive": True, "alert_id": alert_id})
        else:
            return api_response(error="Alert not found", status=404)

    except Exception as e:
        logger.error(f"[API] Mark false positive error: {e}")
        return api_response(error="Internal server error", status=500)


# ============================================================================
# Paste Site Endpoints
# ============================================================================

@darkweb_bp.route("/pastes/search", methods=["POST"])
@require_api_key
def search_pastes():
    """
    Search paste sites for specific content

    Request Body:
        {
            "query": "search term",
            "keywords": ["keyword1", "keyword2"]  // Add to permanent monitoring
        }

    Returns:
        Search results from paste sites
    """
    try:
        data = request.get_json()

        if not data or ("query" not in data and "keywords" not in data):
            return api_response(error="Query or keywords required", status=400)

        monitor = get_paste_monitor()

        # Add keywords for monitoring
        if "keywords" in data:
            monitor.add_keywords(data["keywords"])

        # Search if query provided
        results = []
        if "query" in data:
            results = monitor.search_all_sites(data["query"])

        response_data = [serialize_dataclass(r) for r in results]

        return api_response(data={
            "results": response_data,
            "count": len(response_data),
            "query": data.get("query"),
            "keywords_added": data.get("keywords", [])
        })

    except Exception as e:
        logger.error(f"[API] Search pastes error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/pastes/recent", methods=["GET"])
@require_api_key
def get_recent_pastes():
    """
    Get recent paste monitoring results

    Query Parameters:
        - min_confidence: Minimum confidence score (0.0-1.0)
        - limit: Maximum results

    Returns:
        Recent paste findings
    """
    try:
        min_confidence = float(request.args.get("min_confidence", 0.0))
        limit = int(request.args.get("limit", 100))

        monitor = get_paste_monitor()
        results = monitor.get_recent_results(
            limit=limit,
            min_confidence=min_confidence
        )

        response_data = [serialize_dataclass(r) for r in results]

        return api_response(data={
            "results": response_data,
            "count": len(response_data)
        })

    except Exception as e:
        logger.error(f"[API] Recent pastes error: {e}")
        return api_response(error="Internal server error", status=500)


# ============================================================================
# Tor Endpoints
# ============================================================================

@darkweb_bp.route("/tor/status", methods=["GET"])
@require_api_key
def get_tor_status():
    """
    Get Tor connection status

    Returns:
        Connection status, current exit IP, circuit info
    """
    try:
        tor = get_tor_client()
        status = tor.get_status()

        return api_response(data=status)

    except Exception as e:
        logger.error(f"[API] Tor status error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/tor/health", methods=["GET"])
@require_api_key
def get_tor_health():
    """Get Tor connection health check"""
    try:
        tor = get_tor_client()
        health = tor.check_health()

        return api_response(data=health)

    except Exception as e:
        logger.error(f"[API] Tor health error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/tor/connect", methods=["POST"])
@require_api_key
def connect_tor():
    """Connect to Tor network"""
    try:
        tor = get_tor_client()
        success = tor.connect()

        return api_response(data={
            "connected": success,
            "status": tor.status.value
        })

    except Exception as e:
        logger.error(f"[API] Tor connect error: {e}")
        return api_response(error="Internal server error", status=500)


@darkweb_bp.route("/tor/rotate-circuit", methods=["POST"])
@require_api_key
def rotate_tor_circuit():
    """Request new Tor circuit"""
    try:
        tor = get_tor_client()
        success = tor.rotate_circuit()

        return api_response(data={
            "rotated": success,
            "new_ip": tor.get_current_ip() if success else None
        })

    except Exception as e:
        logger.error(f"[API] Tor rotate circuit error: {e}")
        return api_response(error="Internal server error", status=500)


# ============================================================================
# Statistics Endpoint
# ============================================================================

@darkweb_bp.route("/stats", methods=["GET"])
@require_api_key
def get_statistics():
    """
    Get overall dark web intelligence statistics

    Returns:
        Statistics from all subsystems
    """
    try:
        stats = {
            "breach_checker": get_breach_checker().get_statistics(),
            "threat_feeds": get_threat_aggregator().get_statistics(),
            "keyword_monitor": get_keyword_monitor().get_statistics(),
            "paste_monitor": get_paste_monitor().get_statistics()
        }

        return api_response(data=stats)

    except Exception as e:
        logger.error(f"[API] Statistics error: {e}")
        return api_response(error="Internal server error", status=500)


# ============================================================================
# Blueprint Registration Helper
# ============================================================================

def register_darkweb_routes(app):
    """Register darkweb blueprint with Flask app"""
    app.register_blueprint(darkweb_bp)
    logger.info("[DARKWEB-API] Routes registered at /api/v5/darkweb/")


# ============================================================================
# Standalone Server (for testing)
# ============================================================================

def create_standalone_app():
    """Create standalone Flask app for testing"""
    from flask import Flask

    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    register_darkweb_routes(app)

    # Health check endpoint
    @app.route("/health")
    def health():
        return jsonify({"status": "healthy", "module": "darkweb_intel"})

    return app


if __name__ == "__main__":
    # Run standalone server for testing
    import os
    app = create_standalone_app()
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    port = int(os.environ.get('DARKWEB_PORT', '5050'))
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
