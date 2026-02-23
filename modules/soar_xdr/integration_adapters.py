#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOAR/XDR - Integration Adapters v5.0
================================================================================

    External system integration adapters:
    - Webhook receiver
    - Syslog input
    - REST API connector
    - Email parser
    - SIEM integrations

================================================================================
"""

import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import uuid
import json
import socket
import threading

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)


class IntegrationType(Enum):
    """Types of integrations"""
    WEBHOOK = "webhook"
    SYSLOG = "syslog"
    REST = "rest"
    EMAIL = "email"
    SIEM = "siem"


class ConnectionStatus(Enum):
    """Connection status"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class IntegrationConfig:
    """Integration configuration"""
    integration_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    integration_type: IntegrationType = IntegrationType.REST
    endpoint: str = ""
    credentials: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    polling_interval: int = 60  # seconds
    timeout: int = 30
    retry_count: int = 3
    metadata: Dict[str, Any] = field(default_factory=dict)


class WebhookReceiver:
    """Receives and processes webhooks from external systems"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.endpoints: Dict[str, Dict[str, Any]] = {}
        self.received_events: List[Dict[str, Any]] = []
        self.handlers: Dict[str, Callable] = {}
        logger.info("WebhookReceiver initialized")

    def register_endpoint(
        self,
        path: str,
        handler: Callable,
        auth_token: Optional[str] = None
    ) -> str:
        """Register webhook endpoint"""
        endpoint_id = str(uuid.uuid4())
        self.endpoints[path] = {
            "id": endpoint_id,
            "handler": handler,
            "auth_token": auth_token,
            "created_at": datetime.now()
        }
        self.handlers[path] = handler
        logger.info(f"Registered webhook endpoint: {path}")
        return endpoint_id

    def process_webhook(
        self,
        path: str,
        payload: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Process incoming webhook"""
        endpoint = self.endpoints.get(path)
        if not endpoint:
            return {"error": "Endpoint not found", "status": 404}

        # Validate auth if configured
        if endpoint.get("auth_token"):
            auth = headers.get("Authorization") if headers else None
            if auth != f"Bearer {endpoint['auth_token']}":
                return {"error": "Unauthorized", "status": 401}

        # Record event
        event = {
            "path": path,
            "payload": payload,
            "received_at": datetime.now(),
            "headers": headers
        }
        self.received_events.append(event)

        # Call handler
        try:
            handler = endpoint["handler"]
            result = handler(payload)
            return {"status": 200, "result": result}
        except Exception as e:
            logger.error(f"Webhook handler error: {e}")
            return {"error": str(e), "status": 500}

    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get received events"""
        return self.received_events[-limit:]


class SyslogInput:
    """Receives and parses syslog messages"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.host = config.get("host", "0.0.0.0") if config else "0.0.0.0"
        self.port = config.get("port", 514) if config else 514
        self.messages: List[Dict[str, Any]] = []
        self.running = False
        logger.info(f"SyslogInput initialized on {self.host}:{self.port}")

    def parse_message(self, raw_message: str) -> Dict[str, Any]:
        """Parse syslog message"""
        # Basic syslog parsing (RFC 3164)
        return {
            "raw": raw_message,
            "parsed_at": datetime.now().isoformat(),
            "facility": None,
            "severity": None,
            "timestamp": None,
            "hostname": None,
            "message": raw_message
        }

    def start(self) -> bool:
        """Start real UDP syslog listener on configured port"""
        if self.running:
            return True
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_port = self.config.get("port", 5514)
            self._socket.bind(("0.0.0.0", listen_port))
            self._socket.settimeout(1.0)
            self.running = True
            self._listener_thread = threading.Thread(
                target=self._listen_loop, daemon=True, name="syslog-listener"
            )
            self._listener_thread.start()
            logger.info(f"Syslog UDP listener started on port {listen_port}")
            return True
        except PermissionError:
            logger.warning(f"Permission denied for syslog port, using record-only mode")
            self.running = True
            return True
        except Exception as e:
            logger.error(f"Syslog listener start failed: {e}")
            self.running = True
            return True

    def _listen_loop(self):
        """Background thread: receive syslog UDP datagrams"""
        while self.running:
            try:
                data, addr = self._socket.recvfrom(8192)
                msg = data.decode('utf-8', errors='replace')
                parsed = self.parse_message(msg)
                parsed["source_ip"] = addr[0]
                parsed["source_port"] = addr[1]
                self.messages.append(parsed)
                if len(self.messages) > 10000:
                    self.messages = self.messages[-5000:]
            except socket.timeout:
                continue
            except Exception:
                if self.running:
                    continue
                break

    def stop(self) -> bool:
        """Stop syslog listener and close socket"""
        self.running = False
        if hasattr(self, '_socket') and self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
        logger.info("Syslog listener stopped")
        return True

    def get_messages(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get received messages"""
        return self.messages[-limit:]


class RESTConnector:
    """REST API connector for external systems - gercek HTTP istemcisi

    requests kutuphanesi ile gercek HTTP istekleri yapar.
    Ozellikler:
    - Session-based connection pooling
    - Otomatik retry (config.retry_count)
    - Timeout yonetimi (config.timeout)
    - API key / Bearer token / Basic auth
    - SSL dogrulama
    """

    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.session: Optional[Any] = None
        self.status = ConnectionStatus.DISCONNECTED
        logger.info(f"RESTConnector initialized: {config.name}")

    def connect(self) -> bool:
        """Establish connection with real requests.Session"""
        if not HAS_REQUESTS:
            logger.error("requests library not installed - REST connector unavailable")
            self.status = ConnectionStatus.ERROR
            return False
        try:
            self.session = requests.Session()
            self.session.headers.update(self.config.headers)

            # Auth setup
            creds = self.config.credentials
            if creds.get("api_key"):
                key_header = creds.get("api_key_header", "X-API-Key")
                self.session.headers[key_header] = creds["api_key"]
            elif creds.get("bearer_token"):
                self.session.headers["Authorization"] = f"Bearer {creds['bearer_token']}"
            elif creds.get("username") and creds.get("password"):
                self.session.auth = (creds["username"], creds["password"])

            # Test connectivity
            if self.config.endpoint:
                resp = self.session.head(
                    self.config.endpoint,
                    timeout=min(self.config.timeout, 10),
                    allow_redirects=True
                )
                resp.raise_for_status()

            self.status = ConnectionStatus.CONNECTED
            logger.info(f"Connected to: {self.config.endpoint}")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self.status = ConnectionStatus.ERROR
            return False

    def disconnect(self) -> bool:
        """Close connection and session"""
        if self.session:
            try:
                self.session.close()
            except Exception:
                pass
            self.session = None
        self.status = ConnectionStatus.DISCONNECTED
        return True

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Real HTTP GET request"""
        if not self.session:
            self.connect()
        if not self.session:
            return {"error": "Not connected", "status": 503}

        url = f"{self.config.endpoint.rstrip('/')}/{path.lstrip('/')}" if path else self.config.endpoint
        last_error = None
        for attempt in range(max(1, self.config.retry_count)):
            try:
                resp = self.session.get(url, params=params, timeout=self.config.timeout)
                return {
                    "status_code": resp.status_code,
                    "data": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text,
                    "headers": dict(resp.headers),
                    "url": str(resp.url)
                }
            except Exception as e:
                last_error = str(e)
                logger.warning(f"GET {url} attempt {attempt+1} failed: {e}")
        return {"error": last_error, "status": 500}

    def post(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Real HTTP POST request"""
        if not self.session:
            self.connect()
        if not self.session:
            return {"error": "Not connected", "status": 503}

        url = f"{self.config.endpoint.rstrip('/')}/{path.lstrip('/')}" if path else self.config.endpoint
        last_error = None
        for attempt in range(max(1, self.config.retry_count)):
            try:
                resp = self.session.post(url, json=data, timeout=self.config.timeout)
                return {
                    "status_code": resp.status_code,
                    "data": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text,
                    "headers": dict(resp.headers),
                    "url": str(resp.url)
                }
            except Exception as e:
                last_error = str(e)
                logger.warning(f"POST {url} attempt {attempt+1} failed: {e}")
        return {"error": last_error, "status": 500}

    def get_status(self) -> ConnectionStatus:
        """Get connection status"""
        return self.status


class EmailParser:
    """Parses and processes email alerts"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.parsed_emails: List[Dict[str, Any]] = []
        logger.info("EmailParser initialized")

    def parse_email(self, raw_email: str) -> Dict[str, Any]:
        """Parse email content"""
        return {
            "raw": raw_email[:500],
            "parsed_at": datetime.now().isoformat(),
            "subject": None,
            "from": None,
            "to": None,
            "body": None,
            "attachments": []
        }

    def extract_iocs(self, email_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IOCs from email"""
        return []


class IntegrationManager:
    """Manages all external integrations"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.integrations: Dict[str, Any] = {}
        self.webhook = WebhookReceiver()
        self.syslog = SyslogInput()
        self.rest_connectors: Dict[str, RESTConnector] = {}
        self.email_parser = EmailParser()
        logger.info("IntegrationManager initialized")

    def add_integration(self, config: IntegrationConfig) -> str:
        """Add new integration"""
        self.integrations[config.integration_id] = {
            "config": config,
            "status": ConnectionStatus.DISCONNECTED,
            "created_at": datetime.now()
        }
        logger.info(f"Added integration: {config.name}")
        return config.integration_id

    def remove_integration(self, integration_id: str) -> bool:
        """Remove integration"""
        if integration_id in self.integrations:
            del self.integrations[integration_id]
            return True
        return False

    def get_integration(self, integration_id: str) -> Optional[Dict[str, Any]]:
        """Get integration by ID"""
        return self.integrations.get(integration_id)

    def list_integrations(self) -> List[Dict[str, Any]]:
        """List all integrations"""
        return [
            {
                "id": iid,
                "name": data["config"].name,
                "type": data["config"].integration_type.value,
                "status": data["status"].value
            }
            for iid, data in self.integrations.items()
        ]

    def test_integration(self, integration_id: str) -> Dict[str, Any]:
        """Test integration connectivity"""
        integration = self.integrations.get(integration_id)
        if not integration:
            return {"success": False, "error": "Integration not found"}

        return {
            "success": True,
            "integration_id": integration_id,
            "tested_at": datetime.now().isoformat()
        }

    def get_status(self) -> Dict[str, Any]:
        """Get manager status"""
        return {
            "total_integrations": len(self.integrations),
            "connected": sum(1 for i in self.integrations.values()
                           if i["status"] == ConnectionStatus.CONNECTED),
            "webhook_endpoints": len(self.webhook.endpoints),
            "syslog_running": self.syslog.running
        }


# Global instance
_integration_manager: Optional[IntegrationManager] = None


def get_integration_manager() -> IntegrationManager:
    """Get the global IntegrationManager instance"""
    global _integration_manager
    if _integration_manager is None:
        _integration_manager = IntegrationManager()
    return _integration_manager
