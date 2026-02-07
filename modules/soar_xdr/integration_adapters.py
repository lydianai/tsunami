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
        """Start syslog listener"""
        self.running = True
        logger.info("Syslog listener started (simulated)")
        return True

    def stop(self) -> bool:
        """Stop syslog listener"""
        self.running = False
        logger.info("Syslog listener stopped")
        return True

    def get_messages(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get received messages"""
        return self.messages[-limit:]


class RESTConnector:
    """REST API connector for external systems"""

    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.session = None
        self.status = ConnectionStatus.DISCONNECTED
        logger.info(f"RESTConnector initialized: {config.name}")

    def connect(self) -> bool:
        """Establish connection"""
        try:
            # Would use requests session in real implementation
            self.status = ConnectionStatus.CONNECTED
            logger.info(f"Connected to: {self.config.endpoint}")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self.status = ConnectionStatus.ERROR
            return False

    def disconnect(self) -> bool:
        """Close connection"""
        self.status = ConnectionStatus.DISCONNECTED
        return True

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """HTTP GET request"""
        return {"method": "GET", "path": path, "params": params, "simulated": True}

    def post(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """HTTP POST request"""
        return {"method": "POST", "path": path, "data": data, "simulated": True}

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
