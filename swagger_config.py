"""
TSUNAMI v5.0 - Swagger/OpenAPI Configuration
=============================================

Flasgger ile API dokümantasyonu.
"""

SWAGGER_CONFIG = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/api/docs/"
}

SWAGGER_TEMPLATE = {
    "swagger": "2.0",
    "info": {
        "title": "TSUNAMI API",
        "description": """
# TSUNAMI v5.0 - Global-Scale Cyber Intelligence Platform

## Overview
TSUNAMI, gelişmiş OSINT (Open Source Intelligence) ve SIGINT (Signal Intelligence)
yetenekleri sunan kapsamlı bir siber istihbarat platformudur.

## Authentication
API çağrıları için session-based authentication kullanılmaktadır.
Öncelikle `/auth/login` endpoint'i ile giriş yapmanız gerekmektedir.

## Rate Limiting
- Genel API: 100 istek/dakika
- OSINT sorguları: 30 istek/dakika
- SIGINT taramaları: 10 istek/dakika

## Error Handling
Tüm hatalar standart JSON formatında döner:
```json
{
  "success": false,
  "error": "Hata mesajı",
  "status_code": 400
}
```

## Versioning
API versiyonlaması URL path ile yapılır:
- v1: `/api/v1/*` (current)
- v2: `/api/v2/*` (beta)
        """,
        "termsOfService": "/terms",
        "contact": {
            "name": "TSUNAMI Support",
            "email": "support@tsunami.local"
        },
        "license": {
            "name": "Proprietary"
        },
        "version": "5.0.0"
    },
    "host": "localhost:8080",
    "basePath": "/",
    "schemes": [
        "https",
        "http"
    ],
    "securityDefinitions": {
        "session": {
            "type": "apiKey",
            "name": "session",
            "in": "cookie",
            "description": "Session-based authentication. Login first via /auth/login"
        },
        "api_key": {
            "type": "apiKey",
            "name": "X-API-Key",
            "in": "header",
            "description": "API key authentication for automated access"
        }
    },
    "tags": [
        {
            "name": "Authentication",
            "description": "Kimlik doğrulama işlemleri"
        },
        {
            "name": "OSINT",
            "description": "Open Source Intelligence - IP, domain, email sorguları"
        },
        {
            "name": "SIGINT",
            "description": "Signal Intelligence - WiFi, Bluetooth, Cell taramaları"
        },
        {
            "name": "System",
            "description": "Sistem durumu ve sağlık kontrolleri"
        },
        {
            "name": "Reports",
            "description": "Raporlama ve veri dışa aktarımı"
        },
        {
            "name": "Maps",
            "description": "Harita ve konum servisleri"
        },
        {
            "name": "BEYIN",
            "description": "AI/ML tabanlı tehdit analizi"
        }
    ],
    "definitions": {
        "Error": {
            "type": "object",
            "properties": {
                "success": {
                    "type": "boolean",
                    "example": False
                },
                "error": {
                    "type": "string",
                    "example": "Hata mesajı"
                },
                "status_code": {
                    "type": "integer",
                    "example": 400
                }
            }
        },
        "Success": {
            "type": "object",
            "properties": {
                "success": {
                    "type": "boolean",
                    "example": True
                },
                "data": {
                    "type": "object"
                }
            }
        },
        "Device": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "example": "wifi-001"
                },
                "type": {
                    "type": "string",
                    "enum": ["wifi", "bluetooth", "cell", "iot"]
                },
                "name": {
                    "type": "string",
                    "example": "NETWORK-5G"
                },
                "mac": {
                    "type": "string",
                    "example": "AA:BB:CC:DD:EE:FF"
                },
                "signal": {
                    "type": "integer",
                    "example": -45
                },
                "risk_score": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100
                },
                "first_seen": {
                    "type": "string",
                    "format": "date-time"
                },
                "last_seen": {
                    "type": "string",
                    "format": "date-time"
                }
            }
        },
        "Threat": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "string"
                },
                "type": {
                    "type": "string",
                    "example": "rogue_ap"
                },
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"]
                },
                "description": {
                    "type": "string"
                },
                "detected_at": {
                    "type": "string",
                    "format": "date-time"
                },
                "status": {
                    "type": "string",
                    "enum": ["active", "resolved", "ignored"]
                }
            }
        },
        "OSINTResult": {
            "type": "object",
            "properties": {
                "success": {
                    "type": "boolean"
                },
                "target": {
                    "type": "string"
                },
                "target_type": {
                    "type": "string",
                    "enum": ["ip", "domain", "email", "phone", "username"]
                },
                "data": {
                    "type": "object"
                },
                "sources": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "timestamp": {
                    "type": "string",
                    "format": "date-time"
                }
            }
        }
    }
}


def init_swagger(app):
    """Flask app'e Swagger ekle"""
    try:
        from flasgger import Swagger
        swagger = Swagger(app, config=SWAGGER_CONFIG, template=SWAGGER_TEMPLATE)
        return swagger
    except ImportError:
        print("[WARNING] flasgger not installed. API docs disabled.")
        return None


__all__ = ['SWAGGER_CONFIG', 'SWAGGER_TEMPLATE', 'init_swagger']
