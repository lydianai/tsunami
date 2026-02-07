#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI API Documentation v1.0
==============================

OpenAPI/Swagger API dokümantasyonu.
- OpenAPI 3.0 spec
- Swagger UI entegrasyonu
- ReDoc entegrasyonu
- Endpoint listesi

KULLANIM:
    from dalga_api_docs import setup_api_docs, get_openapi_spec

    setup_api_docs(app)  # /api/docs, /api/openapi.json
"""

import json
from typing import Dict, Any, List
from flask import Blueprint, jsonify, render_template_string

# OpenAPI Specification
OPENAPI_SPEC: Dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {
        "title": "TSUNAMI API",
        "description": """
# TSUNAMI Siber İstihbarat ve Güvenlik Platformu API

## Genel Bakış
TSUNAMI, kapsamlı siber güvenlik yetenekleri sunan bir istihbarat platformudur.

## Authentication
API'ye erişim için oturum açmanız gerekir. Login endpoint'i ile session token alın.

## Rate Limiting
- 100 istek/dakika (authenticated)
- 10 istek/dakika (unauthenticated)

## Hata Kodları
| Kod | Açıklama |
|-----|----------|
| 400 | Bad Request - Geçersiz parametre |
| 401 | Unauthorized - Oturum gerekli |
| 403 | Forbidden - Yetki yetersiz |
| 429 | Too Many Requests - Rate limit aşıldı |
| 500 | Internal Server Error |
        """,
        "version": "5.0.0",
        "contact": {
            "name": "TSUNAMI Support",
            "url": "https://github.com/tsunami-security"
        },
        "license": {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT"
        }
    },
    "servers": [
        {
            "url": "http://localhost:8080",
            "description": "Development server"
        }
    ],
    "tags": [
        {"name": "Auth", "description": "Kimlik doğrulama işlemleri"},
        {"name": "System", "description": "Sistem durumu ve sağlık kontrolleri"},
        {"name": "WiFi", "description": "WiFi ağ tarama ve analiz"},
        {"name": "Bluetooth", "description": "Bluetooth cihaz tespiti"},
        {"name": "Network", "description": "Ağ tarama ve zafiyet analizi"},
        {"name": "OSINT", "description": "Açık kaynak istihbaratı"},
        {"name": "Siber", "description": "Siber Komuta Merkezi"},
        {"name": "Security", "description": "Güvenlik ayarları ve 2FA"},
        {"name": "Metrics", "description": "Prometheus metrikleri"},
    ],
    "paths": {
        # ==================== AUTH ====================
        "/login": {
            "post": {
                "tags": ["Auth"],
                "summary": "Kullanıcı girişi",
                "description": "Kullanıcı adı ve şifre ile oturum açın",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/LoginRequest"}
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Başarılı giriş",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LoginResponse"}
                            }
                        }
                    },
                    "401": {"description": "Geçersiz kimlik bilgileri"},
                    "429": {"description": "Çok fazla başarısız deneme"}
                }
            }
        },
        "/logout": {
            "get": {
                "tags": ["Auth"],
                "summary": "Çıkış yap",
                "responses": {
                    "302": {"description": "Login sayfasına yönlendirilir"}
                }
            }
        },

        # ==================== SYSTEM ====================
        "/health": {
            "get": {
                "tags": ["System"],
                "summary": "Sistem sağlık durumu",
                "responses": {
                    "200": {
                        "description": "Sistem sağlıklı",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/HealthResponse"}
                            }
                        }
                    }
                }
            }
        },
        "/health/live": {
            "get": {
                "tags": ["System"],
                "summary": "Liveness probe",
                "responses": {
                    "200": {"description": "Uygulama çalışıyor"}
                }
            }
        },
        "/health/ready": {
            "get": {
                "tags": ["System"],
                "summary": "Readiness probe",
                "responses": {
                    "200": {"description": "Uygulama hazır"}
                }
            }
        },
        "/api/durum": {
            "get": {
                "tags": ["System"],
                "summary": "Detaylı sistem durumu",
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {
                        "description": "Sistem durumu",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/SystemStatus"}
                            }
                        }
                    }
                }
            }
        },

        # ==================== WIFI ====================
        "/api/wifi/tara": {
            "post": {
                "tags": ["WiFi"],
                "summary": "WiFi ağlarını tara",
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {
                        "description": "Tarama sonuçları",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/WiFiScanResponse"}
                            }
                        }
                    }
                }
            }
        },
        "/api/wifi/liste": {
            "get": {
                "tags": ["WiFi"],
                "summary": "Kaydedilmiş WiFi ağları",
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {
                        "description": "WiFi listesi",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/WiFiNetwork"}
                                }
                            }
                        }
                    }
                }
            }
        },

        # ==================== BLUETOOTH ====================
        "/api/bluetooth/tara": {
            "post": {
                "tags": ["Bluetooth"],
                "summary": "Bluetooth cihazlarını tara",
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {
                        "description": "Tarama sonuçları",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/BluetoothScanResponse"}
                            }
                        }
                    }
                }
            }
        },
        "/api/bluetooth/liste": {
            "get": {
                "tags": ["Bluetooth"],
                "summary": "Kaydedilmiş Bluetooth cihazları",
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {"description": "Bluetooth listesi"}
                }
            }
        },

        # ==================== NETWORK ====================
        "/api/port/tara": {
            "post": {
                "tags": ["Network"],
                "summary": "Port taraması",
                "security": [{"sessionAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/PortScanRequest"}
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Port tarama sonuçları",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/PortScanResponse"}
                            }
                        }
                    },
                    "400": {"description": "Geçersiz hedef"}
                }
            }
        },
        "/api/zafiyet/tara": {
            "post": {
                "tags": ["Network"],
                "summary": "Zafiyet taraması",
                "security": [{"sessionAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/VulnScanRequest"}
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Zafiyet sonuçları"}
                }
            }
        },

        # ==================== OSINT ====================
        "/api/osint/ip/<ip>": {
            "get": {
                "tags": ["OSINT"],
                "summary": "IP adres istihbaratı",
                "security": [{"sessionAuth": []}],
                "parameters": [
                    {
                        "name": "ip",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "ipv4"}
                    }
                ],
                "responses": {
                    "200": {"description": "IP bilgileri"}
                }
            }
        },
        "/api/osint/domain/<domain>": {
            "get": {
                "tags": ["OSINT"],
                "summary": "Domain istihbaratı",
                "security": [{"sessionAuth": []}],
                "parameters": [
                    {
                        "name": "domain",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    }
                ],
                "responses": {
                    "200": {"description": "Domain bilgileri"}
                }
            }
        },
        "/api/konum/ara": {
            "post": {
                "tags": ["OSINT"],
                "summary": "Konum bazlı arama",
                "security": [{"sessionAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/LocationSearchRequest"}
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Konum verileri"}
                }
            }
        },

        # ==================== SIBER ====================
        "/api/siber/durum": {
            "get": {
                "tags": ["Siber"],
                "summary": "Siber Komuta durumu",
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {
                        "description": "Siber modül durumu",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/SiberStatus"}
                            }
                        }
                    }
                }
            }
        },
        "/api/siber/ajanlar": {
            "get": {
                "tags": ["Siber"],
                "summary": "Pentagon ajanları listesi",
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {"description": "22 Pentagon ajan bilgisi"}
                }
            }
        },

        # ==================== SECURITY ====================
        "/api/guvenlik/durum": {
            "get": {
                "tags": ["Security"],
                "summary": "Güvenlik modülleri durumu",
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {
                        "description": "Güvenlik durumu",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/SecurityStatus"}
                            }
                        }
                    }
                }
            }
        },
        "/api/guvenlik/2fa/setup": {
            "post": {
                "tags": ["Security"],
                "summary": "2FA kurulumu başlat",
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {
                        "description": "2FA setup bilgileri",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TwoFactorSetup"}
                            }
                        }
                    }
                }
            }
        },
        "/api/guvenlik/2fa/verify": {
            "post": {
                "tags": ["Security"],
                "summary": "2FA kodunu doğrula",
                "security": [{"sessionAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/TwoFactorVerify"}
                        }
                    }
                },
                "responses": {
                    "200": {"description": "2FA aktifleştirildi"},
                    "401": {"description": "Geçersiz kod"}
                }
            }
        },
        "/api/csrf-token": {
            "get": {
                "tags": ["Security"],
                "summary": "CSRF token al",
                "responses": {
                    "200": {
                        "description": "CSRF token",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "csrf_token": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        # ==================== METRICS ====================
        "/metrics": {
            "get": {
                "tags": ["Metrics"],
                "summary": "Prometheus metrikleri",
                "responses": {
                    "200": {
                        "description": "Prometheus formatında metrikler",
                        "content": {
                            "text/plain": {
                                "schema": {"type": "string"}
                            }
                        }
                    }
                }
            }
        },
        "/metrics/json": {
            "get": {
                "tags": ["Metrics"],
                "summary": "JSON formatında metrikler",
                "responses": {
                    "200": {"description": "Metrikler"}
                }
            }
        },
    },
    "components": {
        "schemas": {
            "LoginRequest": {
                "type": "object",
                "required": ["username", "password"],
                "properties": {
                    "username": {"type": "string", "example": "admin"},
                    "password": {"type": "string", "format": "password"},
                    "totp_code": {"type": "string", "description": "2FA kodu (aktifse)"}
                }
            },
            "LoginResponse": {
                "type": "object",
                "properties": {
                    "basarili": {"type": "boolean"},
                    "yonlendir": {"type": "string", "example": "/panel"}
                }
            },
            "HealthResponse": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "example": "healthy"},
                    "version": {"type": "string", "example": "5.0.0"},
                    "uptime": {"type": "number"},
                    "timestamp": {"type": "string", "format": "date-time"}
                }
            },
            "SystemStatus": {
                "type": "object",
                "properties": {
                    "versiyon": {"type": "string"},
                    "kod_adi": {"type": "string"},
                    "istatistikler": {"type": "object"},
                    "api_durumu": {"type": "object"},
                    "araclar": {"type": "object"}
                }
            },
            "WiFiNetwork": {
                "type": "object",
                "properties": {
                    "ssid": {"type": "string"},
                    "bssid": {"type": "string"},
                    "kanal": {"type": "integer"},
                    "sinyal_dbm": {"type": "integer"},
                    "guvenlik": {"type": "string"},
                    "frekans": {"type": "integer"}
                }
            },
            "WiFiScanResponse": {
                "type": "object",
                "properties": {
                    "basarili": {"type": "boolean"},
                    "sonuc_sayisi": {"type": "integer"},
                    "sonuclar": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/WiFiNetwork"}
                    }
                }
            },
            "BluetoothScanResponse": {
                "type": "object",
                "properties": {
                    "basarili": {"type": "boolean"},
                    "sonuc_sayisi": {"type": "integer"},
                    "sonuclar": {"type": "array", "items": {"type": "object"}}
                }
            },
            "PortScanRequest": {
                "type": "object",
                "required": ["hedef"],
                "properties": {
                    "hedef": {"type": "string", "example": "192.168.1.1"},
                    "portlar": {"type": "string", "example": "1-1000", "default": "1-1000"}
                }
            },
            "PortScanResponse": {
                "type": "object",
                "properties": {
                    "basarili": {"type": "boolean"},
                    "hedef": {"type": "string"},
                    "sonuc_sayisi": {"type": "integer"},
                    "sonuclar": {"type": "array", "items": {"type": "object"}}
                }
            },
            "VulnScanRequest": {
                "type": "object",
                "required": ["hedef"],
                "properties": {
                    "hedef": {"type": "string"}
                }
            },
            "LocationSearchRequest": {
                "type": "object",
                "required": ["enlem", "boylam"],
                "properties": {
                    "enlem": {"type": "number", "minimum": -90, "maximum": 90},
                    "boylam": {"type": "number", "minimum": -180, "maximum": 180}
                }
            },
            "SiberStatus": {
                "type": "object",
                "properties": {
                    "aktif": {"type": "boolean"},
                    "ajanlar": {"type": "integer"},
                    "groq_aktif": {"type": "boolean"},
                    "osint_fusion": {"type": "boolean"}
                }
            },
            "SecurityStatus": {
                "type": "object",
                "properties": {
                    "modules": {
                        "type": "object",
                        "properties": {
                            "secrets_manager": {"type": "boolean"},
                            "input_validation": {"type": "boolean"},
                            "auth_security": {"type": "boolean"},
                            "csrf_protection": {"type": "boolean"},
                            "rate_limiting": {"type": "boolean"},
                            "brute_force_protection": {"type": "boolean"},
                            "totp_2fa": {"type": "boolean"}
                        }
                    },
                    "config": {"type": "object"}
                }
            },
            "TwoFactorSetup": {
                "type": "object",
                "properties": {
                    "basarili": {"type": "boolean"},
                    "secret": {"type": "string"},
                    "qr_uri": {"type": "string"},
                    "qr_image": {"type": "string", "description": "Base64 PNG"}
                }
            },
            "TwoFactorVerify": {
                "type": "object",
                "required": ["secret", "code"],
                "properties": {
                    "secret": {"type": "string"},
                    "code": {"type": "string", "minLength": 6, "maxLength": 6}
                }
            },
            "Error": {
                "type": "object",
                "properties": {
                    "error": {"type": "string"},
                    "code": {"type": "string"},
                    "details": {"type": "object"}
                }
            }
        },
        "securitySchemes": {
            "sessionAuth": {
                "type": "apiKey",
                "in": "cookie",
                "name": "session",
                "description": "Flask session cookie"
            }
        }
    }
}


# Swagger UI HTML Template
SWAGGER_UI_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>TSUNAMI API Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css">
    <style>
        body { margin: 0; padding: 0; }
        .swagger-ui .topbar { display: none; }
        .swagger-ui .info .title { color: #00e5ff; }
        .swagger-ui { background: #0a0e14; }
        .swagger-ui .opblock-tag { color: #00ff88; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            SwaggerUIBundle({
                url: "{{ spec_url }}",
                dom_id: '#swagger-ui',
                presets: [SwaggerUIBundle.presets.apis],
                layout: "BaseLayout",
                deepLinking: true,
                showExtensions: true,
                showCommonExtensions: true
            });
        }
    </script>
</body>
</html>
"""


# ReDoc HTML Template
REDOC_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>TSUNAMI API - ReDoc</title>
    <link href="https://fonts.googleapis.com/css?family=Roboto:300,400,700" rel="stylesheet">
    <style>
        body { margin: 0; padding: 0; }
    </style>
</head>
<body>
    <redoc spec-url="{{ spec_url }}"></redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body>
</html>
"""


def get_openapi_spec() -> Dict[str, Any]:
    """OpenAPI spec'i döndür"""
    return OPENAPI_SPEC


def create_docs_blueprint() -> Blueprint:
    """API dokümantasyonu Blueprint'i oluştur"""
    docs_bp = Blueprint('api_docs', __name__)

    @docs_bp.route('/api/docs')
    def swagger_ui():
        """Swagger UI"""
        return render_template_string(
            SWAGGER_UI_TEMPLATE,
            spec_url='/api/openapi.json'
        )

    @docs_bp.route('/api/redoc')
    def redoc():
        """ReDoc"""
        return render_template_string(
            REDOC_TEMPLATE,
            spec_url='/api/openapi.json'
        )

    @docs_bp.route('/api/openapi.json')
    def openapi_spec():
        """OpenAPI JSON spec"""
        return jsonify(OPENAPI_SPEC)

    @docs_bp.route('/api/openapi.yaml')
    def openapi_yaml():
        """OpenAPI YAML spec"""
        try:
            import yaml
            yaml_content = yaml.dump(OPENAPI_SPEC, allow_unicode=True, default_flow_style=False)
            return yaml_content, 200, {'Content-Type': 'text/yaml; charset=utf-8'}
        except ImportError:
            return jsonify({'error': 'PyYAML not installed'}), 500

    @docs_bp.route('/api/endpoints')
    def list_endpoints():
        """Tüm endpoint'leri listele"""
        from flask import current_app

        endpoints = []
        for rule in current_app.url_map.iter_rules():
            if rule.endpoint != 'static':
                endpoints.append({
                    'endpoint': rule.endpoint,
                    'methods': list(rule.methods - {'HEAD', 'OPTIONS'}),
                    'path': str(rule)
                })

        # Path'e göre sırala
        endpoints.sort(key=lambda x: x['path'])

        return jsonify({
            'count': len(endpoints),
            'endpoints': endpoints
        })

    return docs_bp


def setup_api_docs(app):
    """
    Flask app'e API dokümantasyonu ekle.

    Kullanım:
        from dalga_api_docs import setup_api_docs
        setup_api_docs(app)

    Endpoint'ler:
        /api/docs       - Swagger UI
        /api/redoc      - ReDoc
        /api/openapi.json - OpenAPI spec (JSON)
        /api/openapi.yaml - OpenAPI spec (YAML)
        /api/endpoints  - Endpoint listesi
    """
    docs_bp = create_docs_blueprint()
    app.register_blueprint(docs_bp)
    print("    [API-DOCS] Swagger UI: /api/docs")
    print("    [API-DOCS] ReDoc: /api/redoc")
    print("    [API-DOCS] OpenAPI: /api/openapi.json")


# CLI Test
if __name__ == '__main__':
    print("=== TSUNAMI OpenAPI Spec ===")
    print(f"Version: {OPENAPI_SPEC['info']['version']}")
    print(f"Paths: {len(OPENAPI_SPEC['paths'])}")
    print(f"Schemas: {len(OPENAPI_SPEC['components']['schemas'])}")

    print("\n=== Endpoints ===")
    for path, methods in OPENAPI_SPEC['paths'].items():
        for method, details in methods.items():
            if method in ['get', 'post', 'put', 'delete', 'patch']:
                print(f"  {method.upper():6} {path}")

    # JSON export
    print("\n=== JSON Export (first 500 chars) ===")
    print(json.dumps(OPENAPI_SPEC, indent=2)[:500] + "...")
