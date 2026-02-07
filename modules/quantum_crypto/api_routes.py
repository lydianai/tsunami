"""
Flask API Routes for Quantum Cryptography Module

Provides RESTful endpoints for post-quantum cryptographic operations:
- Key generation and management
- Encryption and decryption
- Digital signatures
- Audit and compliance reporting
"""

import json
import base64
import secrets
from functools import wraps
from typing import Optional, Dict, Any
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, current_app, g

from .pqc_algorithms import PQCAlgorithms, SecurityLevel
from .secure_channel import SecureChannel, ChannelState
from .key_manager import KeyManager, KeyType, KeyStatus, KeyRotationPolicy
from .message_crypto import MessageCrypto
from .crypto_audit import CryptoAudit, AuditEventType, ComplianceStandard


# Create Blueprint
crypto_bp = Blueprint('crypto', __name__, url_prefix='/api/v5/crypto')

# Global instances (initialized by init_crypto_module)
_pqc: Optional[PQCAlgorithms] = None
_key_manager: Optional[KeyManager] = None
_message_crypto: Optional[MessageCrypto] = None
_secure_channel: Optional[SecureChannel] = None
_crypto_audit: Optional[CryptoAudit] = None


def init_crypto_module(
    storage_path: Optional[str] = None,
    master_key: Optional[bytes] = None,
    security_level: SecurityLevel = SecurityLevel.LEVEL_3,
    use_hybrid: bool = True
):
    """
    Initialize the crypto module with configuration.

    Args:
        storage_path: Path for key and audit storage
        master_key: Master key for encrypted storage
        security_level: Default NIST security level
        use_hybrid: Whether to use hybrid classical+PQC mode
    """
    global _pqc, _key_manager, _message_crypto, _secure_channel, _crypto_audit

    _pqc = PQCAlgorithms(security_level)

    _key_manager = KeyManager(
        storage_path=f"{storage_path}/keys" if storage_path else None,
        master_key=master_key,
        default_security_level=security_level
    )

    _message_crypto = MessageCrypto(
        key_manager=_key_manager,
        security_level=security_level,
        use_hybrid=use_hybrid
    )

    _secure_channel = SecureChannel(
        security_level=security_level,
        use_hybrid=use_hybrid
    )

    _crypto_audit = CryptoAudit(
        storage_path=f"{storage_path}/audit" if storage_path else None
    )


def get_pqc() -> PQCAlgorithms:
    """Get PQC algorithms instance."""
    global _pqc
    if _pqc is None:
        init_crypto_module()
    return _pqc


def get_key_manager() -> KeyManager:
    """Get key manager instance."""
    global _key_manager
    if _key_manager is None:
        init_crypto_module()
    return _key_manager


def get_message_crypto() -> MessageCrypto:
    """Get message crypto instance."""
    global _message_crypto
    if _message_crypto is None:
        init_crypto_module()
    return _message_crypto


def get_secure_channel() -> SecureChannel:
    """Get secure channel instance."""
    global _secure_channel
    if _secure_channel is None:
        init_crypto_module()
    return _secure_channel


def get_crypto_audit() -> CryptoAudit:
    """Get crypto audit instance."""
    global _crypto_audit
    if _crypto_audit is None:
        init_crypto_module()
    return _crypto_audit


def audit_operation(event_type: AuditEventType):
    """Decorator to audit API operations."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            audit = get_crypto_audit()
            start_time = datetime.now(timezone.utc)

            try:
                result = f(*args, **kwargs)

                # Log successful operation
                audit.log_event(
                    event_type=event_type,
                    algorithm=g.get('algorithm'),
                    key_id=g.get('key_id'),
                    security_level=g.get('security_level'),
                    success=True,
                    user_id=request.headers.get('X-User-ID'),
                    source_ip=request.remote_addr,
                    metadata={
                        "endpoint": request.path,
                        "method": request.method,
                        "duration_ms": (datetime.now(timezone.utc) - start_time).total_seconds() * 1000,
                    }
                )
                return result

            except Exception as e:
                # Log failed operation
                audit.log_event(
                    event_type=event_type,
                    algorithm=g.get('algorithm'),
                    key_id=g.get('key_id'),
                    security_level=g.get('security_level'),
                    success=False,
                    error_message=str(e),
                    user_id=request.headers.get('X-User-ID'),
                    source_ip=request.remote_addr,
                    metadata={
                        "endpoint": request.path,
                        "method": request.method,
                    }
                )
                raise

        return decorated_function
    return decorator


def parse_security_level(level: Any) -> SecurityLevel:
    """Parse security level from request data."""
    if level is None:
        return SecurityLevel.LEVEL_3
    if isinstance(level, int):
        return SecurityLevel(level)
    if isinstance(level, str):
        level_map = {"1": SecurityLevel.LEVEL_1, "3": SecurityLevel.LEVEL_3, "5": SecurityLevel.LEVEL_5}
        return level_map.get(level, SecurityLevel.LEVEL_3)
    return SecurityLevel.LEVEL_3


# ==================== KEY GENERATION ====================

@crypto_bp.route('/keygen', methods=['POST'])
@audit_operation(AuditEventType.KEY_GENERATION)
def generate_keypair():
    """
    Generate a PQC key pair.

    Request JSON:
    {
        "key_type": "kem" | "sign" | "hybrid_kem" | "hybrid_sign",
        "security_level": 1 | 3 | 5,
        "labels": {"purpose": "encryption"},
        "expires_in_days": 365
    }

    Response JSON:
    {
        "success": true,
        "key_id": "...",
        "algorithm": "ML-KEM-768",
        "public_key": "base64...",
        "fingerprint": "sha256...",
        "metadata": {...}
    }
    """
    try:
        data = request.get_json() or {}
        key_type = data.get('key_type', 'kem')
        security_level = parse_security_level(data.get('security_level'))
        labels = data.get('labels', {})
        expires_in_days = data.get('expires_in_days', 365)

        # Store in g for audit
        g.security_level = security_level.value

        km = get_key_manager()

        # Generate key based on type
        if key_type == 'kem':
            metadata = km.generate_kem_keypair(
                security_level=security_level,
                labels=labels,
                expires_in_days=expires_in_days
            )
        elif key_type == 'sign':
            metadata = km.generate_sign_keypair(
                security_level=security_level,
                labels=labels,
                expires_in_days=expires_in_days
            )
        elif key_type == 'hybrid_kem':
            metadata = km.generate_hybrid_kem_keypair(
                security_level=security_level,
                labels=labels,
                expires_in_days=expires_in_days
            )
        elif key_type == 'hybrid_sign':
            metadata = km.generate_hybrid_sign_keypair(
                security_level=security_level,
                labels=labels,
                expires_in_days=expires_in_days
            )
        else:
            return jsonify({
                "success": False,
                "error": f"Invalid key type: {key_type}",
                "valid_types": ["kem", "sign", "hybrid_kem", "hybrid_sign"]
            }), 400

        # Store algorithm for audit
        g.algorithm = metadata.algorithm
        g.key_id = metadata.key_id

        # Get public key
        public_key = km.get_public_key(metadata.key_id)

        return jsonify({
            "success": True,
            "key_id": metadata.key_id,
            "algorithm": metadata.algorithm,
            "security_level": metadata.security_level,
            "public_key": base64.b64encode(public_key).decode() if public_key else None,
            "fingerprint": metadata.public_key_fingerprint,
            "expires_at": metadata.expires_at.isoformat() if metadata.expires_at else None,
            "metadata": metadata.to_dict()
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@crypto_bp.route('/keys', methods=['GET'])
def list_keys():
    """
    List all managed keys.

    Query Parameters:
    - key_type: Filter by key type
    - status: Filter by status
    - label_key, label_value: Filter by label

    Response JSON:
    {
        "success": true,
        "keys": [{...}, {...}],
        "count": 5
    }
    """
    try:
        km = get_key_manager()

        # Parse filters
        key_type = request.args.get('key_type')
        status = request.args.get('status')
        label_key = request.args.get('label_key')
        label_value = request.args.get('label_value')

        key_type_enum = KeyType(key_type) if key_type else None
        status_enum = KeyStatus(status) if status else None
        labels = {label_key: label_value} if label_key and label_value else None

        keys = km.list_keys(key_type=key_type_enum, status=status_enum, labels=labels)

        return jsonify({
            "success": True,
            "keys": [k.to_dict() for k in keys],
            "count": len(keys)
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@crypto_bp.route('/keys/<key_id>', methods=['GET'])
def get_key(key_id: str):
    """
    Get key metadata and public key.

    Response JSON:
    {
        "success": true,
        "key_id": "...",
        "metadata": {...},
        "public_key": "base64..."
    }
    """
    try:
        km = get_key_manager()
        metadata = km.get_metadata(key_id)

        if not metadata:
            return jsonify({
                "success": False,
                "error": f"Key not found: {key_id}"
            }), 404

        public_key = km.get_public_key(key_id)

        return jsonify({
            "success": True,
            "key_id": key_id,
            "metadata": metadata.to_dict(),
            "public_key": base64.b64encode(public_key).decode() if public_key else None
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@crypto_bp.route('/keys/<key_id>/rotate', methods=['POST'])
@audit_operation(AuditEventType.KEY_ROTATION)
def rotate_key(key_id: str):
    """
    Rotate a key.

    Response JSON:
    {
        "success": true,
        "old_key_id": "...",
        "new_key_id": "...",
        "new_metadata": {...}
    }
    """
    try:
        km = get_key_manager()
        g.key_id = key_id

        new_metadata = km.rotate_key(key_id)
        if not new_metadata:
            return jsonify({
                "success": False,
                "error": f"Failed to rotate key: {key_id}"
            }), 400

        g.algorithm = new_metadata.algorithm

        return jsonify({
            "success": True,
            "old_key_id": key_id,
            "new_key_id": new_metadata.key_id,
            "new_metadata": new_metadata.to_dict()
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@crypto_bp.route('/keys/<key_id>/revoke', methods=['POST'])
@audit_operation(AuditEventType.KEY_REVOCATION)
def revoke_key(key_id: str):
    """
    Revoke a key.

    Request JSON:
    {
        "reason": "Suspected compromise"
    }
    """
    try:
        data = request.get_json() or {}
        reason = data.get('reason', '')

        km = get_key_manager()
        g.key_id = key_id

        success = km.revoke_key(key_id, reason)
        if not success:
            return jsonify({
                "success": False,
                "error": f"Failed to revoke key: {key_id}"
            }), 400

        return jsonify({
            "success": True,
            "key_id": key_id,
            "status": "revoked",
            "reason": reason
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ==================== ENCRYPTION ====================

@crypto_bp.route('/encrypt', methods=['POST'])
@audit_operation(AuditEventType.ENCRYPTION)
def encrypt_data():
    """
    Encrypt data using PQC.

    Request JSON:
    {
        "plaintext": "base64...",  # or "plaintext_string": "hello"
        "recipient_key_id": "...",
        "sender_key_id": "..." (optional)
    }

    Response JSON:
    {
        "success": true,
        "message_id": "...",
        "encrypted_message": {...}
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "error": "Request body required"
            }), 400

        # Get plaintext
        if 'plaintext' in data:
            plaintext = base64.b64decode(data['plaintext'])
        elif 'plaintext_string' in data:
            plaintext = data['plaintext_string'].encode()
        else:
            return jsonify({
                "success": False,
                "error": "plaintext or plaintext_string required"
            }), 400

        recipient_key_id = data.get('recipient_key_id')
        if not recipient_key_id:
            return jsonify({
                "success": False,
                "error": "recipient_key_id required"
            }), 400

        sender_key_id = data.get('sender_key_id')

        g.key_id = recipient_key_id

        mc = get_message_crypto()
        encrypted = mc.encrypt_with_key_manager(
            plaintext=plaintext,
            recipient_key_id=recipient_key_id,
            sender_key_id=sender_key_id
        )

        if not encrypted:
            return jsonify({
                "success": False,
                "error": f"Encryption failed. Check recipient key: {recipient_key_id}"
            }), 400

        g.algorithm = encrypted.algorithm

        return jsonify({
            "success": True,
            "message_id": encrypted.message_id,
            "encrypted_message": encrypted.to_dict()
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ==================== DECRYPTION ====================

@crypto_bp.route('/decrypt', methods=['POST'])
@audit_operation(AuditEventType.DECRYPTION)
def decrypt_data():
    """
    Decrypt data using PQC.

    Request JSON:
    {
        "encrypted_message": {...}  # EncryptedMessage dict from encrypt
    }

    Response JSON:
    {
        "success": true,
        "plaintext": "base64...",
        "plaintext_string": "hello" (if valid UTF-8),
        "integrity_verified": true
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "error": "Request body required"
            }), 400

        encrypted_data = data.get('encrypted_message')
        if not encrypted_data:
            return jsonify({
                "success": False,
                "error": "encrypted_message required"
            }), 400

        from .message_crypto import EncryptedMessage
        encrypted = EncryptedMessage.from_dict(encrypted_data)

        g.key_id = encrypted.recipient_key_id
        g.algorithm = encrypted.algorithm

        mc = get_message_crypto()
        plaintext, integrity_verified = mc.decrypt_with_key_manager(encrypted)

        if not plaintext and not integrity_verified:
            return jsonify({
                "success": False,
                "error": "Decryption failed"
            }), 400

        # Try to decode as UTF-8
        plaintext_string = None
        try:
            plaintext_string = plaintext.decode('utf-8')
        except UnicodeDecodeError:
            pass

        return jsonify({
            "success": True,
            "plaintext": base64.b64encode(plaintext).decode(),
            "plaintext_string": plaintext_string,
            "integrity_verified": integrity_verified
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ==================== SIGNING ====================

@crypto_bp.route('/sign', methods=['POST'])
@audit_operation(AuditEventType.SIGNING)
def sign_data():
    """
    Sign data using PQC.

    Request JSON:
    {
        "content": "base64...",  # or "content_string": "hello"
        "signer_key_id": "...",
        "expiration_seconds": 3600 (optional)
    }

    Response JSON:
    {
        "success": true,
        "message_id": "...",
        "signed_message": {...}
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "error": "Request body required"
            }), 400

        # Get content
        if 'content' in data:
            content = base64.b64decode(data['content'])
        elif 'content_string' in data:
            content = data['content_string'].encode()
        else:
            return jsonify({
                "success": False,
                "error": "content or content_string required"
            }), 400

        signer_key_id = data.get('signer_key_id')
        if not signer_key_id:
            return jsonify({
                "success": False,
                "error": "signer_key_id required"
            }), 400

        expiration_seconds = data.get('expiration_seconds')

        g.key_id = signer_key_id

        mc = get_message_crypto()
        signed = mc.sign_with_key_manager(
            content=content,
            signer_key_id=signer_key_id,
            expiration_seconds=expiration_seconds
        )

        if not signed:
            return jsonify({
                "success": False,
                "error": f"Signing failed. Check signer key: {signer_key_id}"
            }), 400

        g.algorithm = signed.algorithm

        return jsonify({
            "success": True,
            "message_id": signed.message_id,
            "signed_message": signed.to_dict()
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ==================== VERIFICATION ====================

@crypto_bp.route('/verify', methods=['POST'])
@audit_operation(AuditEventType.VERIFICATION)
def verify_signature():
    """
    Verify a signature using PQC.

    Request JSON:
    {
        "signed_message": {...}  # SignedMessage dict from sign
    }

    Response JSON:
    {
        "success": true,
        "valid": true,
        "signer_key_id": "...",
        "content": "base64..."
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "error": "Request body required"
            }), 400

        signed_data = data.get('signed_message')
        if not signed_data:
            return jsonify({
                "success": False,
                "error": "signed_message required"
            }), 400

        from .message_crypto import SignedMessage
        signed = SignedMessage.from_dict(signed_data)

        g.key_id = signed.signer_key_id
        g.algorithm = signed.algorithm

        mc = get_message_crypto()
        is_valid, error = mc.verify_with_key_manager(signed)

        # Try to decode content as UTF-8
        content_string = None
        try:
            content_string = signed.content.decode('utf-8')
        except UnicodeDecodeError:
            pass

        return jsonify({
            "success": True,
            "valid": is_valid,
            "error": error,
            "signer_key_id": signed.signer_key_id,
            "content": base64.b64encode(signed.content).decode(),
            "content_string": content_string,
            "timestamp": signed.timestamp.isoformat(),
            "expired": signed.expiration and datetime.now(timezone.utc) > signed.expiration
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ==================== AUDIT ====================

@crypto_bp.route('/audit', methods=['GET'])
def get_audit_report():
    """
    Get cryptographic audit report.

    Query Parameters:
    - standard: Compliance standard (NIST-PQC, FIPS-140-3, NSA-CNSA-2.0, TSUNAMI)
    - include_events: Include recent events (default: false)
    - event_limit: Max events to include (default: 100)

    Response JSON:
    {
        "success": true,
        "statistics": {...},
        "weak_algorithms": [...],
        "migration_readiness": {...},
        "compliance_report": {...},
        "recent_events": [...] (optional)
    }
    """
    try:
        audit = get_crypto_audit()
        km = get_key_manager()

        # Parse parameters
        standard_str = request.args.get('standard', 'NIST-PQC')
        include_events = request.args.get('include_events', 'false').lower() == 'true'
        event_limit = int(request.args.get('event_limit', 100))

        # Map standard string
        standard_map = {
            'NIST-PQC': ComplianceStandard.NIST_PQC,
            'FIPS-140-3': ComplianceStandard.FIPS_140_3,
            'NSA-CNSA-2.0': ComplianceStandard.NSA_CNSA_2,
            'TSUNAMI': ComplianceStandard.TSUNAMI_INTERNAL,
        }
        standard = standard_map.get(standard_str, ComplianceStandard.NIST_PQC)

        # Gather data
        statistics = audit.get_statistics()
        weak_algorithms = audit.detect_weak_algorithms()
        migration = audit.assess_pqc_migration_readiness()

        # Get key inventory for compliance report
        key_inventory = km.export_public_keys()
        compliance = audit.generate_compliance_report(standard=standard, key_inventory=key_inventory)

        result = {
            "success": True,
            "statistics": statistics,
            "weak_algorithms": weak_algorithms,
            "migration_readiness": migration,
            "compliance_report": compliance.to_dict()
        }

        if include_events:
            events = audit.get_events(limit=event_limit)
            result["recent_events"] = [e.to_dict() for e in events]

        return jsonify(result)

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@crypto_bp.route('/audit/events', methods=['GET'])
def get_audit_events():
    """
    Get audit events with filtering.

    Query Parameters:
    - event_type: Filter by event type
    - algorithm: Filter by algorithm
    - key_id: Filter by key ID
    - success_only: Only successful events (default: false)
    - limit: Max events (default: 100)

    Response JSON:
    {
        "success": true,
        "events": [...],
        "count": 50
    }
    """
    try:
        audit = get_crypto_audit()

        # Parse filters
        event_type_str = request.args.get('event_type')
        algorithm = request.args.get('algorithm')
        key_id = request.args.get('key_id')
        success_only = request.args.get('success_only', 'false').lower() == 'true'
        limit = int(request.args.get('limit', 100))

        event_type = AuditEventType(event_type_str) if event_type_str else None

        events = audit.get_events(
            event_type=event_type,
            algorithm=algorithm,
            key_id=key_id,
            success_only=success_only,
            limit=limit
        )

        return jsonify({
            "success": True,
            "events": [e.to_dict() for e in events],
            "count": len(events)
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ==================== ALGORITHMS INFO ====================

@crypto_bp.route('/algorithms', methods=['GET'])
def list_algorithms():
    """
    List available PQC algorithms and their parameters.

    Response JSON:
    {
        "success": true,
        "algorithms": {
            "LEVEL_1": {...},
            "LEVEL_3": {...},
            "LEVEL_5": {...}
        }
    }
    """
    try:
        pqc = get_pqc()
        algorithms = pqc.list_available_algorithms()

        return jsonify({
            "success": True,
            "algorithms": algorithms,
            "default_security_level": 3,
            "hybrid_mode_available": True
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ==================== SECURE CHANNEL ====================

@crypto_bp.route('/channel/initiate', methods=['POST'])
@audit_operation(AuditEventType.CHANNEL_ESTABLISHED)
def initiate_channel():
    """
    Initiate a secure channel handshake.

    Response JSON:
    {
        "success": true,
        "channel_id": "...",
        "handshake_message": "base64..."
    }
    """
    try:
        sc = get_secure_channel()
        channel_id, handshake_msg, session = sc.initiate_handshake()

        g.key_id = channel_id
        g.algorithm = f"ML-KEM-{sc.security_level.value * 256}"

        return jsonify({
            "success": True,
            "channel_id": channel_id,
            "handshake_message": base64.b64encode(handshake_msg).decode(),
            "security_level": sc.security_level.value,
            "hybrid_mode": sc.use_hybrid
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@crypto_bp.route('/channel/respond', methods=['POST'])
@audit_operation(AuditEventType.CHANNEL_ESTABLISHED)
def respond_to_channel():
    """
    Respond to a channel handshake.

    Request JSON:
    {
        "handshake_message": "base64..."
    }

    Response JSON:
    {
        "success": true,
        "channel_id": "...",
        "response_message": "base64..."
    }
    """
    try:
        data = request.get_json()
        if not data or 'handshake_message' not in data:
            return jsonify({
                "success": False,
                "error": "handshake_message required"
            }), 400

        handshake_msg = base64.b64decode(data['handshake_message'])

        sc = get_secure_channel()
        result = sc.respond_to_handshake(handshake_msg)

        g.key_id = result.channel_id

        if not result.success:
            return jsonify({
                "success": False,
                "error": result.error_message
            }), 400

        return jsonify({
            "success": True,
            "channel_id": result.channel_id,
            "response_message": base64.b64encode(result.handshake_data).decode() if result.handshake_data else None
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@crypto_bp.route('/channel/<channel_id>/finalize', methods=['POST'])
def finalize_channel(channel_id: str):
    """
    Finalize a channel handshake.

    Request JSON:
    {
        "response_message": "base64..."
    }
    """
    try:
        data = request.get_json()
        if not data or 'response_message' not in data:
            return jsonify({
                "success": False,
                "error": "response_message required"
            }), 400

        response_msg = base64.b64decode(data['response_message'])

        sc = get_secure_channel()
        result = sc.finalize_handshake(channel_id, response_msg)

        if not result.success:
            return jsonify({
                "success": False,
                "error": result.error_message
            }), 400

        return jsonify({
            "success": True,
            "channel_id": channel_id,
            "state": "established"
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@crypto_bp.route('/channel/<channel_id>/send', methods=['POST'])
@audit_operation(AuditEventType.ENCRYPTION)
def channel_send(channel_id: str):
    """
    Send an encrypted message on a channel.

    Request JSON:
    {
        "message": "base64...",  # or "message_string": "hello"
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "error": "Request body required"
            }), 400

        if 'message' in data:
            plaintext = base64.b64decode(data['message'])
        elif 'message_string' in data:
            plaintext = data['message_string'].encode()
        else:
            return jsonify({
                "success": False,
                "error": "message or message_string required"
            }), 400

        g.key_id = channel_id

        sc = get_secure_channel()
        encrypted, error = sc.encrypt_message(channel_id, plaintext)

        if error:
            return jsonify({
                "success": False,
                "error": error
            }), 400

        return jsonify({
            "success": True,
            "encrypted_message": base64.b64encode(encrypted).decode()
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@crypto_bp.route('/channel/<channel_id>/receive', methods=['POST'])
@audit_operation(AuditEventType.DECRYPTION)
def channel_receive(channel_id: str):
    """
    Receive and decrypt a message on a channel.

    Request JSON:
    {
        "encrypted_message": "base64..."
    }
    """
    try:
        data = request.get_json()
        if not data or 'encrypted_message' not in data:
            return jsonify({
                "success": False,
                "error": "encrypted_message required"
            }), 400

        encrypted = base64.b64decode(data['encrypted_message'])
        g.key_id = channel_id

        sc = get_secure_channel()
        plaintext, error = sc.decrypt_message(channel_id, encrypted)

        if error:
            return jsonify({
                "success": False,
                "error": error
            }), 400

        # Try to decode as UTF-8
        plaintext_string = None
        try:
            plaintext_string = plaintext.decode('utf-8')
        except UnicodeDecodeError:
            pass

        return jsonify({
            "success": True,
            "message": base64.b64encode(plaintext).decode(),
            "message_string": plaintext_string
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@crypto_bp.route('/channel/<channel_id>', methods=['GET'])
def channel_info(channel_id: str):
    """Get channel information."""
    try:
        sc = get_secure_channel()
        info = sc.get_channel_info(channel_id)

        if not info:
            return jsonify({
                "success": False,
                "error": f"Channel not found: {channel_id}"
            }), 404

        return jsonify({
            "success": True,
            "channel": info
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@crypto_bp.route('/channel/<channel_id>', methods=['DELETE'])
@audit_operation(AuditEventType.CHANNEL_CLOSED)
def close_channel(channel_id: str):
    """Close a secure channel."""
    try:
        g.key_id = channel_id

        sc = get_secure_channel()
        success = sc.close_channel(channel_id)

        if not success:
            return jsonify({
                "success": False,
                "error": f"Channel not found: {channel_id}"
            }), 404

        return jsonify({
            "success": True,
            "channel_id": channel_id,
            "status": "closed"
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@crypto_bp.route('/channels', methods=['GET'])
def list_channels():
    """List all active channels."""
    try:
        sc = get_secure_channel()
        channels = sc.list_channels()

        return jsonify({
            "success": True,
            "channels": channels,
            "count": len(channels)
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ==================== HEALTH CHECK ====================

@crypto_bp.route('/health', methods=['GET'])
def health_check():
    """Health check for the crypto module."""
    try:
        pqc = get_pqc()

        # Quick crypto test
        keypair = pqc.generate_kem_keypair(SecurityLevel.LEVEL_1)
        result = pqc.encapsulate(keypair.public_key, SecurityLevel.LEVEL_1)
        decapsulated = pqc.decapsulate(keypair.secret_key, result.ciphertext, SecurityLevel.LEVEL_1)

        crypto_working = decapsulated == result.shared_secret

        return jsonify({
            "success": True,
            "status": "healthy" if crypto_working else "degraded",
            "crypto_test": crypto_working,
            "algorithms_available": list(pqc.KEM_NAMES.values()) + list(pqc.SIGN_NAMES.values()),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "status": "unhealthy",
            "error": str(e)
        }), 500
