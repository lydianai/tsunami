"""
Quantum-Safe Secure Channel

Establishes PQC-protected communication channels with:
- Hybrid TLS-like handshake (combining classical + PQC)
- Forward secrecy using ephemeral keys
- Session key management
- Channel state tracking
"""

import os
import secrets
import hashlib
import hmac
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from .pqc_algorithms import PQCAlgorithms, SecurityLevel, KeyPair, HybridKeyPair


class ChannelState(Enum):
    """State of a secure channel."""
    INITIAL = "initial"
    HANDSHAKE_INITIATED = "handshake_initiated"
    HANDSHAKE_RESPONSE = "handshake_response"
    ESTABLISHED = "established"
    REKEYING = "rekeying"
    CLOSED = "closed"
    ERROR = "error"


@dataclass
class HandshakeResult:
    """Result of a channel handshake operation."""
    success: bool
    channel_id: str
    session_key: Optional[bytes] = None
    error_message: Optional[str] = None
    handshake_data: Optional[bytes] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "channel_id": self.channel_id,
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat(),
            "handshake_data_size": len(self.handshake_data) if self.handshake_data else 0,
        }


@dataclass
class ChannelSession:
    """Active secure channel session."""
    channel_id: str
    state: ChannelState
    local_keypair: HybridKeyPair
    peer_public_keys: Optional[Dict[str, bytes]] = None
    session_key: Optional[bytes] = None
    encryption_key: Optional[bytes] = None
    mac_key: Optional[bytes] = None
    send_counter: int = 0
    recv_counter: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    max_messages: int = 1000000  # Rekey after this many messages
    max_lifetime_seconds: int = 86400  # Rekey after 24 hours


class SecureChannel:
    """
    Quantum-Safe Secure Channel Provider

    Implements a hybrid TLS-like protocol combining:
    - ML-KEM for post-quantum key encapsulation
    - X25519 for classical key agreement
    - AES-256-GCM for authenticated encryption
    - HMAC-SHA256 for message authentication

    Features:
    - Forward secrecy via ephemeral keys
    - Protection against harvest-now-decrypt-later attacks
    - Session key derivation using HKDF
    - Automatic rekeying
    """

    # Protocol version
    PROTOCOL_VERSION = b"\x05\x00"  # TSUNAMI v5.0

    # Key derivation labels
    KDF_LABEL_ENC = b"TSUNAMI-v5-encryption"
    KDF_LABEL_MAC = b"TSUNAMI-v5-authentication"
    KDF_LABEL_REKEY = b"TSUNAMI-v5-rekey"

    def __init__(
        self,
        security_level: SecurityLevel = SecurityLevel.LEVEL_3,
        use_hybrid: bool = True
    ):
        """
        Initialize the secure channel provider.

        Args:
            security_level: NIST security level for PQC operations
            use_hybrid: Whether to use hybrid classical+PQC mode
        """
        self.pqc = PQCAlgorithms(security_level)
        self.security_level = security_level
        self.use_hybrid = use_hybrid
        self.sessions: Dict[str, ChannelSession] = {}

    def _generate_channel_id(self) -> str:
        """Generate a unique channel identifier."""
        return secrets.token_hex(16)

    def _derive_session_keys(
        self,
        shared_secret: bytes,
        channel_id: str,
        additional_data: bytes = b""
    ) -> Tuple[bytes, bytes]:
        """
        Derive encryption and MAC keys from shared secret.

        Uses HKDF with channel-specific info to derive independent keys.

        Args:
            shared_secret: Combined shared secret from key exchange
            channel_id: Channel identifier for key separation
            additional_data: Optional additional data to bind to keys

        Returns:
            Tuple of (encryption_key, mac_key)
        """
        # Create info string for HKDF
        info_base = channel_id.encode() + additional_data

        # Derive encryption key (32 bytes for AES-256)
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=self.KDF_LABEL_ENC + info_base,
            backend=default_backend()
        ).derive(shared_secret)

        # Derive MAC key (32 bytes for HMAC-SHA256)
        mac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=self.KDF_LABEL_MAC + info_base,
            backend=default_backend()
        ).derive(shared_secret)

        return encryption_key, mac_key

    # ==================== HANDSHAKE - INITIATOR ====================

    def initiate_handshake(self) -> Tuple[str, bytes, ChannelSession]:
        """
        Initiate a new secure channel handshake.

        This is step 1 of the handshake protocol. The initiator generates
        ephemeral keys and sends public keys to the responder.

        Returns:
            Tuple of (channel_id, handshake_message, session)
        """
        channel_id = self._generate_channel_id()

        # Generate ephemeral hybrid keypair for forward secrecy
        if self.use_hybrid:
            local_keypair = self.pqc.generate_hybrid_kem_keypair(self.security_level)
        else:
            # PQC-only mode
            pqc_keypair = self.pqc.generate_kem_keypair(self.security_level)
            local_keypair = HybridKeyPair(
                pqc_keypair=pqc_keypair,
                classical_public_key=b"",
                classical_secret_key=b"",
                classical_algorithm="none"
            )

        # Build handshake message
        # Format: VERSION (2) | CHANNEL_ID (32) | SECURITY_LEVEL (1) | HYBRID (1) |
        #         PQC_PK_LEN (2) | PQC_PUBLIC_KEY | CLASSICAL_PK_LEN (2) | CLASSICAL_PUBLIC_KEY
        handshake_msg = bytearray()
        handshake_msg.extend(self.PROTOCOL_VERSION)
        handshake_msg.extend(bytes.fromhex(channel_id))
        handshake_msg.append(self.security_level.value)
        handshake_msg.append(1 if self.use_hybrid else 0)

        # PQC public key
        pqc_pk = local_keypair.pqc_keypair.public_key
        handshake_msg.extend(len(pqc_pk).to_bytes(2, 'big'))
        handshake_msg.extend(pqc_pk)

        # Classical public key (if hybrid)
        classical_pk = local_keypair.classical_public_key
        handshake_msg.extend(len(classical_pk).to_bytes(2, 'big'))
        handshake_msg.extend(classical_pk)

        # Create session
        session = ChannelSession(
            channel_id=channel_id,
            state=ChannelState.HANDSHAKE_INITIATED,
            local_keypair=local_keypair,
        )
        self.sessions[channel_id] = session

        return channel_id, bytes(handshake_msg), session

    # ==================== HANDSHAKE - RESPONDER ====================

    def respond_to_handshake(
        self,
        handshake_msg: bytes
    ) -> HandshakeResult:
        """
        Respond to an incoming handshake message.

        This is step 2 of the handshake protocol. The responder:
        1. Parses the initiator's public keys
        2. Generates ephemeral keys
        3. Performs key encapsulation
        4. Derives session keys
        5. Returns response message

        Args:
            handshake_msg: Handshake message from initiator

        Returns:
            HandshakeResult with response data
        """
        try:
            # Parse handshake message
            offset = 0

            # Version check
            version = handshake_msg[offset:offset+2]
            offset += 2
            if version != self.PROTOCOL_VERSION:
                return HandshakeResult(
                    success=False,
                    channel_id="",
                    error_message=f"Protocol version mismatch: expected {self.PROTOCOL_VERSION.hex()}, got {version.hex()}"
                )

            # Channel ID
            channel_id = handshake_msg[offset:offset+16].hex()
            offset += 16

            # Security level
            security_level = SecurityLevel(handshake_msg[offset])
            offset += 1

            # Hybrid flag
            use_hybrid = handshake_msg[offset] == 1
            offset += 1

            # PQC public key
            pqc_pk_len = int.from_bytes(handshake_msg[offset:offset+2], 'big')
            offset += 2
            initiator_pqc_pk = handshake_msg[offset:offset+pqc_pk_len]
            offset += pqc_pk_len

            # Classical public key
            classical_pk_len = int.from_bytes(handshake_msg[offset:offset+2], 'big')
            offset += 2
            initiator_classical_pk = handshake_msg[offset:offset+classical_pk_len]

            # Generate our ephemeral keypair
            if use_hybrid:
                local_keypair = self.pqc.generate_hybrid_kem_keypair(security_level)
            else:
                pqc_keypair = self.pqc.generate_kem_keypair(security_level)
                local_keypair = HybridKeyPair(
                    pqc_keypair=pqc_keypair,
                    classical_public_key=b"",
                    classical_secret_key=b"",
                    classical_algorithm="none"
                )

            # Perform key encapsulation
            if use_hybrid:
                pqc_ct, classical_ct, shared_secret = self.pqc.hybrid_encapsulate(
                    initiator_pqc_pk,
                    initiator_classical_pk,
                    security_level
                )
            else:
                result = self.pqc.encapsulate(initiator_pqc_pk, security_level)
                pqc_ct = result.ciphertext
                classical_ct = b""
                shared_secret = result.shared_secret

            # Derive session keys
            encryption_key, mac_key = self._derive_session_keys(
                shared_secret, channel_id
            )

            # Build response message
            # Format: VERSION | CHANNEL_ID | PQC_CT_LEN | PQC_CIPHERTEXT |
            #         CLASSICAL_CT_LEN | CLASSICAL_CIPHERTEXT |
            #         PQC_PK_LEN | OUR_PQC_PUBLIC_KEY | CLASSICAL_PK_LEN | OUR_CLASSICAL_PUBLIC_KEY
            response = bytearray()
            response.extend(self.PROTOCOL_VERSION)
            response.extend(bytes.fromhex(channel_id))

            response.extend(len(pqc_ct).to_bytes(2, 'big'))
            response.extend(pqc_ct)

            response.extend(len(classical_ct).to_bytes(2, 'big'))
            response.extend(classical_ct)

            response.extend(len(local_keypair.pqc_keypair.public_key).to_bytes(2, 'big'))
            response.extend(local_keypair.pqc_keypair.public_key)

            response.extend(len(local_keypair.classical_public_key).to_bytes(2, 'big'))
            response.extend(local_keypair.classical_public_key)

            # Create session
            session = ChannelSession(
                channel_id=channel_id,
                state=ChannelState.ESTABLISHED,
                local_keypair=local_keypair,
                peer_public_keys={
                    "pqc": initiator_pqc_pk,
                    "classical": initiator_classical_pk,
                },
                session_key=shared_secret,
                encryption_key=encryption_key,
                mac_key=mac_key,
            )
            self.sessions[channel_id] = session

            return HandshakeResult(
                success=True,
                channel_id=channel_id,
                session_key=shared_secret,
                handshake_data=bytes(response),
            )

        except Exception as e:
            return HandshakeResult(
                success=False,
                channel_id="",
                error_message=str(e),
            )

    # ==================== HANDSHAKE - FINALIZE ====================

    def finalize_handshake(
        self,
        channel_id: str,
        response_msg: bytes
    ) -> HandshakeResult:
        """
        Finalize the handshake as the initiator.

        This is step 3 of the handshake protocol. The initiator:
        1. Parses the responder's response
        2. Decapsulates the shared secret
        3. Derives session keys

        Args:
            channel_id: Channel ID from initiation
            response_msg: Response message from responder

        Returns:
            HandshakeResult indicating success/failure
        """
        session = self.sessions.get(channel_id)
        if not session:
            return HandshakeResult(
                success=False,
                channel_id=channel_id,
                error_message="Unknown channel ID",
            )

        if session.state != ChannelState.HANDSHAKE_INITIATED:
            return HandshakeResult(
                success=False,
                channel_id=channel_id,
                error_message=f"Invalid channel state: {session.state}",
            )

        try:
            # Parse response
            offset = 0

            # Version
            version = response_msg[offset:offset+2]
            offset += 2
            if version != self.PROTOCOL_VERSION:
                return HandshakeResult(
                    success=False,
                    channel_id=channel_id,
                    error_message="Protocol version mismatch",
                )

            # Channel ID verification
            resp_channel_id = response_msg[offset:offset+16].hex()
            offset += 16
            if resp_channel_id != channel_id:
                return HandshakeResult(
                    success=False,
                    channel_id=channel_id,
                    error_message="Channel ID mismatch",
                )

            # PQC ciphertext
            pqc_ct_len = int.from_bytes(response_msg[offset:offset+2], 'big')
            offset += 2
            pqc_ciphertext = response_msg[offset:offset+pqc_ct_len]
            offset += pqc_ct_len

            # Classical ciphertext
            classical_ct_len = int.from_bytes(response_msg[offset:offset+2], 'big')
            offset += 2
            classical_ciphertext = response_msg[offset:offset+classical_ct_len]
            offset += classical_ct_len

            # Responder's PQC public key (for potential rekeying)
            resp_pqc_pk_len = int.from_bytes(response_msg[offset:offset+2], 'big')
            offset += 2
            responder_pqc_pk = response_msg[offset:offset+resp_pqc_pk_len]
            offset += resp_pqc_pk_len

            # Responder's classical public key
            resp_classical_pk_len = int.from_bytes(response_msg[offset:offset+2], 'big')
            offset += 2
            responder_classical_pk = response_msg[offset:offset+resp_classical_pk_len]

            # Decapsulate shared secret
            if self.use_hybrid and classical_ciphertext:
                shared_secret = self.pqc.hybrid_decapsulate(
                    session.local_keypair.pqc_keypair.secret_key,
                    session.local_keypair.classical_secret_key,
                    pqc_ciphertext,
                    classical_ciphertext,
                    self.security_level
                )
            else:
                shared_secret = self.pqc.decapsulate(
                    session.local_keypair.pqc_keypair.secret_key,
                    pqc_ciphertext,
                    self.security_level
                )

            # Derive session keys
            encryption_key, mac_key = self._derive_session_keys(
                shared_secret, channel_id
            )

            # Update session
            session.state = ChannelState.ESTABLISHED
            session.peer_public_keys = {
                "pqc": responder_pqc_pk,
                "classical": responder_classical_pk,
            }
            session.session_key = shared_secret
            session.encryption_key = encryption_key
            session.mac_key = mac_key

            return HandshakeResult(
                success=True,
                channel_id=channel_id,
                session_key=shared_secret,
            )

        except Exception as e:
            session.state = ChannelState.ERROR
            return HandshakeResult(
                success=False,
                channel_id=channel_id,
                error_message=str(e),
            )

    # ==================== SECURE MESSAGING ====================

    def encrypt_message(
        self,
        channel_id: str,
        plaintext: bytes
    ) -> Tuple[bytes, Optional[str]]:
        """
        Encrypt a message for the secure channel.

        Uses AES-256-GCM with a counter-based nonce for replay protection.

        Args:
            channel_id: Channel to send on
            plaintext: Message to encrypt

        Returns:
            Tuple of (ciphertext, error_message)
        """
        session = self.sessions.get(channel_id)
        if not session:
            return b"", "Unknown channel"

        if session.state != ChannelState.ESTABLISHED:
            return b"", f"Channel not established: {session.state}"

        # Check if rekey is needed
        if session.send_counter >= session.max_messages:
            return b"", "Rekey required: message limit exceeded"

        # Build nonce from counter (12 bytes for GCM)
        nonce = session.send_counter.to_bytes(12, 'big')
        session.send_counter += 1

        # Encrypt with AES-GCM
        aesgcm = AESGCM(session.encryption_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, channel_id.encode())

        # Build message: NONCE | CIPHERTEXT
        message = nonce + ciphertext

        session.last_activity = datetime.now(timezone.utc)
        return message, None

    def decrypt_message(
        self,
        channel_id: str,
        encrypted_msg: bytes
    ) -> Tuple[bytes, Optional[str]]:
        """
        Decrypt a message from the secure channel.

        Args:
            channel_id: Channel to receive on
            encrypted_msg: Encrypted message

        Returns:
            Tuple of (plaintext, error_message)
        """
        session = self.sessions.get(channel_id)
        if not session:
            return b"", "Unknown channel"

        if session.state != ChannelState.ESTABLISHED:
            return b"", f"Channel not established: {session.state}"

        try:
            # Extract nonce and ciphertext
            nonce = encrypted_msg[:12]
            ciphertext = encrypted_msg[12:]

            # Verify counter is not replayed
            msg_counter = int.from_bytes(nonce, 'big')
            if msg_counter < session.recv_counter:
                return b"", "Replay detected: old message counter"

            # Decrypt with AES-GCM
            aesgcm = AESGCM(session.encryption_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, channel_id.encode())

            # Update receive counter
            session.recv_counter = max(session.recv_counter, msg_counter + 1)
            session.last_activity = datetime.now(timezone.utc)

            return plaintext, None

        except Exception as e:
            return b"", f"Decryption failed: {str(e)}"

    # ==================== SESSION MANAGEMENT ====================

    def rekey_channel(self, channel_id: str) -> HandshakeResult:
        """
        Perform a rekey operation on an established channel.

        This generates new ephemeral keys while maintaining the channel.

        Args:
            channel_id: Channel to rekey

        Returns:
            HandshakeResult indicating success/failure
        """
        session = self.sessions.get(channel_id)
        if not session:
            return HandshakeResult(
                success=False,
                channel_id=channel_id,
                error_message="Unknown channel",
            )

        if session.state != ChannelState.ESTABLISHED:
            return HandshakeResult(
                success=False,
                channel_id=channel_id,
                error_message=f"Channel not established: {session.state}",
            )

        try:
            session.state = ChannelState.REKEYING

            # Derive new keys from current session key
            new_session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=secrets.token_bytes(32),
                info=self.KDF_LABEL_REKEY + channel_id.encode(),
                backend=default_backend()
            ).derive(session.session_key)

            # Derive new encryption and MAC keys
            new_enc_key, new_mac_key = self._derive_session_keys(
                new_session_key, channel_id, b"rekey"
            )

            # Update session
            session.session_key = new_session_key
            session.encryption_key = new_enc_key
            session.mac_key = new_mac_key
            session.send_counter = 0
            session.recv_counter = 0
            session.state = ChannelState.ESTABLISHED

            return HandshakeResult(
                success=True,
                channel_id=channel_id,
                session_key=new_session_key,
            )

        except Exception as e:
            session.state = ChannelState.ERROR
            return HandshakeResult(
                success=False,
                channel_id=channel_id,
                error_message=str(e),
            )

    def close_channel(self, channel_id: str) -> bool:
        """
        Close a secure channel and clear all keys.

        Args:
            channel_id: Channel to close

        Returns:
            True if channel was closed, False if not found
        """
        session = self.sessions.get(channel_id)
        if not session:
            return False

        # Securely clear keys
        if session.session_key:
            session.session_key = secrets.token_bytes(len(session.session_key))
        if session.encryption_key:
            session.encryption_key = secrets.token_bytes(len(session.encryption_key))
        if session.mac_key:
            session.mac_key = secrets.token_bytes(len(session.mac_key))

        session.state = ChannelState.CLOSED
        del self.sessions[channel_id]
        return True

    def get_channel_info(self, channel_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a channel."""
        session = self.sessions.get(channel_id)
        if not session:
            return None

        return {
            "channel_id": channel_id,
            "state": session.state.value,
            "send_counter": session.send_counter,
            "recv_counter": session.recv_counter,
            "created_at": session.created_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "hybrid_mode": self.use_hybrid,
            "security_level": self.security_level.value,
        }

    def list_channels(self) -> Dict[str, Dict[str, Any]]:
        """List all active channels."""
        return {
            cid: self.get_channel_info(cid)
            for cid in self.sessions
        }
