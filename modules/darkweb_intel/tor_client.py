#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 - Tor Network Client
    Real Tor integration with SOCKS proxy, circuit management, and .onion access
================================================================================
"""

import os
import time
import socket
import hashlib
import logging
import threading
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TorConnectionStatus(Enum):
    """Tor connection status enumeration"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    CIRCUIT_BUILDING = "circuit_building"
    READY = "ready"
    ERROR = "error"


@dataclass
class TorCircuit:
    """Represents a Tor circuit"""
    circuit_id: str
    status: str
    created_at: datetime = field(default_factory=datetime.now)
    nodes: List[str] = field(default_factory=list)
    entry_node: Optional[str] = None
    middle_node: Optional[str] = None
    exit_node: Optional[str] = None
    latency_ms: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0


@dataclass
class TorConfig:
    """Tor client configuration"""
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050
    control_port: int = 9051
    control_password: Optional[str] = None
    timeout: int = 60
    retry_attempts: int = 3
    circuit_build_timeout: int = 60
    new_circuit_period: int = 300  # Request new circuit every 5 minutes
    use_stem: bool = True  # Use stem library for control if available


class TorCircuitManager:
    """
    Manages Tor circuits for improved anonymity and reliability
    """

    def __init__(self, control_port: int = 9051, control_password: Optional[str] = None):
        self.control_port = control_port
        self.control_password = control_password or os.getenv("TOR_CONTROL_PASSWORD", "")
        self.circuits: Dict[str, TorCircuit] = {}
        self._controller = None
        self._stem_available = False

        # Check if stem is available for control port operations
        try:
            from stem.control import Controller
            from stem import Signal
            self._stem_available = True
            logger.info("[TOR] Stem library available for circuit management")
        except ImportError:
            logger.warning("[TOR] Stem library not available - limited circuit control")

    def connect_controller(self) -> bool:
        """Connect to Tor control port using stem"""
        if not self._stem_available:
            return False

        try:
            from stem.control import Controller

            self._controller = Controller.from_port(port=self.control_port)

            if self.control_password:
                self._controller.authenticate(password=self.control_password)
            else:
                self._controller.authenticate()

            logger.info(f"[TOR] Connected to control port {self.control_port}")
            return True

        except Exception as e:
            logger.error(f"[TOR] Control port connection failed: {e}")
            return False

    def request_new_circuit(self) -> bool:
        """Request Tor to build a new circuit (new identity)"""
        if not self._stem_available or not self._controller:
            return False

        try:
            from stem import Signal

            self._controller.signal(Signal.NEWNYM)
            logger.info("[TOR] Requested new circuit (NEWNYM signal sent)")

            # Wait for new circuit to be established
            time.sleep(5)
            return True

        except Exception as e:
            logger.error(f"[TOR] Failed to request new circuit: {e}")
            return False

    def get_circuits(self) -> List[TorCircuit]:
        """Get list of current circuits"""
        if not self._stem_available or not self._controller:
            return []

        try:
            circuits = []
            for circ in self._controller.get_circuits():
                circuit = TorCircuit(
                    circuit_id=str(circ.id),
                    status=str(circ.status),
                    nodes=[str(node[0]) for node in circ.path]
                )
                if len(circuit.nodes) >= 1:
                    circuit.entry_node = circuit.nodes[0]
                if len(circuit.nodes) >= 2:
                    circuit.middle_node = circuit.nodes[1]
                if len(circuit.nodes) >= 3:
                    circuit.exit_node = circuit.nodes[2]

                circuits.append(circuit)
                self.circuits[circuit.circuit_id] = circuit

            return circuits

        except Exception as e:
            logger.error(f"[TOR] Failed to get circuits: {e}")
            return []

    def get_exit_node_info(self) -> Optional[Dict[str, Any]]:
        """Get information about current exit node"""
        if not self._stem_available or not self._controller:
            return None

        try:
            circuits = self.get_circuits()
            for circ in circuits:
                if circ.status == "BUILT" and circ.exit_node:
                    # Get relay info
                    relay = self._controller.get_network_status(circ.exit_node)
                    if relay:
                        return {
                            "fingerprint": circ.exit_node,
                            "nickname": relay.nickname,
                            "address": str(relay.address),
                            "or_port": relay.or_port,
                            "flags": list(relay.flags) if relay.flags else [],
                            "bandwidth": relay.bandwidth
                        }
            return None

        except Exception as e:
            logger.error(f"[TOR] Failed to get exit node info: {e}")
            return None

    def close(self):
        """Close control connection"""
        if self._controller:
            try:
                self._controller.close()
            except:
                pass
            self._controller = None


class TorClient:
    """
    Production-ready Tor client for TSUNAMI v5.0

    Features:
    - SOCKS5 proxy connection through Tor
    - .onion site access
    - Circuit management and rotation
    - Connection health monitoring
    - Automatic fallback mechanisms
    - Rate limiting to avoid detection
    """

    def __init__(self, config: Optional[TorConfig] = None):
        self.config = config or TorConfig()
        self.status = TorConnectionStatus.DISCONNECTED
        self._session: Optional[requests.Session] = None
        self._circuit_manager: Optional[TorCircuitManager] = None
        self._last_circuit_change = datetime.now()
        self._request_count = 0
        self._lock = threading.Lock()
        self._health_check_thread: Optional[threading.Thread] = None
        self._running = False

        # Load config from environment
        self.config.socks_host = os.getenv("TOR_SOCKS_HOST", self.config.socks_host)
        self.config.socks_port = int(os.getenv("TOR_SOCKS_PORT", self.config.socks_port))
        self.config.control_port = int(os.getenv("TOR_CONTROL_PORT", self.config.control_port))
        self.config.control_password = os.getenv("TOR_CONTROL_PASSWORD", self.config.control_password)

        logger.info(f"[TOR] Client initialized - SOCKS: {self.config.socks_host}:{self.config.socks_port}")

    def _create_session(self) -> requests.Session:
        """Create a requests session configured for Tor"""
        session = requests.Session()

        # Configure SOCKS5 proxy
        proxy_url = f"socks5h://{self.config.socks_host}:{self.config.socks_port}"
        session.proxies = {
            "http": proxy_url,
            "https": proxy_url
        }

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.retry_attempts,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set headers to appear more like Tor Browser
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1"
        })

        return session

    def connect(self) -> bool:
        """
        Connect to Tor network

        Returns:
            bool: True if connection successful
        """
        with self._lock:
            self.status = TorConnectionStatus.CONNECTING

            try:
                # Create session
                self._session = self._create_session()

                # Test connection by checking Tor status
                if not self._verify_tor_connection():
                    self.status = TorConnectionStatus.ERROR
                    return False

                # Initialize circuit manager
                self._circuit_manager = TorCircuitManager(
                    control_port=self.config.control_port,
                    control_password=self.config.control_password
                )
                self._circuit_manager.connect_controller()

                self.status = TorConnectionStatus.READY
                logger.info("[TOR] Successfully connected to Tor network")

                # Start health check thread
                self._start_health_check()

                return True

            except Exception as e:
                logger.error(f"[TOR] Connection failed: {e}")
                self.status = TorConnectionStatus.ERROR
                return False

    def _verify_tor_connection(self) -> bool:
        """Verify that requests are going through Tor"""
        try:
            # Use Tor Project's check service
            response = self._session.get(
                "https://check.torproject.org/api/ip",
                timeout=self.config.timeout
            )

            if response.status_code == 200:
                data = response.json()
                is_tor = data.get("IsTor", False)

                if is_tor:
                    ip = data.get("IP", "unknown")
                    logger.info(f"[TOR] Connection verified - Exit IP: {ip}")
                    return True
                else:
                    logger.warning("[TOR] Not using Tor according to check.torproject.org")
                    return False

            return False

        except Exception as e:
            logger.error(f"[TOR] Connection verification failed: {e}")
            return False

    def _start_health_check(self):
        """Start background health check thread"""
        if self._health_check_thread and self._health_check_thread.is_alive():
            return

        self._running = True
        self._health_check_thread = threading.Thread(
            target=self._health_check_loop,
            daemon=True
        )
        self._health_check_thread.start()

    def _health_check_loop(self):
        """Background health check loop"""
        while self._running:
            time.sleep(60)  # Check every minute

            if self.status == TorConnectionStatus.READY:
                # Rotate circuit if needed
                elapsed = (datetime.now() - self._last_circuit_change).total_seconds()
                if elapsed >= self.config.new_circuit_period:
                    self.rotate_circuit()

                # Verify connection is still working
                if not self._verify_tor_connection():
                    logger.warning("[TOR] Health check failed - attempting reconnect")
                    self.reconnect()

    def disconnect(self):
        """Disconnect from Tor network"""
        self._running = False

        if self._circuit_manager:
            self._circuit_manager.close()
            self._circuit_manager = None

        if self._session:
            self._session.close()
            self._session = None

        self.status = TorConnectionStatus.DISCONNECTED
        logger.info("[TOR] Disconnected from Tor network")

    def reconnect(self) -> bool:
        """Reconnect to Tor network"""
        self.disconnect()
        time.sleep(2)
        return self.connect()

    def rotate_circuit(self) -> bool:
        """Request a new Tor circuit for a new identity"""
        if self._circuit_manager:
            success = self._circuit_manager.request_new_circuit()
            if success:
                self._last_circuit_change = datetime.now()
                logger.info("[TOR] Circuit rotated successfully")
            return success
        return False

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Make a GET request through Tor

        Args:
            url: Target URL (can be .onion)
            **kwargs: Additional arguments for requests.get()

        Returns:
            requests.Response or None
        """
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Make a POST request through Tor

        Args:
            url: Target URL (can be .onion)
            **kwargs: Additional arguments for requests.post()

        Returns:
            requests.Response or None
        """
        return self._request("POST", url, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Internal method to make requests through Tor"""
        if self.status != TorConnectionStatus.READY:
            logger.warning("[TOR] Not connected - attempting connection")
            if not self.connect():
                return None

        # Set default timeout
        kwargs.setdefault("timeout", self.config.timeout)

        try:
            with self._lock:
                self._request_count += 1

            if method == "GET":
                response = self._session.get(url, **kwargs)
            elif method == "POST":
                response = self._session.post(url, **kwargs)
            else:
                raise ValueError(f"Unsupported method: {method}")

            return response

        except requests.exceptions.Timeout:
            logger.error(f"[TOR] Request timeout: {url}")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"[TOR] Connection error: {e}")
            # Try to reconnect
            self.reconnect()
            return None
        except Exception as e:
            logger.error(f"[TOR] Request failed: {e}")
            return None

    def fetch_onion(self, onion_url: str, retries: int = 3) -> Optional[str]:
        """
        Fetch content from a .onion site

        Args:
            onion_url: Full .onion URL
            retries: Number of retry attempts

        Returns:
            Page content as string or None
        """
        if not onion_url.endswith(".onion") and ".onion/" not in onion_url:
            logger.error("[TOR] Invalid onion URL")
            return None

        for attempt in range(retries):
            try:
                response = self.get(onion_url)
                if response and response.status_code == 200:
                    return response.text

                logger.warning(f"[TOR] Onion fetch attempt {attempt + 1} failed")

                # Rotate circuit between retries
                if attempt < retries - 1:
                    self.rotate_circuit()
                    time.sleep(5)

            except Exception as e:
                logger.error(f"[TOR] Onion fetch error: {e}")

        return None

    def get_current_ip(self) -> Optional[str]:
        """Get current Tor exit IP address"""
        try:
            response = self.get("https://check.torproject.org/api/ip")
            if response and response.status_code == 200:
                return response.json().get("IP")
        except:
            pass
        return None

    def get_status(self) -> Dict[str, Any]:
        """Get current client status"""
        status_data = {
            "status": self.status.value,
            "socks_proxy": f"{self.config.socks_host}:{self.config.socks_port}",
            "request_count": self._request_count,
            "last_circuit_change": self._last_circuit_change.isoformat(),
            "current_ip": None,
            "circuits": []
        }

        if self.status == TorConnectionStatus.READY:
            status_data["current_ip"] = self.get_current_ip()

            if self._circuit_manager:
                circuits = self._circuit_manager.get_circuits()
                status_data["circuits"] = [
                    {
                        "id": c.circuit_id,
                        "status": c.status,
                        "nodes": c.nodes,
                        "exit_node": c.exit_node
                    }
                    for c in circuits[:5]  # Limit to 5 circuits
                ]

        return status_data

    def check_health(self) -> Dict[str, Any]:
        """
        Comprehensive health check

        Returns:
            Dict with health status details
        """
        health = {
            "healthy": False,
            "tor_connection": False,
            "circuit_available": False,
            "latency_ms": None,
            "exit_ip": None,
            "error": None
        }

        try:
            start_time = time.time()

            # Check Tor connection
            if self._verify_tor_connection():
                health["tor_connection"] = True
                health["latency_ms"] = round((time.time() - start_time) * 1000, 2)
                health["exit_ip"] = self.get_current_ip()

            # Check circuit availability
            if self._circuit_manager:
                circuits = self._circuit_manager.get_circuits()
                health["circuit_available"] = len([c for c in circuits if c.status == "BUILT"]) > 0

            health["healthy"] = health["tor_connection"]

        except Exception as e:
            health["error"] = str(e)

        return health


# Convenience function for quick access
_tor_client: Optional[TorClient] = None

def get_tor_client() -> TorClient:
    """Get or create the global Tor client instance"""
    global _tor_client
    if _tor_client is None:
        _tor_client = TorClient()
    return _tor_client
