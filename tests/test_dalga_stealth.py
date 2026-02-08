"""
TSUNAMI - dalga_stealth.py Test Suite
Stealth/anonymization module tests
"""

import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock


class TestProxyNode:
    """ProxyNode dataclass testleri"""

    def test_creation(self):
        from dalga_stealth import ProxyNode
        node = ProxyNode(
            ip="192.168.1.1",
            port=9050,
            country="TR",
            type="socks5",
            latency=0.5,
            last_check=datetime.now()
        )
        assert node.ip == "192.168.1.1"
        assert node.port == 9050
        assert node.country == "TR"
        assert node.type == "socks5"
        assert node.active is True

    def test_default_active(self):
        from dalga_stealth import ProxyNode
        node = ProxyNode("1.1.1.1", 8080, "US", "http", 1.0, datetime.now())
        assert node.active is True

    def test_inactive_node(self):
        from dalga_stealth import ProxyNode
        node = ProxyNode("1.1.1.1", 8080, "US", "http", 1.0, datetime.now(), active=False)
        assert node.active is False


class TestTorCircuit:
    """TorCircuit dataclass testleri"""

    def test_creation(self):
        from dalga_stealth import TorCircuit
        circuit = TorCircuit(
            circuit_id="abc123",
            guard_node={"ip": "1.1.1.1"},
            middle_node={"ip": "2.2.2.2"},
            exit_node={"ip": "3.3.3.3"},
            created_at=datetime.now(),
            bandwidth=1000
        )
        assert circuit.circuit_id == "abc123"
        assert len(circuit.guard_node) > 0
        assert len(circuit.middle_node) > 0
        assert len(circuit.exit_node) > 0


class TestStealthRoute:
    """StealthRoute dataclass testleri"""

    def test_creation(self):
        from dalga_stealth import StealthRoute
        route = StealthRoute(
            route_id="route1",
            hops=[],
            total_latency=0.0,
            encryption_layers=3,
            geo_path=[]
        )
        assert route.route_id == "route1"
        assert route.encryption_layers == 3
