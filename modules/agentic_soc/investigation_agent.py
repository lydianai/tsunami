#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Agentic SOC - Investigation Agent v5.0
================================================================================

    Automated investigation capabilities:
    - Context gathering for alerts
    - Multi-source data querying
    - Investigation timeline building
    - Affected asset identification
    - Blast radius determination

================================================================================
"""

import asyncio
import logging
import uuid
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Callable, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import socket
import json

logger = logging.getLogger(__name__)


class InvestigationStatus(Enum):
    """Investigation status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ESCALATED = "escalated"


class DataSourceType(Enum):
    """Types of data sources"""
    SIEM = "siem"
    EDR = "edr"
    NETWORK = "network"
    IDENTITY = "identity"
    ASSET_INVENTORY = "asset_inventory"
    THREAT_INTEL = "threat_intel"
    DNS = "dns"
    FIREWALL = "firewall"
    PROXY = "proxy"
    EMAIL = "email"
    CLOUD = "cloud"


@dataclass
class InvestigationStep:
    """Single step in an investigation"""
    id: str
    name: str
    description: str
    data_source: DataSourceType
    query: str
    status: InvestigationStatus = InvestigationStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'data_source': self.data_source.value,
            'query': self.query,
            'status': self.status.value,
            'result': self.result,
            'error': self.error,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_ms': self.duration_ms
        }


@dataclass
class TimelineEvent:
    """Event in investigation timeline"""
    timestamp: datetime
    event_type: str
    description: str
    source: str
    severity: str
    data: Dict[str, Any] = field(default_factory=dict)
    related_entities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'description': self.description,
            'source': self.source,
            'severity': self.severity,
            'data': self.data,
            'related_entities': self.related_entities
        }


@dataclass
class AffectedAsset:
    """Asset affected by the incident"""
    id: str
    name: str
    asset_type: str  # server, workstation, network_device, user, etc.
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    criticality: str = "medium"  # critical, high, medium, low
    owner: Optional[str] = None
    department: Optional[str] = None
    compromise_level: str = "unknown"  # confirmed, suspected, unknown
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'asset_type': self.asset_type,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'criticality': self.criticality,
            'owner': self.owner,
            'department': self.department,
            'compromise_level': self.compromise_level,
            'evidence': self.evidence
        }


@dataclass
class BlastRadius:
    """Blast radius assessment"""
    directly_affected: List[AffectedAsset]
    potentially_affected: List[AffectedAsset]
    network_segments: List[str]
    user_accounts: List[str]
    services_impacted: List[str]
    data_at_risk: List[str]
    estimated_impact: str  # critical, high, medium, low
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            'directly_affected': [a.to_dict() for a in self.directly_affected],
            'potentially_affected': [a.to_dict() for a in self.potentially_affected],
            'network_segments': self.network_segments,
            'user_accounts': self.user_accounts,
            'services_impacted': self.services_impacted,
            'data_at_risk': self.data_at_risk,
            'estimated_impact': self.estimated_impact,
            'confidence': self.confidence
        }


@dataclass
class InvestigationResult:
    """Complete investigation result"""
    investigation_id: str
    alert_id: str
    status: InvestigationStatus
    started_at: datetime
    completed_at: Optional[datetime]
    duration_seconds: Optional[float]
    steps: List[InvestigationStep]
    timeline: List[TimelineEvent]
    affected_assets: List[AffectedAsset]
    blast_radius: Optional[BlastRadius]
    summary: str
    recommendations: List[str]
    confidence_score: float
    requires_escalation: bool
    escalation_reason: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'investigation_id': self.investigation_id,
            'alert_id': self.alert_id,
            'status': self.status.value,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds,
            'steps': [s.to_dict() for s in self.steps],
            'timeline': [e.to_dict() for e in self.timeline],
            'affected_assets': [a.to_dict() for a in self.affected_assets],
            'blast_radius': self.blast_radius.to_dict() if self.blast_radius else None,
            'summary': self.summary,
            'recommendations': self.recommendations,
            'confidence_score': self.confidence_score,
            'requires_escalation': self.requires_escalation,
            'escalation_reason': self.escalation_reason
        }


@dataclass
class Investigation:
    """Active investigation tracking"""
    id: str
    alert_id: str
    alert_data: Dict[str, Any]
    status: InvestigationStatus
    created_at: datetime
    steps: List[InvestigationStep] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    affected_assets: List[AffectedAsset] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)


class DataSourceConnector:
    """Base class for data source connectors"""

    def __init__(self, source_type: DataSourceType, config: Dict[str, Any] = None):
        self.source_type = source_type
        self.config = config or {}
        self.enabled = True

    async def query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute query against data source"""
        raise NotImplementedError

    def is_available(self) -> bool:
        """Check if data source is available"""
        return self.enabled


class SIEMConnector(DataSourceConnector):
    """SIEM data source connector"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(DataSourceType.SIEM, config)

    async def query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """Query SIEM for related events"""
        # Simulated SIEM query - in production, connect to actual SIEM
        ip = query_params.get('ip')
        username = query_params.get('username')
        hostname = query_params.get('hostname')
        time_range = query_params.get('time_range_hours', 24)

        # Generate realistic SIEM results
        events = []
        if ip:
            events.extend([
                {
                    'timestamp': (datetime.utcnow() - timedelta(hours=i)).isoformat(),
                    'event_type': 'authentication',
                    'source_ip': ip,
                    'action': 'login_success' if i % 3 != 0 else 'login_failure',
                    'user': f'user{i % 5}',
                    'hostname': f'workstation{i % 10}'
                }
                for i in range(min(10, time_range))
            ])

        if username:
            events.extend([
                {
                    'timestamp': (datetime.utcnow() - timedelta(hours=i * 2)).isoformat(),
                    'event_type': 'process_execution',
                    'username': username,
                    'process': ['cmd.exe', 'powershell.exe', 'chrome.exe'][i % 3],
                    'command_line': f'command_{i}'
                }
                for i in range(min(5, time_range // 2))
            ])

        return {
            'source': 'siem',
            'query': query_params,
            'total_events': len(events),
            'events': events,
            'query_time_ms': 150
        }


class EDRConnector(DataSourceConnector):
    """EDR data source connector"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(DataSourceType.EDR, config)

    async def query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """Query EDR for endpoint data"""
        hostname = query_params.get('hostname')
        ip = query_params.get('ip')
        process_name = query_params.get('process_name')

        # Simulated EDR results
        endpoint_data = {}

        if hostname or ip:
            endpoint_data = {
                'hostname': hostname or f'host-{ip}',
                'ip': ip or '10.0.0.100',
                'os': 'Windows 10 Enterprise',
                'last_seen': datetime.utcnow().isoformat(),
                'agent_version': '7.5.2',
                'isolation_status': 'not_isolated',
                'running_processes': [
                    {'name': 'chrome.exe', 'pid': 1234, 'user': 'DOMAIN\\user1'},
                    {'name': 'outlook.exe', 'pid': 5678, 'user': 'DOMAIN\\user1'},
                    {'name': 'svchost.exe', 'pid': 912, 'user': 'SYSTEM'}
                ],
                'network_connections': [
                    {'remote_ip': '8.8.8.8', 'remote_port': 443, 'process': 'chrome.exe'},
                    {'remote_ip': '40.97.164.146', 'remote_port': 443, 'process': 'outlook.exe'}
                ],
                'recent_detections': []
            }

        if process_name:
            endpoint_data['process_tree'] = {
                'name': process_name,
                'pid': 9999,
                'parent': 'explorer.exe',
                'children': ['child_proc.exe'],
                'command_line': f'{process_name} --suspicious-flag',
                'file_hash': 'abc123def456...'
            }

        return {
            'source': 'edr',
            'query': query_params,
            'endpoint_data': endpoint_data,
            'query_time_ms': 200
        }


class NetworkConnector(DataSourceConnector):
    """Network data source connector"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(DataSourceType.NETWORK, config)

    async def query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """Query network data"""
        ip = query_params.get('ip')
        port = query_params.get('port')

        # Simulated network data
        network_data = {
            'flows': [],
            'dns_queries': [],
            'connections': []
        }

        if ip:
            # Check if internal or external
            try:
                ip_obj = ipaddress.ip_address(ip)
                is_private = ip_obj.is_private
            except Exception:
                is_private = False

            if is_private:
                network_data['flows'] = [
                    {
                        'src_ip': ip,
                        'dst_ip': '10.0.0.1',
                        'src_port': 49152,
                        'dst_port': 443,
                        'protocol': 'TCP',
                        'bytes_sent': 1024,
                        'bytes_recv': 4096,
                        'timestamp': datetime.utcnow().isoformat()
                    }
                ]
            else:
                network_data['geo'] = {
                    'country': 'US',
                    'city': 'Seattle',
                    'asn': 16509,
                    'org': 'Amazon.com Inc.'
                }

            # DNS lookups
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                network_data['reverse_dns'] = hostname
            except Exception:
                network_data['reverse_dns'] = None

        return {
            'source': 'network',
            'query': query_params,
            'network_data': network_data,
            'query_time_ms': 100
        }


class ThreatIntelConnector(DataSourceConnector):
    """Threat intelligence data source connector"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(DataSourceType.THREAT_INTEL, config)

    async def query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """Query threat intelligence"""
        ioc = query_params.get('ioc')
        ioc_type = query_params.get('ioc_type', 'ip')

        # Simulated threat intel
        intel_data = {
            'found': False,
            'feeds_checked': ['alienvault', 'virustotal', 'abuse.ch'],
            'matches': []
        }

        # Simulate finding some IOCs
        if ioc and '.' in str(ioc):
            # Randomly mark some as malicious
            if hash(str(ioc)) % 5 == 0:
                intel_data['found'] = True
                intel_data['matches'] = [
                    {
                        'feed': 'abuse.ch',
                        'type': ioc_type,
                        'value': ioc,
                        'threat_type': 'malware',
                        'malware_family': 'Emotet',
                        'first_seen': (datetime.utcnow() - timedelta(days=30)).isoformat(),
                        'last_seen': datetime.utcnow().isoformat(),
                        'confidence': 85
                    }
                ]

        return {
            'source': 'threat_intel',
            'query': query_params,
            'intel_data': intel_data,
            'query_time_ms': 300
        }


class AssetInventoryConnector(DataSourceConnector):
    """Asset inventory data source connector"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(DataSourceType.ASSET_INVENTORY, config)

    async def query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """Query asset inventory"""
        ip = query_params.get('ip')
        hostname = query_params.get('hostname')

        # Simulated asset inventory
        asset_data = {}

        if ip or hostname:
            asset_data = {
                'found': True,
                'asset': {
                    'id': f'ASSET-{hash(str(ip or hostname)) % 10000}',
                    'hostname': hostname or f'host-{ip}',
                    'ip': ip or '10.0.0.100',
                    'type': 'workstation',
                    'os': 'Windows 10',
                    'owner': 'john.doe@company.com',
                    'department': 'Engineering',
                    'criticality': 'medium',
                    'location': 'Building A, Floor 3',
                    'tags': ['pci-scope', 'developer'],
                    'installed_software': ['Microsoft Office', 'Visual Studio', 'Chrome'],
                    'last_patched': (datetime.utcnow() - timedelta(days=7)).isoformat(),
                    'compliance_status': 'compliant'
                }
            }
        else:
            asset_data = {'found': False}

        return {
            'source': 'asset_inventory',
            'query': query_params,
            'asset_data': asset_data,
            'query_time_ms': 50
        }


class IdentityConnector(DataSourceConnector):
    """Identity/IAM data source connector"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(DataSourceType.IDENTITY, config)

    async def query(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """Query identity information"""
        username = query_params.get('username')
        email = query_params.get('email')

        # Simulated identity data
        identity_data = {}

        if username or email:
            identity_data = {
                'found': True,
                'user': {
                    'username': username or email.split('@')[0],
                    'email': email or f'{username}@company.com',
                    'full_name': 'John Doe',
                    'department': 'Engineering',
                    'title': 'Senior Developer',
                    'manager': 'jane.smith@company.com',
                    'groups': ['Developers', 'VPN Users', 'Remote Access'],
                    'privileged': False,
                    'mfa_enabled': True,
                    'last_login': datetime.utcnow().isoformat(),
                    'password_last_changed': (datetime.utcnow() - timedelta(days=45)).isoformat(),
                    'account_status': 'active',
                    'risk_score': 25
                }
            }
        else:
            identity_data = {'found': False}

        return {
            'source': 'identity',
            'query': query_params,
            'identity_data': identity_data,
            'query_time_ms': 80
        }


class InvestigationAgent:
    """Automated investigation agent"""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize investigation agent"""
        self.config = config or {}
        self.max_workers = self.config.get('max_workers', 10)
        self.timeout_seconds = self.config.get('timeout_seconds', 300)

        # Initialize data source connectors
        self.connectors: Dict[DataSourceType, DataSourceConnector] = {
            DataSourceType.SIEM: SIEMConnector(),
            DataSourceType.EDR: EDRConnector(),
            DataSourceType.NETWORK: NetworkConnector(),
            DataSourceType.THREAT_INTEL: ThreatIntelConnector(),
            DataSourceType.ASSET_INVENTORY: AssetInventoryConnector(),
            DataSourceType.IDENTITY: IdentityConnector()
        }

        # Active investigations
        self.investigations: Dict[str, Investigation] = {}

        # Thread pool for parallel queries
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)

    def _create_investigation_steps(self, alert_data: Dict[str, Any]) -> List[InvestigationStep]:
        """Create investigation steps based on alert data"""
        steps = []

        # Extract relevant entities from alert
        source_ip = alert_data.get('source_ip')
        dest_ip = alert_data.get('dest_ip')
        username = alert_data.get('username')
        hostname = alert_data.get('hostname')
        indicators = alert_data.get('indicators', [])

        # SIEM correlation
        if source_ip or username or hostname:
            steps.append(InvestigationStep(
                id=str(uuid.uuid4()),
                name='SIEM Correlation',
                description='Search for related events in SIEM',
                data_source=DataSourceType.SIEM,
                query=json.dumps({
                    'ip': source_ip,
                    'username': username,
                    'hostname': hostname,
                    'time_range_hours': 24
                })
            ))

        # EDR endpoint analysis
        if hostname or source_ip:
            steps.append(InvestigationStep(
                id=str(uuid.uuid4()),
                name='EDR Endpoint Analysis',
                description='Analyze endpoint data from EDR',
                data_source=DataSourceType.EDR,
                query=json.dumps({
                    'hostname': hostname,
                    'ip': source_ip
                })
            ))

        # Network analysis
        if source_ip or dest_ip:
            steps.append(InvestigationStep(
                id=str(uuid.uuid4()),
                name='Network Analysis',
                description='Analyze network traffic and connections',
                data_source=DataSourceType.NETWORK,
                query=json.dumps({
                    'ip': dest_ip or source_ip
                })
            ))

        # Threat intelligence lookup
        for ioc in indicators[:5]:  # Limit to 5 IOCs
            steps.append(InvestigationStep(
                id=str(uuid.uuid4()),
                name=f'Threat Intel: {ioc[:30]}',
                description=f'Check threat intelligence for {ioc}',
                data_source=DataSourceType.THREAT_INTEL,
                query=json.dumps({
                    'ioc': ioc,
                    'ioc_type': 'ip' if '.' in str(ioc) else 'hash'
                })
            ))

        # Asset lookup
        if hostname or source_ip:
            steps.append(InvestigationStep(
                id=str(uuid.uuid4()),
                name='Asset Inventory Lookup',
                description='Identify affected assets',
                data_source=DataSourceType.ASSET_INVENTORY,
                query=json.dumps({
                    'hostname': hostname,
                    'ip': source_ip
                })
            ))

        # Identity lookup
        if username:
            steps.append(InvestigationStep(
                id=str(uuid.uuid4()),
                name='Identity Analysis',
                description='Analyze user identity and permissions',
                data_source=DataSourceType.IDENTITY,
                query=json.dumps({
                    'username': username
                })
            ))

        return steps

    async def _execute_step(self, step: InvestigationStep) -> InvestigationStep:
        """Execute a single investigation step"""
        step.status = InvestigationStatus.IN_PROGRESS
        step.started_at = datetime.utcnow()

        try:
            connector = self.connectors.get(step.data_source)
            if not connector or not connector.is_available():
                step.status = InvestigationStatus.FAILED
                step.error = f"Data source {step.data_source.value} not available"
            else:
                query_params = json.loads(step.query)
                step.result = await connector.query(query_params)
                step.status = InvestigationStatus.COMPLETED

        except Exception as e:
            step.status = InvestigationStatus.FAILED
            step.error = str(e)
            logger.error(f"Step {step.name} failed: {e}")

        step.completed_at = datetime.utcnow()
        step.duration_ms = (step.completed_at - step.started_at).total_seconds() * 1000

        return step

    def _build_timeline(
        self,
        alert_data: Dict[str, Any],
        steps: List[InvestigationStep]
    ) -> List[TimelineEvent]:
        """Build investigation timeline from gathered data"""
        events = []

        # Add alert as first event
        events.append(TimelineEvent(
            timestamp=datetime.fromisoformat(alert_data.get('timestamp', datetime.utcnow().isoformat())),
            event_type='alert',
            description=alert_data.get('title', 'Security Alert'),
            source=alert_data.get('source', 'unknown'),
            severity=alert_data.get('severity', 'medium'),
            data=alert_data
        ))

        # Extract events from investigation steps
        for step in steps:
            if step.status == InvestigationStatus.COMPLETED and step.result:
                result_data = step.result

                # Extract SIEM events
                if step.data_source == DataSourceType.SIEM:
                    for event in result_data.get('events', []):
                        events.append(TimelineEvent(
                            timestamp=datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat())),
                            event_type=event.get('event_type', 'siem_event'),
                            description=event.get('action', 'Unknown action'),
                            source='siem',
                            severity='low',
                            data=event
                        ))

        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)

        return events

    def _identify_affected_assets(
        self,
        alert_data: Dict[str, Any],
        steps: List[InvestigationStep]
    ) -> List[AffectedAsset]:
        """Identify affected assets from investigation data"""
        assets = []
        seen_ids = set()

        for step in steps:
            if step.status == InvestigationStatus.COMPLETED and step.result:
                result_data = step.result

                # Extract from asset inventory
                if step.data_source == DataSourceType.ASSET_INVENTORY:
                    asset_data = result_data.get('asset_data', {})
                    if asset_data.get('found'):
                        asset_info = asset_data['asset']
                        asset_id = asset_info.get('id')

                        if asset_id not in seen_ids:
                            seen_ids.add(asset_id)
                            assets.append(AffectedAsset(
                                id=asset_id,
                                name=asset_info.get('hostname', 'Unknown'),
                                asset_type=asset_info.get('type', 'unknown'),
                                ip_address=asset_info.get('ip'),
                                hostname=asset_info.get('hostname'),
                                criticality=asset_info.get('criticality', 'medium'),
                                owner=asset_info.get('owner'),
                                department=asset_info.get('department'),
                                compromise_level='suspected',
                                evidence=[f"Alert: {alert_data.get('title', 'Unknown')}"]
                            ))

                # Extract from EDR
                if step.data_source == DataSourceType.EDR:
                    endpoint_data = result_data.get('endpoint_data', {})
                    if endpoint_data:
                        hostname = endpoint_data.get('hostname')
                        asset_id = f"EDR-{hostname}"

                        if asset_id not in seen_ids:
                            seen_ids.add(asset_id)
                            assets.append(AffectedAsset(
                                id=asset_id,
                                name=hostname,
                                asset_type='endpoint',
                                ip_address=endpoint_data.get('ip'),
                                hostname=hostname,
                                criticality='medium',
                                compromise_level='suspected',
                                evidence=[f"EDR investigation"]
                            ))

        return assets

    def _calculate_blast_radius(
        self,
        affected_assets: List[AffectedAsset],
        steps: List[InvestigationStep],
        alert_data: Dict[str, Any]
    ) -> BlastRadius:
        """Calculate the blast radius of the incident"""
        directly_affected = [a for a in affected_assets if a.compromise_level == 'confirmed']
        potentially_affected = [a for a in affected_assets if a.compromise_level == 'suspected']

        # Identify network segments
        network_segments = set()
        for asset in affected_assets:
            if asset.ip_address:
                try:
                    ip = ipaddress.ip_address(asset.ip_address)
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                    network_segments.add(str(network))
                except Exception:
                    pass

        # Identify user accounts
        user_accounts = set()
        for step in steps:
            if step.status == InvestigationStatus.COMPLETED and step.result:
                if step.data_source == DataSourceType.IDENTITY:
                    identity_data = step.result.get('identity_data', {})
                    if identity_data.get('found'):
                        user_accounts.add(identity_data['user'].get('username', ''))

                if step.data_source == DataSourceType.SIEM:
                    for event in step.result.get('events', []):
                        if event.get('user'):
                            user_accounts.add(event['user'])

        # Identify services impacted
        services_impacted = []
        for asset in affected_assets:
            if 'server' in asset.asset_type.lower():
                services_impacted.append(f"{asset.name} services")

        # Identify data at risk
        data_at_risk = []
        alert_category = alert_data.get('category', '')
        if 'exfiltration' in alert_category.lower():
            data_at_risk.append('Potentially sensitive data')
        if 'credential' in alert_category.lower():
            data_at_risk.append('User credentials')

        # Calculate estimated impact
        critical_count = sum(1 for a in affected_assets if a.criticality == 'critical')
        high_count = sum(1 for a in affected_assets if a.criticality == 'high')

        if critical_count > 0:
            estimated_impact = 'critical'
            confidence = 0.9
        elif high_count > 0 or len(affected_assets) > 5:
            estimated_impact = 'high'
            confidence = 0.8
        elif len(affected_assets) > 2:
            estimated_impact = 'medium'
            confidence = 0.7
        else:
            estimated_impact = 'low'
            confidence = 0.6

        return BlastRadius(
            directly_affected=directly_affected,
            potentially_affected=potentially_affected,
            network_segments=list(network_segments),
            user_accounts=list(user_accounts),
            services_impacted=services_impacted,
            data_at_risk=data_at_risk,
            estimated_impact=estimated_impact,
            confidence=confidence
        )

    def _generate_summary(
        self,
        alert_data: Dict[str, Any],
        steps: List[InvestigationStep],
        affected_assets: List[AffectedAsset],
        blast_radius: BlastRadius
    ) -> str:
        """Generate investigation summary"""
        completed_steps = [s for s in steps if s.status == InvestigationStatus.COMPLETED]
        failed_steps = [s for s in steps if s.status == InvestigationStatus.FAILED]

        summary_parts = [
            f"Investigation of alert '{alert_data.get('title', 'Unknown')}' completed.",
            f"Executed {len(completed_steps)}/{len(steps)} investigation steps.",
            f"Identified {len(affected_assets)} potentially affected assets.",
            f"Estimated impact: {blast_radius.estimated_impact.upper()}."
        ]

        if blast_radius.network_segments:
            summary_parts.append(
                f"Network segments involved: {', '.join(blast_radius.network_segments[:3])}."
            )

        if blast_radius.user_accounts:
            summary_parts.append(
                f"User accounts involved: {len(blast_radius.user_accounts)}."
            )

        if failed_steps:
            summary_parts.append(
                f"Note: {len(failed_steps)} investigation steps failed."
            )

        return ' '.join(summary_parts)

    def _generate_recommendations(
        self,
        alert_data: Dict[str, Any],
        steps: List[InvestigationStep],
        affected_assets: List[AffectedAsset],
        blast_radius: BlastRadius
    ) -> List[str]:
        """Generate investigation recommendations"""
        recommendations = []

        # Based on impact
        if blast_radius.estimated_impact == 'critical':
            recommendations.append("IMMEDIATE: Activate incident response team")
            recommendations.append("Consider isolating affected systems")

        # Based on affected assets
        critical_assets = [a for a in affected_assets if a.criticality == 'critical']
        if critical_assets:
            recommendations.append(
                f"Priority review for critical assets: {', '.join(a.name for a in critical_assets[:3])}"
            )

        # Based on user accounts
        if blast_radius.user_accounts:
            recommendations.append("Review and potentially reset affected user credentials")

        # Based on threat intel
        for step in steps:
            if step.data_source == DataSourceType.THREAT_INTEL:
                if step.result and step.result.get('intel_data', {}).get('found'):
                    recommendations.append(
                        "Block identified IOCs at network perimeter"
                    )
                    break

        # General recommendations
        recommendations.append("Preserve evidence for forensic analysis")
        recommendations.append("Document all findings and actions taken")

        return recommendations

    def _check_escalation(
        self,
        alert_data: Dict[str, Any],
        blast_radius: BlastRadius,
        steps: List[InvestigationStep]
    ) -> Tuple[bool, Optional[str]]:
        """Check if investigation requires escalation"""
        reasons = []

        # Critical impact
        if blast_radius.estimated_impact == 'critical':
            reasons.append("Critical impact detected")

        # Threat intel matches
        for step in steps:
            if step.data_source == DataSourceType.THREAT_INTEL:
                if step.result and step.result.get('intel_data', {}).get('found'):
                    matches = step.result['intel_data'].get('matches', [])
                    for match in matches:
                        if match.get('confidence', 0) > 80:
                            reasons.append(f"High-confidence threat intel match: {match.get('malware_family', 'Unknown')}")

        # Multiple critical assets
        if len(blast_radius.directly_affected) > 3:
            reasons.append("Multiple assets directly affected")

        if reasons:
            return True, '; '.join(reasons)

        return False, None

    async def investigate(self, alert_data: Dict[str, Any]) -> InvestigationResult:
        """Perform automated investigation of an alert"""
        investigation_id = str(uuid.uuid4())
        alert_id = alert_data.get('id', str(uuid.uuid4()))
        started_at = datetime.utcnow()

        logger.info(f"Starting investigation {investigation_id} for alert {alert_id}")

        # Create investigation
        investigation = Investigation(
            id=investigation_id,
            alert_id=alert_id,
            alert_data=alert_data,
            status=InvestigationStatus.IN_PROGRESS,
            created_at=started_at
        )
        self.investigations[investigation_id] = investigation

        # Create investigation steps
        steps = self._create_investigation_steps(alert_data)
        investigation.steps = steps

        # Execute steps in parallel
        tasks = [self._execute_step(step) for step in steps]
        completed_steps = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle any exceptions
        for i, result in enumerate(completed_steps):
            if isinstance(result, Exception):
                steps[i].status = InvestigationStatus.FAILED
                steps[i].error = str(result)

        # Build timeline
        timeline = self._build_timeline(alert_data, steps)
        investigation.timeline = timeline

        # Identify affected assets
        affected_assets = self._identify_affected_assets(alert_data, steps)
        investigation.affected_assets = affected_assets

        # Calculate blast radius
        blast_radius = self._calculate_blast_radius(affected_assets, steps, alert_data)

        # Generate summary and recommendations
        summary = self._generate_summary(alert_data, steps, affected_assets, blast_radius)
        recommendations = self._generate_recommendations(alert_data, steps, affected_assets, blast_radius)

        # Check escalation
        requires_escalation, escalation_reason = self._check_escalation(alert_data, blast_radius, steps)

        # Calculate confidence
        completed_count = sum(1 for s in steps if s.status == InvestigationStatus.COMPLETED)
        confidence_score = completed_count / len(steps) if steps else 0.0

        completed_at = datetime.utcnow()
        duration_seconds = (completed_at - started_at).total_seconds()

        # Update investigation status
        investigation.status = InvestigationStatus.COMPLETED

        result = InvestigationResult(
            investigation_id=investigation_id,
            alert_id=alert_id,
            status=InvestigationStatus.COMPLETED,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
            steps=steps,
            timeline=timeline,
            affected_assets=affected_assets,
            blast_radius=blast_radius,
            summary=summary,
            recommendations=recommendations,
            confidence_score=confidence_score,
            requires_escalation=requires_escalation,
            escalation_reason=escalation_reason
        )

        logger.info(
            f"Investigation {investigation_id} completed in {duration_seconds:.2f}s. "
            f"Escalation required: {requires_escalation}"
        )

        return result

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        """Get investigation by ID"""
        return self.investigations.get(investigation_id)

    def get_active_investigations(self) -> List[Investigation]:
        """Get all active investigations"""
        return [
            inv for inv in self.investigations.values()
            if inv.status == InvestigationStatus.IN_PROGRESS
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get investigation agent statistics"""
        statuses = {}
        for inv in self.investigations.values():
            status = inv.status.value
            statuses[status] = statuses.get(status, 0) + 1

        return {
            'total_investigations': len(self.investigations),
            'by_status': statuses,
            'available_data_sources': [
                ds.value for ds, conn in self.connectors.items()
                if conn.is_available()
            ],
            'max_workers': self.max_workers,
            'timeout_seconds': self.timeout_seconds
        }


# Global investigation agent instance
_investigation_agent: Optional[InvestigationAgent] = None


def get_investigation_agent() -> InvestigationAgent:
    """Get or create the global investigation agent instance"""
    global _investigation_agent
    if _investigation_agent is None:
        _investigation_agent = InvestigationAgent()
    return _investigation_agent
