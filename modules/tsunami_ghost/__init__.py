"""
TSUNAMI GHOST Module
====================

OSINT Investigation Management & CRM System

Based on GHOST-osint-crm by elm1nst3r (CC BY-NC-SA 4.0)
https://github.com/elm1nst3r/GHOST-osint-crm

Features:
- Entity Management (People, Organizations, Devices)
- Relationship Network Visualization
- Case/Investigation Management
- Wireless Network Intelligence (WiGLE KML Import)
- Travel History Tracking
- OSINT Data Collection
- Geographic Intelligence

Turkish Language Support:
- Full AI assistant integration
- Natural language commands
"""

__version__ = '1.0.0'
__author__ = 'TSUNAMI Team'
__license__ = 'CC BY-NC-SA 4.0 (based on elm1nst3r/GHOST-osint-crm)'

from .ghost_manager import (
    GhostManager,
    get_ghost_manager
)

from .entity_manager import (
    EntityManager,
    Entity,
    EntityCategory,
    EntityStatus
)

from .case_manager import (
    CaseManager,
    Case,
    CaseStatus,
    CasePriority
)

from .relationship_graph import (
    RelationshipManager,
    Relationship,
    RelationshipType
)

from .wireless_intel import (
    WirelessIntelManager,
    WirelessNetwork,
    NetworkEncryption
)

from .kml_parser import (
    WiGLEKMLParser,
    parse_wigle_kml
)

from .travel_tracker import (
    TravelTracker,
    TravelRecord
)

from .db import GhostDatabase

__all__ = [
    # Main Manager
    'GhostManager',
    'get_ghost_manager',

    # Entity
    'EntityManager',
    'Entity',
    'EntityCategory',
    'EntityStatus',

    # Case
    'CaseManager',
    'Case',
    'CaseStatus',
    'CasePriority',

    # Relationships
    'RelationshipManager',
    'Relationship',
    'RelationshipType',

    # Wireless
    'WirelessIntelManager',
    'WirelessNetwork',
    'NetworkEncryption',

    # KML
    'WiGLEKMLParser',
    'parse_wigle_kml',

    # Travel
    'TravelTracker',
    'TravelRecord',

    # Database
    'GhostDatabase',
]
