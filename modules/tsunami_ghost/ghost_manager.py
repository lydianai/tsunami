"""
GHOST Manager
=============

Main manager class for GHOST OSINT CRM.
Provides unified access to all GHOST functionality.

Based on GHOST-osint-crm by elm1nst3r (CC BY-NC-SA 4.0)
https://github.com/elm1nst3r/GHOST-osint-crm
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

from .db import GhostDatabase
from .entity_manager import EntityManager, Entity
from .case_manager import CaseManager, Case
from .relationship_graph import RelationshipManager, Relationship
from .wireless_intel import WirelessIntelManager, WirelessNetwork
from .kml_parser import WiGLEKMLParser
from .travel_tracker import TravelTracker

logger = logging.getLogger('tsunami.ghost')


class GhostManager:
    """
    Main manager for GHOST OSINT CRM.

    Provides unified access to:
    - Entity management (people, organizations, devices)
    - Case/investigation management
    - Relationship network visualization
    - Wireless network intelligence
    - Travel history tracking
    - OSINT data collection

    Usage:
        ghost = GhostManager()

        # Create a case
        case = ghost.cases.create(name="Operation Alpha")

        # Add entity
        person = ghost.entities.create(
            first_name="John",
            last_name="Doe",
            category="poi",
            case_id=case.id
        )

        # Add relationship
        ghost.relationships.create(
            source_entity_id=person.id,
            target_entity_id=other_person.id,
            relationship_type="business"
        )

        # Get network graph
        graph = ghost.relationships.get_network_graph(case_id=case.id)
    """

    _instance: Optional['GhostManager'] = None

    def __new__(cls, db_path: Optional[str] = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_path: Optional[str] = None):
        if self._initialized:
            return

        self.db = GhostDatabase(db_path)

        # Initialize sub-managers
        self.entities = EntityManager(self.db)
        self.cases = CaseManager(self.db)
        self.relationships = RelationshipManager(self.db)
        self.wireless = WirelessIntelManager(self.db)
        self.travel = TravelTracker(self.db)
        self.kml_parser = WiGLEKMLParser()

        self._initialized = True
        logger.info("[GHOST] OSINT CRM Manager initialized")

    # ==================== QUICK ACCESS METHODS ====================

    def create_person(
        self,
        first_name: str,
        last_name: Optional[str] = None,
        category: str = 'poi',
        case_id: Optional[int] = None,
        **kwargs
    ) -> Entity:
        """Quick method to create a person entity"""
        return self.entities.create(
            entity_type='person',
            first_name=first_name,
            last_name=last_name,
            category=category,
            case_id=case_id,
            **kwargs
        )

    def create_organization(
        self,
        name: str,
        category: str = 'poi',
        case_id: Optional[int] = None,
        **kwargs
    ) -> Entity:
        """Quick method to create an organization entity"""
        return self.entities.create(
            entity_type='organization',
            full_name=name,
            category=category,
            case_id=case_id,
            **kwargs
        )

    def create_case(
        self,
        name: str,
        case_type: str = 'investigation',
        **kwargs
    ) -> Case:
        """Quick method to create a case"""
        return self.cases.create(name=name, case_type=case_type, **kwargs)

    def link_entities(
        self,
        source_id: int,
        target_id: int,
        relationship_type: str,
        **kwargs
    ) -> Relationship:
        """Quick method to link two entities"""
        return self.relationships.create(
            source_entity_id=source_id,
            target_entity_id=target_id,
            relationship_type=relationship_type,
            **kwargs
        )

    # ==================== IMPORT METHODS ====================

    def import_wigle_kml(
        self,
        file_path: str,
        case_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Import WiGLE KML file.

        Args:
            file_path: Path to KML file
            case_id: Optional case to associate networks with

        Returns:
            Import summary with statistics
        """
        try:
            networks = self.kml_parser.parse_file(file_path)
            imported = 0

            for net in networks:
                if case_id:
                    net['case_id'] = case_id

                self.wireless.add_network(**net)
                imported += 1

            summary = self.kml_parser.get_summary()
            summary['imported'] = imported

            logger.info(f"[GHOST] Imported {imported} networks from {file_path}")
            return summary

        except Exception as e:
            logger.error(f"[GHOST] WiGLE import failed: {e}")
            return {'error': str(e), 'imported': 0}

    def import_from_sigint(self, case_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Import wireless networks from TSUNAMI SIGINT module.

        Args:
            case_id: Optional case to associate networks with

        Returns:
            Import summary
        """
        try:
            # Try to import from SIGINT
            from dalga_sigint import SigintDatabase
            sigint_db = SigintDatabase()

            # Get WiFi networks
            wifi_networks = sigint_db.get_all_wifi() if hasattr(sigint_db, 'get_all_wifi') else []

            imported = 0
            for net in wifi_networks:
                try:
                    net_data = {
                        'ssid': getattr(net, 'ssid', 'Unknown'),
                        'bssid': getattr(net, 'bssid', None),
                        'latitude': getattr(net, 'latitude', None) or getattr(net, 'lat', None),
                        'longitude': getattr(net, 'longitude', None) or getattr(net, 'lng', None),
                        'encryption': getattr(net, 'encryption', None) or getattr(net, 'security', 'Unknown'),
                        'signal_strength': getattr(net, 'signal_strength', None) or getattr(net, 'signal', None),
                        'frequency': getattr(net, 'frequency', None),
                        'channel': getattr(net, 'channel', None),
                        'import_source': 'sigint_scan',
                        'case_id': case_id
                    }
                    # Remove None values
                    net_data = {k: v for k, v in net_data.items() if v is not None}
                    self.wireless.add_network(**net_data)
                    imported += 1
                except Exception:
                    continue

            logger.info(f"[GHOST] Imported {imported} networks from SIGINT")
            return {'imported': imported, 'source': 'sigint'}

        except ImportError:
            logger.warning("[GHOST] SIGINT module not available")
            return {'error': 'SIGINT module not available', 'imported': 0}
        except Exception as e:
            logger.error(f"[GHOST] SIGINT import failed: {e}")
            return {'error': str(e), 'imported': 0}

    # ==================== EXPORT METHODS ====================

    def export_case(self, case_id: int) -> Dict[str, Any]:
        """
        Export all case data as JSON.

        Args:
            case_id: Case ID to export

        Returns:
            Dictionary with all case data
        """
        case = self.cases.get(case_id)
        if not case:
            return {'error': 'Case not found'}

        # Get all related data
        entities = self.cases.get_entities(case_id)
        networks = self.wireless.list(case_id=case_id)

        # Get relationships for case entities
        entity_ids = [e['id'] for e in entities]
        relationships = []
        for entity_id in entity_ids:
            rels = self.relationships.get_entity_relationships(entity_id)
            relationships.extend([r.to_dict() for r in rels])

        # Get travel history
        travel = []
        for entity_id in entity_ids:
            history = self.travel.get_history(entity_id)
            travel.extend([t.to_dict() for t in history])

        # Get OSINT findings
        osint = self.db.get_osint_findings(case_id=case_id)

        return {
            'case': case.to_dict(),
            'entities': entities,
            'relationships': relationships,
            'wireless_networks': [n.to_dict() for n in networks],
            'travel_history': travel,
            'osint_findings': osint,
            'exported_at': datetime.now().isoformat(),
            'version': '1.0'
        }

    # ==================== STATISTICS ====================

    def get_statistics(self) -> Dict[str, Any]:
        """Get overall GHOST statistics"""
        return self.db.get_statistics()

    def get_dashboard_data(self) -> Dict[str, Any]:
        """
        Get dashboard summary data.

        Returns statistics for UI dashboard display.
        """
        stats = self.get_statistics()

        # Get recent cases
        recent_cases, _ = self.db.get_cases(limit=5)

        # Get high-risk entities
        entities, _ = self.db.get_entities(limit=100)
        high_risk = [e for e in entities if e.get('risk_level') in ['high', 'critical']]

        return {
            'statistics': stats,
            'recent_cases': recent_cases[:5],
            'high_risk_entities': high_risk[:10],
            'generated_at': datetime.now().isoformat()
        }

    # ==================== SEARCH ====================

    def search(
        self,
        query: str,
        search_types: Optional[List[str]] = None,
        limit: int = 50
    ) -> Dict[str, Any]:
        """
        Global search across entities, cases, and networks.

        Args:
            query: Search query
            search_types: Types to search ('entities', 'cases', 'wireless')
            limit: Maximum results per type

        Returns:
            Dictionary with search results by type
        """
        results = {}

        if not search_types:
            search_types = ['entities', 'cases', 'wireless']

        if 'entities' in search_types:
            entities = self.entities.search(query, limit=limit)
            results['entities'] = [e.to_dict() for e in entities]

        if 'cases' in search_types:
            cases, _ = self.db.get_cases(limit=limit)
            results['cases'] = [
                c for c in cases
                if query.lower() in (c.get('name', '') or '').lower()
                or query.lower() in (c.get('description', '') or '').lower()
            ][:limit]

        if 'wireless' in search_types:
            networks = self.wireless.list(ssid=query, limit=limit)
            results['wireless'] = [n.to_dict() for n in networks]

        return results

    # ==================== MAP DATA ====================

    def get_map_data(
        self,
        case_id: Optional[int] = None,
        include_entities: bool = True,
        include_wireless: bool = True,
        include_travel: bool = True
    ) -> Dict[str, Any]:
        """
        Get all map visualization data.

        Args:
            case_id: Filter by case
            include_entities: Include entity locations
            include_wireless: Include wireless networks
            include_travel: Include travel paths

        Returns:
            Dictionary with markers, paths, and metadata
        """
        map_data = {
            'entity_markers': [],
            'wireless_markers': [],
            'travel_markers': [],
            'travel_paths': [],
            'relationship_lines': []
        }

        if include_entities:
            map_data['entity_markers'] = self.entities.get_map_markers(case_id=case_id)

        if include_wireless:
            map_data['wireless_markers'] = self.wireless.get_map_data(case_id=case_id)

        if include_travel:
            # Get entity IDs for case
            if case_id:
                entities = self.cases.get_entities(case_id)
                entity_ids = [e['id'] for e in entities]
            else:
                entities, _ = self.db.get_entities(limit=100)
                entity_ids = [e['id'] for e in entities]

            travel_data = self.travel.get_map_data(entity_ids=entity_ids)
            map_data['travel_markers'] = travel_data['markers']
            map_data['travel_paths'] = travel_data['paths']

        return map_data

    # ==================== GRAPH DATA ====================

    def get_graph_data(
        self,
        case_id: Optional[int] = None,
        entity_ids: Optional[List[int]] = None,
        relationship_types: Optional[List[str]] = None,
        min_strength: int = 0
    ) -> Dict[str, Any]:
        """
        Get relationship graph data for D3.js visualization.

        Args:
            case_id: Filter by case
            entity_ids: Filter by specific entities
            relationship_types: Filter by relationship types
            min_strength: Minimum relationship strength

        Returns:
            Dictionary with nodes and edges for D3.js
        """
        return self.relationships.get_network_graph(
            case_id=case_id,
            entity_ids=entity_ids,
            relationship_types=relationship_types,
            min_strength=min_strength
        )


# Singleton accessor
_ghost_manager: Optional[GhostManager] = None


def get_ghost_manager(db_path: Optional[str] = None) -> GhostManager:
    """
    Get or create the global GHOST manager instance.

    Args:
        db_path: Optional database path

    Returns:
        GhostManager instance
    """
    global _ghost_manager
    if _ghost_manager is None:
        _ghost_manager = GhostManager(db_path)
    return _ghost_manager
