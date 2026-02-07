"""
GHOST Relationship Graph
========================

Entity relationship network management and D3.js visualization.
"""

from enum import Enum
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime


class RelationshipType(Enum):
    """Relationship types between entities"""
    FAMILY = 'family'
    BUSINESS = 'business'
    CRIMINAL = 'criminal'
    SOCIAL = 'social'
    COMMUNICATION = 'communication'
    FINANCIAL = 'financial'
    LOCATION = 'location'
    ORGANIZATION = 'organization'
    UNKNOWN = 'unknown'


class RelationshipSubtype(Enum):
    """Relationship subtypes"""
    # Family
    PARENT = 'parent'
    CHILD = 'child'
    SIBLING = 'sibling'
    SPOUSE = 'spouse'
    RELATIVE = 'relative'

    # Business
    EMPLOYER = 'employer'
    EMPLOYEE = 'employee'
    PARTNER = 'partner'
    INVESTOR = 'investor'
    CLIENT = 'client'
    VENDOR = 'vendor'

    # Criminal
    ACCOMPLICE = 'accomplice'
    SUSPECT = 'suspect'
    VICTIM = 'victim'
    WITNESS = 'witness'

    # Social
    FRIEND = 'friend'
    ACQUAINTANCE = 'acquaintance'
    NEIGHBOR = 'neighbor'

    # Communication
    CALLED = 'called'
    MESSAGED = 'messaged'
    EMAILED = 'emailed'

    # Other
    OWNS = 'owns'
    USES = 'uses'
    VISITS = 'visits'
    ASSOCIATED = 'associated'


@dataclass
class Relationship:
    """Relationship data model"""
    id: Optional[int] = None
    source_entity_id: int = 0
    target_entity_id: int = 0
    relationship_type: str = 'unknown'
    relationship_subtype: Optional[str] = None
    direction: str = 'bidirectional'  # unidirectional, bidirectional
    strength: int = 50  # 0-100
    confidence: int = 50  # 0-100
    evidence: List[Dict[str, Any]] = None
    notes: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    is_active: bool = True
    created_at: Optional[datetime] = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        if result.get('created_at'):
            result['created_at'] = result['created_at'].isoformat() if isinstance(result['created_at'], datetime) else result['created_at']
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Relationship':
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class RelationshipManager:
    """
    Manager for entity relationships and network graph visualization.

    Supports D3.js force-directed graph rendering.
    """

    def __init__(self, db=None):
        from .db import GhostDatabase
        self.db = db or GhostDatabase()

    def create(
        self,
        source_entity_id: int,
        target_entity_id: int,
        relationship_type: str,
        relationship_subtype: Optional[str] = None,
        direction: str = 'bidirectional',
        strength: int = 50,
        confidence: int = 50,
        evidence: Optional[List[Dict]] = None,
        notes: Optional[str] = None
    ) -> Relationship:
        """
        Create a relationship between two entities.

        Args:
            source_entity_id: Source entity ID
            target_entity_id: Target entity ID
            relationship_type: Type of relationship
            relationship_subtype: Subtype of relationship
            direction: 'unidirectional' or 'bidirectional'
            strength: Relationship strength (0-100)
            confidence: Confidence level (0-100)
            evidence: List of evidence items
            notes: Additional notes

        Returns:
            Created Relationship object
        """
        rel_data = {
            'source_entity_id': source_entity_id,
            'target_entity_id': target_entity_id,
            'relationship_type': relationship_type,
            'relationship_subtype': relationship_subtype,
            'direction': direction,
            'strength': strength,
            'confidence': confidence,
            'evidence': evidence or [],
            'notes': notes
        }

        rel_data = {k: v for k, v in rel_data.items() if v is not None}

        rel_id = self.db.create_relationship(rel_data)
        relationships = self.db.get_relationships()
        for rel in relationships:
            if rel['id'] == rel_id:
                return Relationship.from_dict(rel)
        return Relationship(**rel_data, id=rel_id)

    def get(self, rel_id: int) -> Optional[Relationship]:
        """Get relationship by ID"""
        relationships = self.db.get_relationships()
        for rel in relationships:
            if rel['id'] == rel_id:
                return Relationship.from_dict(rel)
        return None

    def delete(self, rel_id: int) -> bool:
        """Delete a relationship"""
        return self.db.delete_relationship(rel_id)

    def get_entity_relationships(self, entity_id: int) -> List[Relationship]:
        """Get all relationships for an entity"""
        relationships = self.db.get_relationships(entity_id=entity_id)
        return [Relationship.from_dict(r) for r in relationships]

    def get_by_type(self, relationship_type: str) -> List[Relationship]:
        """Get relationships by type"""
        relationships = self.db.get_relationships(relationship_type=relationship_type)
        return [Relationship.from_dict(r) for r in relationships]

    def add_evidence(
        self,
        rel_id: int,
        evidence_type: str,
        description: str,
        source: Optional[str] = None,
        url: Optional[str] = None
    ) -> Optional[Relationship]:
        """Add evidence to a relationship"""
        rel = self.get(rel_id)
        if not rel:
            return None

        evidence_item = {
            'type': evidence_type,
            'description': description,
            'source': source,
            'url': url,
            'added_at': datetime.now().isoformat()
        }

        evidence = rel.evidence or []
        evidence.append(evidence_item)

        # Update relationship with new evidence
        rel_data = {'evidence': evidence}
        self.db.create_relationship({
            'id': rel_id,
            **rel.to_dict(),
            **rel_data
        })

        return self.get(rel_id)

    def update_strength(self, rel_id: int, strength: int) -> Optional[Relationship]:
        """Update relationship strength"""
        rel = self.get(rel_id)
        if not rel:
            return None

        strength = max(0, min(100, strength))  # Clamp to 0-100

        self.db.create_relationship({
            **rel.to_dict(),
            'strength': strength
        })

        return self.get(rel_id)

    def get_network_graph(
        self,
        case_id: Optional[int] = None,
        entity_ids: Optional[List[int]] = None,
        relationship_types: Optional[List[str]] = None,
        min_strength: int = 0
    ) -> Dict[str, Any]:
        """
        Get network graph data for D3.js visualization.

        Args:
            case_id: Filter by case
            entity_ids: Filter by specific entities
            relationship_types: Filter by relationship types
            min_strength: Minimum relationship strength

        Returns:
            Dictionary with 'nodes' and 'edges' for D3.js
        """
        # Get base graph from database
        graph = self.db.get_relationship_graph(case_id=case_id)

        nodes = graph.get('nodes', [])
        edges = graph.get('edges', [])

        # Filter by entity IDs
        if entity_ids:
            entity_id_set = set(entity_ids)
            nodes = [n for n in nodes if n['entity_id'] in entity_id_set]
            valid_node_ids = set(n['id'] for n in nodes)
            edges = [e for e in edges if e['source'] in valid_node_ids and e['target'] in valid_node_ids]

        # Filter by relationship types
        if relationship_types:
            edges = [e for e in edges if e['type'] in relationship_types]

        # Filter by minimum strength
        if min_strength > 0:
            edges = [e for e in edges if e.get('strength', 0) >= min_strength]

        # Add styling information for D3
        for node in nodes:
            node['color'] = self._get_node_color(node.get('category'), node.get('risk_level'))
            node['size'] = self._get_node_size(node.get('risk_level'))

        for edge in edges:
            edge['color'] = self._get_edge_color(edge.get('type'))
            edge['width'] = max(1, (edge.get('strength', 50) / 25))

        return {
            'nodes': nodes,
            'edges': edges,
            'metadata': {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'generated_at': datetime.now().isoformat()
            }
        }

    def _get_node_color(self, category: Optional[str], risk_level: Optional[str]) -> str:
        """Get node color based on category and risk"""
        # Risk-based colors take priority
        risk_colors = {
            'critical': '#ff0000',
            'high': '#ff6600',
            'medium': '#ffcc00',
            'low': '#00cc00',
            'unknown': '#888888'
        }

        if risk_level and risk_level in risk_colors:
            return risk_colors[risk_level]

        # Category colors
        category_colors = {
            'suspect': '#ff3355',
            'witness': '#3399ff',
            'poi': '#ff9900',
            'associate': '#9933ff',
            'victim': '#00cc99',
            'informant': '#ffcc00'
        }

        return category_colors.get(category, '#666666')

    def _get_node_size(self, risk_level: Optional[str]) -> int:
        """Get node size based on risk level"""
        sizes = {
            'critical': 20,
            'high': 16,
            'medium': 12,
            'low': 10,
            'unknown': 8
        }
        return sizes.get(risk_level, 10)

    def _get_edge_color(self, relationship_type: Optional[str]) -> str:
        """Get edge color based on relationship type"""
        colors = {
            'family': '#ff6699',
            'business': '#3399ff',
            'criminal': '#ff3333',
            'social': '#66cc66',
            'communication': '#ffcc00',
            'financial': '#00cccc',
            'location': '#9966ff',
            'organization': '#ff9933'
        }
        return colors.get(relationship_type, '#999999')

    def find_path(
        self,
        source_entity_id: int,
        target_entity_id: int,
        max_depth: int = 5
    ) -> List[List[int]]:
        """
        Find connection paths between two entities.

        Uses BFS to find shortest paths.

        Args:
            source_entity_id: Starting entity
            target_entity_id: Target entity
            max_depth: Maximum path length

        Returns:
            List of paths (each path is a list of entity IDs)
        """
        from collections import deque

        # Build adjacency list
        all_relationships = self.db.get_relationships()
        adjacency = {}

        for rel in all_relationships:
            src = rel['source_entity_id']
            tgt = rel['target_entity_id']

            if src not in adjacency:
                adjacency[src] = []
            if tgt not in adjacency:
                adjacency[tgt] = []

            adjacency[src].append(tgt)
            if rel.get('direction') == 'bidirectional':
                adjacency[tgt].append(src)

        # BFS
        paths = []
        queue = deque([(source_entity_id, [source_entity_id])])
        visited = set()

        while queue:
            current, path = queue.popleft()

            if len(path) > max_depth:
                continue

            if current == target_entity_id:
                paths.append(path)
                continue

            if current in visited:
                continue

            visited.add(current)

            for neighbor in adjacency.get(current, []):
                if neighbor not in visited:
                    queue.append((neighbor, path + [neighbor]))

        return paths

    def get_clusters(self, min_cluster_size: int = 2) -> List[Dict[str, Any]]:
        """
        Find clusters of connected entities.

        Uses Union-Find algorithm.

        Args:
            min_cluster_size: Minimum entities in a cluster

        Returns:
            List of clusters with entity IDs
        """
        all_relationships = self.db.get_relationships()

        # Collect all entity IDs
        entity_ids = set()
        for rel in all_relationships:
            entity_ids.add(rel['source_entity_id'])
            entity_ids.add(rel['target_entity_id'])

        # Union-Find
        parent = {eid: eid for eid in entity_ids}

        def find(x):
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        # Process relationships
        for rel in all_relationships:
            union(rel['source_entity_id'], rel['target_entity_id'])

        # Group by cluster
        clusters = {}
        for eid in entity_ids:
            root = find(eid)
            if root not in clusters:
                clusters[root] = []
            clusters[root].append(eid)

        # Filter by minimum size and format
        result = []
        for i, (root, members) in enumerate(clusters.items()):
            if len(members) >= min_cluster_size:
                result.append({
                    'cluster_id': i,
                    'size': len(members),
                    'entity_ids': members
                })

        return sorted(result, key=lambda x: x['size'], reverse=True)

    def get_central_entities(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """
        Find most central entities (highest degree centrality).

        Args:
            top_n: Number of top entities to return

        Returns:
            List of entities with centrality scores
        """
        all_relationships = self.db.get_relationships()

        # Count connections per entity
        degree = {}
        for rel in all_relationships:
            src = rel['source_entity_id']
            tgt = rel['target_entity_id']

            degree[src] = degree.get(src, 0) + 1
            if rel.get('direction') == 'bidirectional':
                degree[tgt] = degree.get(tgt, 0) + 1

        # Sort by degree
        sorted_entities = sorted(degree.items(), key=lambda x: x[1], reverse=True)[:top_n]

        # Get entity details
        result = []
        for entity_id, connections in sorted_entities:
            entity_data = self.db.get_entity(entity_id)
            if entity_data:
                result.append({
                    'entity_id': entity_id,
                    'full_name': entity_data.get('full_name'),
                    'category': entity_data.get('category'),
                    'connections': connections,
                    'centrality_score': connections
                })

        return result
