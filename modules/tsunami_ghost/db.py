"""
GHOST Database Module
=====================

SQLite database operations for GHOST OSINT CRM.
Thread-safe with WAL mode for concurrent access.
"""

import sqlite3
import json
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager


class GhostDatabase:
    """
    SQLite database manager for GHOST CRM data.

    Thread-safe singleton with WAL mode.
    """

    _instance: Optional['GhostDatabase'] = None
    _lock = threading.Lock()

    def __new__(cls, db_path: Optional[str] = None):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_path: Optional[str] = None):
        if self._initialized:
            return

        if db_path is None:
            db_path = str(Path.home() / '.dalga' / 'ghost_crm.db')

        self._db_path = db_path
        self._local = threading.local()

        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Initialize schema
        self._init_schema()
        self._initialized = True

    @property
    def conn(self) -> sqlite3.Connection:
        """Get thread-local connection"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                timeout=30.0
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute('PRAGMA journal_mode=WAL')
            self._local.conn.execute('PRAGMA foreign_keys=ON')
        return self._local.conn

    @contextmanager
    def transaction(self):
        """Context manager for transactions"""
        try:
            yield self.conn
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise e

    def _init_schema(self):
        """Initialize database schema"""
        with self.transaction():
            cursor = self.conn.cursor()

            # Entities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ghost_entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL DEFAULT 'person',
                    first_name TEXT,
                    last_name TEXT,
                    full_name TEXT,
                    aliases TEXT DEFAULT '[]',
                    date_of_birth DATE,
                    category TEXT DEFAULT 'poi',
                    status TEXT DEFAULT 'active',
                    crm_status TEXT DEFAULT 'new',
                    risk_level TEXT DEFAULT 'unknown',
                    nationality TEXT,
                    profile_picture_url TEXT,
                    notes TEXT,
                    phone_numbers TEXT DEFAULT '[]',
                    email_addresses TEXT DEFAULT '[]',
                    social_media TEXT DEFAULT '{}',
                    physical_addresses TEXT DEFAULT '[]',
                    osint_data TEXT DEFAULT '[]',
                    attachments TEXT DEFAULT '[]',
                    custom_fields TEXT DEFAULT '{}',
                    case_id INTEGER,
                    parent_entity_id INTEGER,
                    created_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (case_id) REFERENCES ghost_cases(id) ON DELETE SET NULL,
                    FOREIGN KEY (parent_entity_id) REFERENCES ghost_entities(id) ON DELETE SET NULL
                )
            """)

            # Relationships table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ghost_relationships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_entity_id INTEGER NOT NULL,
                    target_entity_id INTEGER NOT NULL,
                    relationship_type TEXT NOT NULL,
                    relationship_subtype TEXT,
                    direction TEXT DEFAULT 'bidirectional',
                    strength INTEGER DEFAULT 50,
                    confidence INTEGER DEFAULT 50,
                    evidence TEXT DEFAULT '[]',
                    notes TEXT,
                    start_date DATE,
                    end_date DATE,
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (source_entity_id) REFERENCES ghost_entities(id) ON DELETE CASCADE,
                    FOREIGN KEY (target_entity_id) REFERENCES ghost_entities(id) ON DELETE CASCADE,
                    UNIQUE(source_entity_id, target_entity_id, relationship_type)
                )
            """)

            # Cases table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ghost_cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_number TEXT UNIQUE,
                    name TEXT NOT NULL,
                    case_type TEXT DEFAULT 'investigation',
                    status TEXT DEFAULT 'open',
                    priority INTEGER DEFAULT 3,
                    classification TEXT DEFAULT 'unclassified',
                    description TEXT,
                    objectives TEXT DEFAULT '[]',
                    scope TEXT,
                    methodology TEXT,
                    lead_analyst TEXT,
                    team_members TEXT DEFAULT '[]',
                    start_date DATE,
                    target_end_date DATE,
                    actual_end_date DATE,
                    tags TEXT DEFAULT '[]',
                    metadata TEXT DEFAULT '{}',
                    created_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Wireless networks table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ghost_wireless_networks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid TEXT NOT NULL,
                    bssid TEXT,
                    latitude REAL,
                    longitude REAL,
                    accuracy REAL,
                    encryption TEXT,
                    auth_mode TEXT,
                    signal_strength INTEGER,
                    frequency TEXT,
                    channel INTEGER,
                    network_type TEXT DEFAULT 'WIFI',
                    entity_id INTEGER,
                    case_id INTEGER,
                    association_type TEXT,
                    association_confidence INTEGER DEFAULT 50,
                    association_note TEXT,
                    import_source TEXT,
                    import_file TEXT,
                    password TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (entity_id) REFERENCES ghost_entities(id) ON DELETE SET NULL,
                    FOREIGN KEY (case_id) REFERENCES ghost_cases(id) ON DELETE SET NULL
                )
            """)

            # Travel history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ghost_travel_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id INTEGER NOT NULL,
                    location_type TEXT,
                    address TEXT,
                    city TEXT,
                    country TEXT,
                    latitude REAL,
                    longitude REAL,
                    arrival_date TIMESTAMP,
                    departure_date TIMESTAMP,
                    duration_days INTEGER,
                    purpose TEXT,
                    transportation_mode TEXT,
                    verified INTEGER DEFAULT 0,
                    evidence TEXT DEFAULT '[]',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (entity_id) REFERENCES ghost_entities(id) ON DELETE CASCADE
                )
            """)

            # OSINT findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ghost_osint_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id INTEGER,
                    case_id INTEGER,
                    finding_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    platform TEXT,
                    identifier TEXT,
                    url TEXT,
                    raw_data TEXT,
                    summary TEXT,
                    risk_indicators TEXT DEFAULT '[]',
                    confidence INTEGER DEFAULT 50,
                    verified INTEGER DEFAULT 0,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (entity_id) REFERENCES ghost_entities(id) ON DELETE SET NULL,
                    FOREIGN KEY (case_id) REFERENCES ghost_cases(id) ON DELETE SET NULL
                )
            """)

            # Audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ghost_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user TEXT,
                    action TEXT NOT NULL,
                    entity_type TEXT,
                    entity_id INTEGER,
                    old_data TEXT,
                    new_data TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_type ON ghost_entities(entity_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_category ON ghost_entities(category)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_case ON ghost_entities(case_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_relationships_source ON ghost_relationships(source_entity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_relationships_target ON ghost_relationships(target_entity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wireless_ssid ON ghost_wireless_networks(ssid)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wireless_bssid ON ghost_wireless_networks(bssid)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wireless_entity ON ghost_wireless_networks(entity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_travel_entity ON ghost_travel_history(entity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_osint_entity ON ghost_osint_findings(entity_id)")

    # ==================== ENTITY OPERATIONS ====================

    def create_entity(self, entity_data: Dict[str, Any]) -> int:
        """Create a new entity"""
        with self.transaction():
            cursor = self.conn.cursor()

            # Generate full_name if not provided
            if 'full_name' not in entity_data or not entity_data['full_name']:
                first = entity_data.get('first_name', '')
                last = entity_data.get('last_name', '')
                entity_data['full_name'] = f"{first} {last}".strip()

            # JSON encode list/dict fields
            json_fields = ['aliases', 'phone_numbers', 'email_addresses', 'social_media',
                           'physical_addresses', 'osint_data', 'attachments', 'custom_fields']
            for field in json_fields:
                if field in entity_data and not isinstance(entity_data[field], str):
                    entity_data[field] = json.dumps(entity_data[field])

            columns = ', '.join(entity_data.keys())
            placeholders = ', '.join(['?' for _ in entity_data])
            values = list(entity_data.values())

            cursor.execute(
                f"INSERT INTO ghost_entities ({columns}) VALUES ({placeholders})",
                values
            )
            return cursor.lastrowid

    def get_entity(self, entity_id: int) -> Optional[Dict[str, Any]]:
        """Get entity by ID"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM ghost_entities WHERE id = ?", (entity_id,))
        row = cursor.fetchone()
        if row:
            return self._row_to_dict(row)
        return None

    def get_entities(
        self,
        entity_type: Optional[str] = None,
        category: Optional[str] = None,
        case_id: Optional[int] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Get entities with filters"""
        cursor = self.conn.cursor()

        conditions = []
        params = []

        if entity_type:
            conditions.append("entity_type = ?")
            params.append(entity_type)
        if category:
            conditions.append("category = ?")
            params.append(category)
        if case_id:
            conditions.append("case_id = ?")
            params.append(case_id)
        if search:
            conditions.append("(full_name LIKE ? OR aliases LIKE ? OR notes LIKE ?)")
            search_term = f"%{search}%"
            params.extend([search_term, search_term, search_term])

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        # Get total count
        cursor.execute(f"SELECT COUNT(*) FROM ghost_entities{where_clause}", params)
        total = cursor.fetchone()[0]

        # Get paginated results
        cursor.execute(
            f"SELECT * FROM ghost_entities{where_clause} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        )
        entities = [self._row_to_dict(row) for row in cursor.fetchall()]

        return entities, total

    def update_entity(self, entity_id: int, entity_data: Dict[str, Any]) -> bool:
        """Update an entity"""
        with self.transaction():
            cursor = self.conn.cursor()

            # JSON encode list/dict fields
            json_fields = ['aliases', 'phone_numbers', 'email_addresses', 'social_media',
                           'physical_addresses', 'osint_data', 'attachments', 'custom_fields']
            for field in json_fields:
                if field in entity_data and not isinstance(entity_data[field], str):
                    entity_data[field] = json.dumps(entity_data[field])

            entity_data['updated_at'] = datetime.now().isoformat()

            set_clause = ', '.join([f"{k} = ?" for k in entity_data.keys()])
            values = list(entity_data.values()) + [entity_id]

            cursor.execute(
                f"UPDATE ghost_entities SET {set_clause} WHERE id = ?",
                values
            )
            return cursor.rowcount > 0

    def delete_entity(self, entity_id: int) -> bool:
        """Delete an entity"""
        with self.transaction():
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM ghost_entities WHERE id = ?", (entity_id,))
            return cursor.rowcount > 0

    # ==================== RELATIONSHIP OPERATIONS ====================

    def create_relationship(self, rel_data: Dict[str, Any]) -> int:
        """Create a relationship between entities"""
        with self.transaction():
            cursor = self.conn.cursor()

            if 'evidence' in rel_data and not isinstance(rel_data['evidence'], str):
                rel_data['evidence'] = json.dumps(rel_data['evidence'])

            columns = ', '.join(rel_data.keys())
            placeholders = ', '.join(['?' for _ in rel_data])
            values = list(rel_data.values())

            cursor.execute(
                f"INSERT OR REPLACE INTO ghost_relationships ({columns}) VALUES ({placeholders})",
                values
            )
            return cursor.lastrowid

    def get_relationships(
        self,
        entity_id: Optional[int] = None,
        relationship_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get relationships"""
        cursor = self.conn.cursor()

        conditions = []
        params = []

        if entity_id:
            conditions.append("(source_entity_id = ? OR target_entity_id = ?)")
            params.extend([entity_id, entity_id])
        if relationship_type:
            conditions.append("relationship_type = ?")
            params.append(relationship_type)

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        cursor.execute(f"SELECT * FROM ghost_relationships{where_clause}", params)
        return [self._row_to_dict(row) for row in cursor.fetchall()]

    def delete_relationship(self, rel_id: int) -> bool:
        """Delete a relationship"""
        with self.transaction():
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM ghost_relationships WHERE id = ?", (rel_id,))
            return cursor.rowcount > 0

    def get_relationship_graph(self, case_id: Optional[int] = None) -> Dict[str, Any]:
        """Get relationship graph data for D3 visualization"""
        cursor = self.conn.cursor()

        # Get entities
        if case_id:
            cursor.execute("""
                SELECT id, entity_type, full_name, category, risk_level
                FROM ghost_entities WHERE case_id = ?
            """, (case_id,))
        else:
            cursor.execute("""
                SELECT id, entity_type, full_name, category, risk_level
                FROM ghost_entities
            """)

        nodes = []
        for row in cursor.fetchall():
            nodes.append({
                'id': f"entity_{row['id']}",
                'entity_id': row['id'],
                'label': row['full_name'] or f"Entity {row['id']}",
                'type': row['entity_type'],
                'category': row['category'],
                'risk_level': row['risk_level']
            })

        # Get relationships
        entity_ids = [n['entity_id'] for n in nodes]
        if entity_ids:
            placeholders = ','.join(['?' for _ in entity_ids])
            cursor.execute(f"""
                SELECT * FROM ghost_relationships
                WHERE source_entity_id IN ({placeholders})
                OR target_entity_id IN ({placeholders})
            """, entity_ids + entity_ids)

            edges = []
            for row in cursor.fetchall():
                edges.append({
                    'id': f"rel_{row['id']}",
                    'source': f"entity_{row['source_entity_id']}",
                    'target': f"entity_{row['target_entity_id']}",
                    'type': row['relationship_type'],
                    'subtype': row['relationship_subtype'],
                    'strength': row['strength'],
                    'confidence': row['confidence']
                })
        else:
            edges = []

        return {'nodes': nodes, 'edges': edges}

    # ==================== CASE OPERATIONS ====================

    def create_case(self, case_data: Dict[str, Any]) -> int:
        """Create a new case"""
        with self.transaction():
            cursor = self.conn.cursor()

            # Generate case number if not provided
            if 'case_number' not in case_data or not case_data['case_number']:
                case_data['case_number'] = f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}"

            json_fields = ['objectives', 'team_members', 'tags', 'metadata']
            for field in json_fields:
                if field in case_data and not isinstance(case_data[field], str):
                    case_data[field] = json.dumps(case_data[field])

            columns = ', '.join(case_data.keys())
            placeholders = ', '.join(['?' for _ in case_data])
            values = list(case_data.values())

            cursor.execute(
                f"INSERT INTO ghost_cases ({columns}) VALUES ({placeholders})",
                values
            )
            return cursor.lastrowid

    def get_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        """Get case by ID"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM ghost_cases WHERE id = ?", (case_id,))
        row = cursor.fetchone()
        if row:
            return self._row_to_dict(row)
        return None

    def get_cases(
        self,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Get cases with filters"""
        cursor = self.conn.cursor()

        conditions = []
        params = []

        if status:
            conditions.append("status = ?")
            params.append(status)

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        cursor.execute(f"SELECT COUNT(*) FROM ghost_cases{where_clause}", params)
        total = cursor.fetchone()[0]

        cursor.execute(
            f"SELECT * FROM ghost_cases{where_clause} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        )
        cases = [self._row_to_dict(row) for row in cursor.fetchall()]

        return cases, total

    def update_case(self, case_id: int, case_data: Dict[str, Any]) -> bool:
        """Update a case"""
        with self.transaction():
            cursor = self.conn.cursor()

            json_fields = ['objectives', 'team_members', 'tags', 'metadata']
            for field in json_fields:
                if field in case_data and not isinstance(case_data[field], str):
                    case_data[field] = json.dumps(case_data[field])

            case_data['updated_at'] = datetime.now().isoformat()

            set_clause = ', '.join([f"{k} = ?" for k in case_data.keys()])
            values = list(case_data.values()) + [case_id]

            cursor.execute(
                f"UPDATE ghost_cases SET {set_clause} WHERE id = ?",
                values
            )
            return cursor.rowcount > 0

    def delete_case(self, case_id: int) -> bool:
        """Delete a case"""
        with self.transaction():
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM ghost_cases WHERE id = ?", (case_id,))
            return cursor.rowcount > 0

    # ==================== WIRELESS OPERATIONS ====================

    def add_wireless_network(self, network_data: Dict[str, Any]) -> int:
        """Add a wireless network"""
        with self.transaction():
            cursor = self.conn.cursor()

            columns = ', '.join(network_data.keys())
            placeholders = ', '.join(['?' for _ in network_data])
            values = list(network_data.values())

            cursor.execute(
                f"INSERT INTO ghost_wireless_networks ({columns}) VALUES ({placeholders})",
                values
            )
            return cursor.lastrowid

    def get_wireless_networks(
        self,
        entity_id: Optional[int] = None,
        case_id: Optional[int] = None,
        ssid: Optional[str] = None,
        limit: int = 500
    ) -> List[Dict[str, Any]]:
        """Get wireless networks"""
        cursor = self.conn.cursor()

        conditions = []
        params = []

        if entity_id:
            conditions.append("entity_id = ?")
            params.append(entity_id)
        if case_id:
            conditions.append("case_id = ?")
            params.append(case_id)
        if ssid:
            conditions.append("ssid LIKE ?")
            params.append(f"%{ssid}%")

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        cursor.execute(
            f"SELECT * FROM ghost_wireless_networks{where_clause} ORDER BY last_seen DESC LIMIT ?",
            params + [limit]
        )
        return [self._row_to_dict(row) for row in cursor.fetchall()]

    def associate_network_to_entity(
        self,
        network_id: int,
        entity_id: int,
        association_type: str = 'accessed',
        confidence: int = 50,
        note: Optional[str] = None
    ) -> bool:
        """Associate a wireless network with an entity"""
        return self.update_wireless_network(network_id, {
            'entity_id': entity_id,
            'association_type': association_type,
            'association_confidence': confidence,
            'association_note': note
        })

    def update_wireless_network(self, network_id: int, data: Dict[str, Any]) -> bool:
        """Update wireless network"""
        with self.transaction():
            cursor = self.conn.cursor()
            set_clause = ', '.join([f"{k} = ?" for k in data.keys()])
            values = list(data.values()) + [network_id]
            cursor.execute(
                f"UPDATE ghost_wireless_networks SET {set_clause} WHERE id = ?",
                values
            )
            return cursor.rowcount > 0

    # ==================== TRAVEL OPERATIONS ====================

    def add_travel_record(self, travel_data: Dict[str, Any]) -> int:
        """Add travel history record"""
        with self.transaction():
            cursor = self.conn.cursor()

            if 'evidence' in travel_data and not isinstance(travel_data['evidence'], str):
                travel_data['evidence'] = json.dumps(travel_data['evidence'])

            columns = ', '.join(travel_data.keys())
            placeholders = ', '.join(['?' for _ in travel_data])
            values = list(travel_data.values())

            cursor.execute(
                f"INSERT INTO ghost_travel_history ({columns}) VALUES ({placeholders})",
                values
            )
            return cursor.lastrowid

    def get_travel_history(self, entity_id: int) -> List[Dict[str, Any]]:
        """Get travel history for an entity"""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM ghost_travel_history WHERE entity_id = ? ORDER BY arrival_date DESC",
            (entity_id,)
        )
        return [self._row_to_dict(row) for row in cursor.fetchall()]

    # ==================== OSINT OPERATIONS ====================

    def add_osint_finding(self, finding_data: Dict[str, Any]) -> int:
        """Add OSINT finding"""
        with self.transaction():
            cursor = self.conn.cursor()

            json_fields = ['raw_data', 'risk_indicators']
            for field in json_fields:
                if field in finding_data and not isinstance(finding_data[field], str):
                    finding_data[field] = json.dumps(finding_data[field])

            columns = ', '.join(finding_data.keys())
            placeholders = ', '.join(['?' for _ in finding_data])
            values = list(finding_data.values())

            cursor.execute(
                f"INSERT INTO ghost_osint_findings ({columns}) VALUES ({placeholders})",
                values
            )
            return cursor.lastrowid

    def get_osint_findings(
        self,
        entity_id: Optional[int] = None,
        case_id: Optional[int] = None,
        finding_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get OSINT findings"""
        cursor = self.conn.cursor()

        conditions = []
        params = []

        if entity_id:
            conditions.append("entity_id = ?")
            params.append(entity_id)
        if case_id:
            conditions.append("case_id = ?")
            params.append(case_id)
        if finding_type:
            conditions.append("finding_type = ?")
            params.append(finding_type)

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        cursor.execute(
            f"SELECT * FROM ghost_osint_findings{where_clause} ORDER BY discovered_at DESC",
            params
        )
        return [self._row_to_dict(row) for row in cursor.fetchall()]

    # ==================== AUDIT OPERATIONS ====================

    def log_audit(
        self,
        action: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[int] = None,
        old_data: Optional[Dict] = None,
        new_data: Optional[Dict] = None,
        user: Optional[str] = None,
        ip_address: Optional[str] = None
    ):
        """Log an audit entry"""
        with self.transaction():
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO ghost_audit_log
                (user, action, entity_type, entity_id, old_data, new_data, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                user,
                action,
                entity_type,
                entity_id,
                json.dumps(old_data) if old_data else None,
                json.dumps(new_data) if new_data else None,
                ip_address
            ))

    # ==================== HELPERS ====================

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert row to dictionary with JSON parsing"""
        result = dict(row)

        # Parse JSON fields
        json_fields = ['aliases', 'phone_numbers', 'email_addresses', 'social_media',
                       'physical_addresses', 'osint_data', 'attachments', 'custom_fields',
                       'objectives', 'team_members', 'tags', 'metadata', 'evidence',
                       'raw_data', 'risk_indicators']

        for field in json_fields:
            if field in result and result[field]:
                try:
                    result[field] = json.loads(result[field])
                except (json.JSONDecodeError, TypeError):
                    pass

        return result

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        cursor = self.conn.cursor()

        stats = {}

        # Entity counts
        cursor.execute("SELECT entity_type, COUNT(*) FROM ghost_entities GROUP BY entity_type")
        stats['entities_by_type'] = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute("SELECT category, COUNT(*) FROM ghost_entities GROUP BY category")
        stats['entities_by_category'] = {row[0]: row[1] for row in cursor.fetchall()}

        # Case counts
        cursor.execute("SELECT status, COUNT(*) FROM ghost_cases GROUP BY status")
        stats['cases_by_status'] = {row[0]: row[1] for row in cursor.fetchall()}

        # Relationship counts
        cursor.execute("SELECT relationship_type, COUNT(*) FROM ghost_relationships GROUP BY relationship_type")
        stats['relationships_by_type'] = {row[0]: row[1] for row in cursor.fetchall()}

        # Wireless counts
        cursor.execute("SELECT COUNT(*) FROM ghost_wireless_networks")
        stats['total_wireless_networks'] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM ghost_wireless_networks WHERE entity_id IS NOT NULL")
        stats['associated_wireless_networks'] = cursor.fetchone()[0]

        return stats
