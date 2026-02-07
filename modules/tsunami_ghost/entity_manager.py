"""
GHOST Entity Manager
====================

Person, Organization, Device, and Account entity management.
"""

from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime, date

from .db import GhostDatabase
from .crypto import get_ghost_crypto


class EntityCategory(Enum):
    """Entity investigation categories"""
    SUSPECT = 'suspect'
    WITNESS = 'witness'
    POI = 'poi'  # Person of Interest
    ASSOCIATE = 'associate'
    VICTIM = 'victim'
    INFORMANT = 'informant'
    UNKNOWN = 'unknown'


class EntityStatus(Enum):
    """Entity status"""
    ACTIVE = 'active'
    ARCHIVED = 'archived'
    INVESTIGATING = 'investigating'
    CLEARED = 'cleared'
    DECEASED = 'deceased'


class EntityType(Enum):
    """Entity types"""
    PERSON = 'person'
    ORGANIZATION = 'organization'
    DEVICE = 'device'
    ACCOUNT = 'account'
    VEHICLE = 'vehicle'
    LOCATION = 'location'


class CRMStatus(Enum):
    """CRM workflow status"""
    NEW = 'new'
    ENGAGED = 'engaged'
    QUALIFIED = 'qualified'
    CONVERTED = 'converted'
    LOST = 'lost'


class RiskLevel(Enum):
    """Risk assessment level"""
    UNKNOWN = 'unknown'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


@dataclass
class Entity:
    """Entity data model"""
    id: Optional[int] = None
    entity_type: str = 'person'
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    full_name: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    date_of_birth: Optional[date] = None
    category: str = 'poi'
    status: str = 'active'
    crm_status: str = 'new'
    risk_level: str = 'unknown'
    nationality: Optional[str] = None
    profile_picture_url: Optional[str] = None
    notes: Optional[str] = None

    # Contact information
    phone_numbers: List[Dict[str, Any]] = field(default_factory=list)
    email_addresses: List[Dict[str, Any]] = field(default_factory=list)
    social_media: Dict[str, str] = field(default_factory=dict)
    physical_addresses: List[Dict[str, Any]] = field(default_factory=list)

    # OSINT data
    osint_data: List[Dict[str, Any]] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    # Relations
    case_id: Optional[int] = None
    parent_entity_id: Optional[int] = None

    # Meta
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        # Convert date objects
        if self.date_of_birth:
            result['date_of_birth'] = self.date_of_birth.isoformat() if isinstance(self.date_of_birth, date) else self.date_of_birth
        if self.created_at:
            result['created_at'] = self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at
        if self.updated_at:
            result['updated_at'] = self.updated_at.isoformat() if isinstance(self.updated_at, datetime) else self.updated_at
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Entity':
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class EntityManager:
    """
    Manager for GHOST entities (people, organizations, devices, accounts).

    Handles CRUD operations, search, and OSINT data management.
    """

    def __init__(self, db: Optional[GhostDatabase] = None):
        self.db = db or GhostDatabase()
        self.crypto = get_ghost_crypto()

    def create(
        self,
        entity_type: str = 'person',
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        category: str = 'poi',
        case_id: Optional[int] = None,
        created_by: Optional[str] = None,
        **kwargs
    ) -> Entity:
        """
        Create a new entity.

        Args:
            entity_type: Type of entity (person, organization, device, account)
            first_name: First name (for person)
            last_name: Last name (for person)
            category: Investigation category (suspect, witness, poi, etc.)
            case_id: Associated case ID
            created_by: Creator username
            **kwargs: Additional entity fields

        Returns:
            Created Entity object
        """
        entity_data = {
            'entity_type': entity_type,
            'first_name': first_name,
            'last_name': last_name,
            'full_name': f"{first_name or ''} {last_name or ''}".strip() or kwargs.get('full_name'),
            'category': category,
            'case_id': case_id,
            'created_by': created_by,
            **kwargs
        }

        # Remove None values
        entity_data = {k: v for k, v in entity_data.items() if v is not None}

        entity_id = self.db.create_entity(entity_data)
        return self.get(entity_id)

    def get(self, entity_id: int) -> Optional[Entity]:
        """
        Get entity by ID.

        Args:
            entity_id: Entity ID

        Returns:
            Entity object or None
        """
        data = self.db.get_entity(entity_id)
        if data:
            return Entity.from_dict(data)
        return None

    def list(
        self,
        entity_type: Optional[str] = None,
        category: Optional[str] = None,
        case_id: Optional[int] = None,
        search: Optional[str] = None,
        page: int = 1,
        per_page: int = 50
    ) -> Dict[str, Any]:
        """
        List entities with filters and pagination.

        Args:
            entity_type: Filter by entity type
            category: Filter by category
            case_id: Filter by case
            search: Search term
            page: Page number (1-indexed)
            per_page: Items per page

        Returns:
            Dictionary with 'entities' list and 'pagination' info
        """
        offset = (page - 1) * per_page
        entities, total = self.db.get_entities(
            entity_type=entity_type,
            category=category,
            case_id=case_id,
            search=search,
            limit=per_page,
            offset=offset
        )

        return {
            'entities': [Entity.from_dict(e) for e in entities],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'total_pages': (total + per_page - 1) // per_page
            }
        }

    def update(self, entity_id: int, **kwargs) -> Optional[Entity]:
        """
        Update an entity.

        Args:
            entity_id: Entity ID
            **kwargs: Fields to update

        Returns:
            Updated Entity or None
        """
        # Update full_name if first/last name changed
        if 'first_name' in kwargs or 'last_name' in kwargs:
            current = self.get(entity_id)
            if current:
                first = kwargs.get('first_name', current.first_name) or ''
                last = kwargs.get('last_name', current.last_name) or ''
                kwargs['full_name'] = f"{first} {last}".strip()

        if self.db.update_entity(entity_id, kwargs):
            return self.get(entity_id)
        return None

    def delete(self, entity_id: int) -> bool:
        """
        Delete an entity.

        Args:
            entity_id: Entity ID

        Returns:
            True if deleted
        """
        return self.db.delete_entity(entity_id)

    def add_phone(
        self,
        entity_id: int,
        number: str,
        phone_type: str = 'mobile',
        is_primary: bool = False,
        notes: Optional[str] = None
    ) -> Optional[Entity]:
        """Add phone number to entity"""
        entity = self.get(entity_id)
        if not entity:
            return None

        phone_entry = {
            'number': number,
            'type': phone_type,
            'is_primary': is_primary,
            'notes': notes,
            'added_at': datetime.now().isoformat()
        }

        phones = entity.phone_numbers or []
        phones.append(phone_entry)

        return self.update(entity_id, phone_numbers=phones)

    def add_email(
        self,
        entity_id: int,
        email: str,
        email_type: str = 'personal',
        is_primary: bool = False,
        verified: bool = False
    ) -> Optional[Entity]:
        """Add email address to entity"""
        entity = self.get(entity_id)
        if not entity:
            return None

        email_entry = {
            'email': email,
            'type': email_type,
            'is_primary': is_primary,
            'verified': verified,
            'added_at': datetime.now().isoformat()
        }

        emails = entity.email_addresses or []
        emails.append(email_entry)

        return self.update(entity_id, email_addresses=emails)

    def add_social_media(
        self,
        entity_id: int,
        platform: str,
        username: str,
        url: Optional[str] = None,
        verified: bool = False
    ) -> Optional[Entity]:
        """Add social media account to entity"""
        entity = self.get(entity_id)
        if not entity:
            return None

        social = entity.social_media or {}
        social[platform.lower()] = {
            'username': username,
            'url': url,
            'verified': verified,
            'added_at': datetime.now().isoformat()
        }

        return self.update(entity_id, social_media=social)

    def add_address(
        self,
        entity_id: int,
        address: str,
        city: Optional[str] = None,
        country: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        address_type: str = 'residence'
    ) -> Optional[Entity]:
        """Add physical address to entity"""
        entity = self.get(entity_id)
        if not entity:
            return None

        address_entry = {
            'address': address,
            'city': city,
            'country': country,
            'latitude': latitude,
            'longitude': longitude,
            'type': address_type,
            'added_at': datetime.now().isoformat()
        }

        addresses = entity.physical_addresses or []
        addresses.append(address_entry)

        return self.update(entity_id, physical_addresses=addresses)

    def add_osint_data(
        self,
        entity_id: int,
        source: str,
        data_type: str,
        data: Dict[str, Any],
        confidence: int = 50
    ) -> Optional[Entity]:
        """Add OSINT data to entity"""
        entity = self.get(entity_id)
        if not entity:
            return None

        osint_entry = {
            'source': source,
            'type': data_type,
            'data': data,
            'confidence': confidence,
            'collected_at': datetime.now().isoformat()
        }

        osint_data = entity.osint_data or []
        osint_data.append(osint_entry)

        return self.update(entity_id, osint_data=osint_data)

    def add_alias(self, entity_id: int, alias: str) -> Optional[Entity]:
        """Add alias to entity"""
        entity = self.get(entity_id)
        if not entity:
            return None

        aliases = entity.aliases or []
        if alias not in aliases:
            aliases.append(alias)

        return self.update(entity_id, aliases=aliases)

    def set_risk_level(
        self,
        entity_id: int,
        risk_level: str,
        reason: Optional[str] = None
    ) -> Optional[Entity]:
        """Set entity risk level"""
        entity = self.get(entity_id)
        if not entity:
            return None

        # Add risk assessment to notes if reason provided
        notes = entity.notes or ''
        if reason:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
            notes += f"\n[{timestamp}] Risk level set to {risk_level}: {reason}"

        return self.update(entity_id, risk_level=risk_level, notes=notes.strip())

    def search(
        self,
        query: str,
        entity_types: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        limit: int = 50
    ) -> List[Entity]:
        """
        Search entities by name, alias, phone, email, etc.

        Args:
            query: Search query
            entity_types: Filter by entity types
            categories: Filter by categories
            limit: Maximum results

        Returns:
            List of matching entities
        """
        # Use database search
        entities, _ = self.db.get_entities(search=query, limit=limit)

        # Filter by types if specified
        if entity_types:
            entities = [e for e in entities if e['entity_type'] in entity_types]

        # Filter by categories if specified
        if categories:
            entities = [e for e in entities if e['category'] in categories]

        return [Entity.from_dict(e) for e in entities]

    def get_case_entities(self, case_id: int) -> List[Entity]:
        """Get all entities for a case"""
        entities, _ = self.db.get_entities(case_id=case_id, limit=1000)
        return [Entity.from_dict(e) for e in entities]

    def link_to_case(self, entity_id: int, case_id: int) -> Optional[Entity]:
        """Link entity to a case"""
        return self.update(entity_id, case_id=case_id)

    def unlink_from_case(self, entity_id: int) -> Optional[Entity]:
        """Unlink entity from case"""
        return self.update(entity_id, case_id=None)

    def get_map_markers(
        self,
        case_id: Optional[int] = None,
        entity_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get entity location markers for map visualization.

        Returns:
            List of marker data with lat/lng
        """
        entities, _ = self.db.get_entities(
            case_id=case_id,
            entity_type=entity_type,
            limit=500
        )

        markers = []
        for entity in entities:
            addresses = entity.get('physical_addresses', [])
            for addr in addresses:
                if addr.get('latitude') and addr.get('longitude'):
                    markers.append({
                        'entity_id': entity['id'],
                        'lat': addr['latitude'],
                        'lng': addr['longitude'],
                        'label': entity.get('full_name', f"Entity {entity['id']}"),
                        'category': entity.get('category'),
                        'risk_level': entity.get('risk_level'),
                        'address_type': addr.get('type'),
                        'address': addr.get('address')
                    })

        return markers
