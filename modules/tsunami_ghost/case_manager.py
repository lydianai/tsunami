"""
GHOST Case Manager
==================

Investigation and case management.
"""

from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime, date


class CaseStatus(Enum):
    """Case status"""
    OPEN = 'open'
    CLOSED = 'closed'
    SUSPENDED = 'suspended'
    ARCHIVED = 'archived'


class CasePriority(Enum):
    """Case priority (1 = highest)"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    MINIMAL = 5


class CaseType(Enum):
    """Case types"""
    INVESTIGATION = 'investigation'
    RESEARCH = 'research'
    THREAT_HUNT = 'threat_hunt'
    SURVEILLANCE = 'surveillance'
    INCIDENT_RESPONSE = 'incident_response'
    BACKGROUND_CHECK = 'background_check'


class Classification(Enum):
    """Classification levels"""
    UNCLASSIFIED = 'unclassified'
    CONFIDENTIAL = 'confidential'
    SECRET = 'secret'
    TOP_SECRET = 'top_secret'


@dataclass
class Case:
    """Case data model"""
    id: Optional[int] = None
    case_number: Optional[str] = None
    name: str = ''
    case_type: str = 'investigation'
    status: str = 'open'
    priority: int = 3
    classification: str = 'unclassified'
    description: Optional[str] = None
    objectives: List[str] = field(default_factory=list)
    scope: Optional[str] = None
    methodology: Optional[str] = None

    # Assignment
    lead_analyst: Optional[str] = None
    team_members: List[str] = field(default_factory=list)

    # Dates
    start_date: Optional[date] = None
    target_end_date: Optional[date] = None
    actual_end_date: Optional[date] = None

    # Meta
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        # Convert date objects
        for date_field in ['start_date', 'target_end_date', 'actual_end_date']:
            if result.get(date_field):
                val = result[date_field]
                result[date_field] = val.isoformat() if isinstance(val, (date, datetime)) else val
        if result.get('created_at'):
            val = result['created_at']
            result['created_at'] = val.isoformat() if isinstance(val, datetime) else val
        if result.get('updated_at'):
            val = result['updated_at']
            result['updated_at'] = val.isoformat() if isinstance(val, datetime) else val
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Case':
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class CaseManager:
    """
    Manager for GHOST investigation cases.

    Handles case lifecycle, entity assignment, and timeline tracking.
    """

    def __init__(self, db=None):
        from .db import GhostDatabase
        self.db = db or GhostDatabase()

    def create(
        self,
        name: str,
        case_type: str = 'investigation',
        priority: int = 3,
        lead_analyst: Optional[str] = None,
        description: Optional[str] = None,
        created_by: Optional[str] = None,
        **kwargs
    ) -> Case:
        """
        Create a new case.

        Args:
            name: Case name
            case_type: Type of case
            priority: Priority (1-5, 1=critical)
            lead_analyst: Lead analyst username
            description: Case description
            created_by: Creator username
            **kwargs: Additional case fields

        Returns:
            Created Case object
        """
        case_data = {
            'name': name,
            'case_type': case_type,
            'priority': priority,
            'lead_analyst': lead_analyst,
            'description': description,
            'created_by': created_by,
            'start_date': datetime.now().date().isoformat(),
            **kwargs
        }

        # Remove None values
        case_data = {k: v for k, v in case_data.items() if v is not None}

        case_id = self.db.create_case(case_data)
        return self.get(case_id)

    def get(self, case_id: int) -> Optional[Case]:
        """
        Get case by ID.

        Args:
            case_id: Case ID

        Returns:
            Case object or None
        """
        data = self.db.get_case(case_id)
        if data:
            return Case.from_dict(data)
        return None

    def get_by_number(self, case_number: str) -> Optional[Case]:
        """Get case by case number"""
        cases, _ = self.db.get_cases(limit=1000)
        for case in cases:
            if case.get('case_number') == case_number:
                return Case.from_dict(case)
        return None

    def list(
        self,
        status: Optional[str] = None,
        page: int = 1,
        per_page: int = 50
    ) -> Dict[str, Any]:
        """
        List cases with filters and pagination.

        Args:
            status: Filter by status
            page: Page number (1-indexed)
            per_page: Items per page

        Returns:
            Dictionary with 'cases' list and 'pagination' info
        """
        offset = (page - 1) * per_page
        cases, total = self.db.get_cases(status=status, limit=per_page, offset=offset)

        return {
            'cases': [Case.from_dict(c) for c in cases],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'total_pages': (total + per_page - 1) // per_page
            }
        }

    def update(self, case_id: int, **kwargs) -> Optional[Case]:
        """
        Update a case.

        Args:
            case_id: Case ID
            **kwargs: Fields to update

        Returns:
            Updated Case or None
        """
        if self.db.update_case(case_id, kwargs):
            return self.get(case_id)
        return None

    def delete(self, case_id: int) -> bool:
        """
        Delete a case.

        Args:
            case_id: Case ID

        Returns:
            True if deleted
        """
        return self.db.delete_case(case_id)

    def close(
        self,
        case_id: int,
        resolution: Optional[str] = None,
        final_notes: Optional[str] = None
    ) -> Optional[Case]:
        """
        Close a case.

        Args:
            case_id: Case ID
            resolution: Resolution summary
            final_notes: Final notes

        Returns:
            Updated Case or None
        """
        case = self.get(case_id)
        if not case:
            return None

        metadata = case.metadata or {}
        metadata['resolution'] = resolution
        metadata['final_notes'] = final_notes
        metadata['closed_at'] = datetime.now().isoformat()

        return self.update(
            case_id,
            status='closed',
            actual_end_date=datetime.now().date().isoformat(),
            metadata=metadata
        )

    def reopen(self, case_id: int, reason: str) -> Optional[Case]:
        """
        Reopen a closed case.

        Args:
            case_id: Case ID
            reason: Reason for reopening

        Returns:
            Updated Case or None
        """
        case = self.get(case_id)
        if not case:
            return None

        metadata = case.metadata or {}
        reopens = metadata.get('reopens', [])
        reopens.append({
            'reason': reason,
            'reopened_at': datetime.now().isoformat()
        })
        metadata['reopens'] = reopens

        return self.update(
            case_id,
            status='open',
            actual_end_date=None,
            metadata=metadata
        )

    def suspend(self, case_id: int, reason: str) -> Optional[Case]:
        """Suspend a case"""
        case = self.get(case_id)
        if not case:
            return None

        metadata = case.metadata or {}
        metadata['suspended_reason'] = reason
        metadata['suspended_at'] = datetime.now().isoformat()

        return self.update(case_id, status='suspended', metadata=metadata)

    def add_objective(self, case_id: int, objective: str) -> Optional[Case]:
        """Add objective to case"""
        case = self.get(case_id)
        if not case:
            return None

        objectives = case.objectives or []
        objectives.append(objective)

        return self.update(case_id, objectives=objectives)

    def add_team_member(self, case_id: int, username: str) -> Optional[Case]:
        """Add team member to case"""
        case = self.get(case_id)
        if not case:
            return None

        team = case.team_members or []
        if username not in team:
            team.append(username)

        return self.update(case_id, team_members=team)

    def remove_team_member(self, case_id: int, username: str) -> Optional[Case]:
        """Remove team member from case"""
        case = self.get(case_id)
        if not case:
            return None

        team = case.team_members or []
        if username in team:
            team.remove(username)

        return self.update(case_id, team_members=team)

    def add_tag(self, case_id: int, tag: str) -> Optional[Case]:
        """Add tag to case"""
        case = self.get(case_id)
        if not case:
            return None

        tags = case.tags or []
        if tag not in tags:
            tags.append(tag)

        return self.update(case_id, tags=tags)

    def get_entities(self, case_id: int) -> List[Dict[str, Any]]:
        """Get all entities linked to a case"""
        entities, _ = self.db.get_entities(case_id=case_id, limit=1000)
        return entities

    def get_entity_count(self, case_id: int) -> int:
        """Get count of entities in a case"""
        entities, total = self.db.get_entities(case_id=case_id, limit=1)
        return total

    def get_timeline(self, case_id: int) -> List[Dict[str, Any]]:
        """
        Get case timeline with all events.

        Returns chronological list of:
        - Case status changes
        - Entity additions
        - OSINT findings
        - Travel records
        - Notes/updates
        """
        timeline = []

        # Case creation
        case = self.get(case_id)
        if case:
            timeline.append({
                'type': 'case_created',
                'timestamp': case.created_at,
                'description': f"Case '{case.name}' created",
                'user': case.created_by
            })

        # Get entities and their OSINT data
        entities = self.get_entities(case_id)
        for entity in entities:
            # Entity creation
            timeline.append({
                'type': 'entity_added',
                'timestamp': entity.get('created_at'),
                'description': f"Entity '{entity.get('full_name')}' added",
                'entity_id': entity.get('id'),
                'user': entity.get('created_by')
            })

            # OSINT findings
            findings = self.db.get_osint_findings(entity_id=entity.get('id'))
            for finding in findings:
                timeline.append({
                    'type': 'osint_finding',
                    'timestamp': finding.get('discovered_at'),
                    'description': f"OSINT: {finding.get('finding_type')} from {finding.get('source')}",
                    'entity_id': entity.get('id'),
                    'finding_id': finding.get('id')
                })

            # Travel history
            travel = self.db.get_travel_history(entity.get('id'))
            for record in travel:
                timeline.append({
                    'type': 'travel_record',
                    'timestamp': record.get('arrival_date'),
                    'description': f"Travel: {entity.get('full_name')} at {record.get('address')}",
                    'entity_id': entity.get('id'),
                    'travel_id': record.get('id')
                })

        # Sort by timestamp
        timeline.sort(key=lambda x: x.get('timestamp') or '', reverse=True)

        return timeline

    def get_statistics(self, case_id: int) -> Dict[str, Any]:
        """Get case statistics"""
        case = self.get(case_id)
        if not case:
            return {}

        entities = self.get_entities(case_id)

        # Count entities by category
        category_counts = {}
        risk_counts = {}
        for entity in entities:
            cat = entity.get('category', 'unknown')
            category_counts[cat] = category_counts.get(cat, 0) + 1
            risk = entity.get('risk_level', 'unknown')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

        # Get OSINT findings count
        osint_count = 0
        for entity in entities:
            findings = self.db.get_osint_findings(entity_id=entity.get('id'))
            osint_count += len(findings)

        # Get wireless networks count
        networks = self.db.get_wireless_networks(case_id=case_id)

        return {
            'case_id': case_id,
            'case_name': case.name,
            'status': case.status,
            'priority': case.priority,
            'total_entities': len(entities),
            'entities_by_category': category_counts,
            'entities_by_risk': risk_counts,
            'osint_findings': osint_count,
            'wireless_networks': len(networks),
            'days_open': self._calculate_days_open(case)
        }

    def _calculate_days_open(self, case: Case) -> int:
        """Calculate days case has been open"""
        if not case.start_date:
            return 0

        start = case.start_date
        if isinstance(start, str):
            start = datetime.fromisoformat(start).date()

        if case.status == 'closed' and case.actual_end_date:
            end = case.actual_end_date
            if isinstance(end, str):
                end = datetime.fromisoformat(end).date()
        else:
            end = datetime.now().date()

        return (end - start).days
