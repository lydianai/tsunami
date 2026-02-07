"""
GHOST Travel Tracker
====================

Entity travel history and movement pattern analysis.
"""

from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime, date
from enum import Enum


class LocationType(Enum):
    """Location types"""
    RESIDENCE = 'residence'
    WORK = 'work'
    VISITED = 'visited'
    TRANSIT = 'transit'
    HOTEL = 'hotel'
    MEETING = 'meeting'
    UNKNOWN = 'unknown'


class TransportMode(Enum):
    """Transportation modes"""
    AIR = 'air'
    LAND = 'land'
    SEA = 'sea'
    RAIL = 'rail'
    UNKNOWN = 'unknown'


class TravelPurpose(Enum):
    """Travel purposes"""
    BUSINESS = 'business'
    PERSONAL = 'personal'
    VACATION = 'vacation'
    MEETING = 'meeting'
    UNKNOWN = 'unknown'


@dataclass
class TravelRecord:
    """Travel history record"""
    id: Optional[int] = None
    entity_id: int = 0

    # Location
    location_type: str = 'visited'
    address: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    # Time
    arrival_date: Optional[datetime] = None
    departure_date: Optional[datetime] = None
    duration_days: Optional[int] = None

    # Details
    purpose: str = 'unknown'
    transportation_mode: str = 'unknown'
    verified: bool = False
    evidence: List[Dict[str, Any]] = None
    notes: Optional[str] = None

    created_at: Optional[datetime] = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []

        # Calculate duration if dates provided
        if self.arrival_date and self.departure_date and not self.duration_days:
            arr = self.arrival_date if isinstance(self.arrival_date, date) else datetime.fromisoformat(str(self.arrival_date)).date()
            dep = self.departure_date if isinstance(self.departure_date, date) else datetime.fromisoformat(str(self.departure_date)).date()
            self.duration_days = (dep - arr).days

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        for ts_field in ['arrival_date', 'departure_date', 'created_at']:
            if result.get(ts_field):
                val = result[ts_field]
                result[ts_field] = val.isoformat() if isinstance(val, (date, datetime)) else val
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TravelRecord':
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class TravelTracker:
    """
    Manager for entity travel history and movement analysis.

    Tracks locations, patterns, and generates travel timelines.
    """

    def __init__(self, db=None):
        from .db import GhostDatabase
        self.db = db or GhostDatabase()

    def add_travel(
        self,
        entity_id: int,
        address: Optional[str] = None,
        city: Optional[str] = None,
        country: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        arrival_date: Optional[str] = None,
        departure_date: Optional[str] = None,
        location_type: str = 'visited',
        purpose: str = 'unknown',
        transportation_mode: str = 'unknown',
        verified: bool = False,
        notes: Optional[str] = None
    ) -> TravelRecord:
        """
        Add travel history record.

        Args:
            entity_id: Entity ID
            address: Full address
            city: City name
            country: Country name
            latitude: GPS latitude
            longitude: GPS longitude
            arrival_date: Arrival date/time (ISO format)
            departure_date: Departure date/time (ISO format)
            location_type: Type of location
            purpose: Purpose of travel
            transportation_mode: Mode of transport
            verified: Whether verified
            notes: Additional notes

        Returns:
            Created TravelRecord
        """
        travel_data = {
            'entity_id': entity_id,
            'address': address,
            'city': city,
            'country': country,
            'latitude': latitude,
            'longitude': longitude,
            'arrival_date': arrival_date,
            'departure_date': departure_date,
            'location_type': location_type,
            'purpose': purpose,
            'transportation_mode': transportation_mode,
            'verified': 1 if verified else 0,
            'notes': notes
        }

        # Calculate duration
        if arrival_date and departure_date:
            try:
                arr = datetime.fromisoformat(arrival_date).date()
                dep = datetime.fromisoformat(departure_date).date()
                travel_data['duration_days'] = (dep - arr).days
            except ValueError:
                pass

        # Remove None values
        travel_data = {k: v for k, v in travel_data.items() if v is not None}

        travel_id = self.db.add_travel_record(travel_data)
        records = self.db.get_travel_history(entity_id)
        for rec in records:
            if rec['id'] == travel_id:
                return TravelRecord.from_dict(rec)
        return TravelRecord(**travel_data, id=travel_id)

    def get_history(self, entity_id: int) -> List[TravelRecord]:
        """
        Get travel history for an entity.

        Args:
            entity_id: Entity ID

        Returns:
            List of TravelRecord objects
        """
        records = self.db.get_travel_history(entity_id)
        return [TravelRecord.from_dict(r) for r in records]

    def get_timeline(self, entity_id: int) -> List[Dict[str, Any]]:
        """
        Get travel timeline for map visualization.

        Args:
            entity_id: Entity ID

        Returns:
            List of timeline points with coordinates
        """
        records = self.get_history(entity_id)

        timeline = []
        for rec in records:
            if rec.latitude and rec.longitude:
                timeline.append({
                    'id': rec.id,
                    'lat': rec.latitude,
                    'lng': rec.longitude,
                    'address': rec.address,
                    'city': rec.city,
                    'country': rec.country,
                    'arrival_date': rec.arrival_date,
                    'departure_date': rec.departure_date,
                    'duration_days': rec.duration_days,
                    'location_type': rec.location_type,
                    'purpose': rec.purpose
                })

        # Sort by arrival date
        timeline.sort(key=lambda x: x.get('arrival_date') or '')

        return timeline

    def get_map_data(
        self,
        entity_ids: Optional[List[int]] = None,
        case_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get travel data for map visualization.

        Returns markers and connection lines.

        Args:
            entity_ids: Filter by specific entities
            case_id: Filter by case

        Returns:
            Dictionary with markers and paths
        """
        # Get entity IDs if case specified
        if case_id and not entity_ids:
            entities, _ = self.db.get_entities(case_id=case_id, limit=1000)
            entity_ids = [e['id'] for e in entities]

        all_markers = []
        all_paths = []

        for entity_id in (entity_ids or []):
            timeline = self.get_timeline(entity_id)

            # Get entity info
            entity = self.db.get_entity(entity_id)
            entity_name = entity.get('full_name', f"Entity {entity_id}") if entity else f"Entity {entity_id}"

            # Create markers
            for point in timeline:
                all_markers.append({
                    'entity_id': entity_id,
                    'entity_name': entity_name,
                    **point
                })

            # Create path (connecting consecutive locations)
            if len(timeline) > 1:
                path_coords = []
                for point in timeline:
                    path_coords.append([point['lat'], point['lng']])

                all_paths.append({
                    'entity_id': entity_id,
                    'entity_name': entity_name,
                    'coordinates': path_coords,
                    'num_stops': len(path_coords)
                })

        return {
            'markers': all_markers,
            'paths': all_paths
        }

    def analyze_patterns(self, entity_id: int) -> Dict[str, Any]:
        """
        Analyze travel patterns for an entity.

        Args:
            entity_id: Entity ID

        Returns:
            Pattern analysis results
        """
        records = self.get_history(entity_id)

        if not records:
            return {'error': 'No travel records found'}

        analysis = {
            'total_trips': len(records),
            'countries_visited': set(),
            'cities_visited': set(),
            'total_days_traveling': 0,
            'by_purpose': {},
            'by_transport': {},
            'by_location_type': {},
            'date_range': {
                'earliest': None,
                'latest': None
            },
            'frequent_locations': [],
            'average_trip_duration': 0
        }

        location_counts = {}
        durations = []

        for rec in records:
            # Countries/Cities
            if rec.country:
                analysis['countries_visited'].add(rec.country)
            if rec.city:
                analysis['cities_visited'].add(rec.city)

            # Duration
            if rec.duration_days:
                analysis['total_days_traveling'] += rec.duration_days
                durations.append(rec.duration_days)

            # Counts by category
            purpose = rec.purpose or 'unknown'
            analysis['by_purpose'][purpose] = analysis['by_purpose'].get(purpose, 0) + 1

            transport = rec.transportation_mode or 'unknown'
            analysis['by_transport'][transport] = analysis['by_transport'].get(transport, 0) + 1

            loc_type = rec.location_type or 'unknown'
            analysis['by_location_type'][loc_type] = analysis['by_location_type'].get(loc_type, 0) + 1

            # Date range
            if rec.arrival_date:
                arr_str = str(rec.arrival_date)
                if not analysis['date_range']['earliest'] or arr_str < analysis['date_range']['earliest']:
                    analysis['date_range']['earliest'] = arr_str
                if not analysis['date_range']['latest'] or arr_str > analysis['date_range']['latest']:
                    analysis['date_range']['latest'] = arr_str

            # Location frequency
            location_key = f"{rec.city or 'Unknown'}, {rec.country or 'Unknown'}"
            location_counts[location_key] = location_counts.get(location_key, 0) + 1

        # Convert sets to lists
        analysis['countries_visited'] = list(analysis['countries_visited'])
        analysis['cities_visited'] = list(analysis['cities_visited'])

        # Calculate averages
        if durations:
            analysis['average_trip_duration'] = sum(durations) / len(durations)

        # Frequent locations
        sorted_locations = sorted(location_counts.items(), key=lambda x: x[1], reverse=True)
        analysis['frequent_locations'] = [
            {'location': loc, 'visits': count}
            for loc, count in sorted_locations[:10]
        ]

        return analysis

    def find_overlaps(
        self,
        entity_ids: List[int],
        time_threshold_days: int = 1,
        distance_threshold_km: float = 10.0
    ) -> List[Dict[str, Any]]:
        """
        Find location/time overlaps between entities.

        Useful for identifying meetings, associations, etc.

        Args:
            entity_ids: Entity IDs to compare
            time_threshold_days: Maximum days apart to consider overlap
            distance_threshold_km: Maximum distance to consider same location

        Returns:
            List of potential overlaps
        """
        import math

        overlaps = []

        # Get all travel records
        all_records = {}
        for entity_id in entity_ids:
            all_records[entity_id] = self.get_history(entity_id)

        # Compare each pair of entities
        for i, entity1_id in enumerate(entity_ids):
            for entity2_id in entity_ids[i+1:]:
                records1 = all_records[entity1_id]
                records2 = all_records[entity2_id]

                for rec1 in records1:
                    for rec2 in records2:
                        # Check location proximity
                        if rec1.latitude and rec1.longitude and rec2.latitude and rec2.longitude:
                            distance = self._haversine_distance(
                                rec1.latitude, rec1.longitude,
                                rec2.latitude, rec2.longitude
                            )

                            if distance > distance_threshold_km:
                                continue

                            # Check time overlap
                            time_overlap = self._check_time_overlap(
                                rec1.arrival_date, rec1.departure_date,
                                rec2.arrival_date, rec2.departure_date,
                                time_threshold_days
                            )

                            if time_overlap:
                                overlaps.append({
                                    'entity1_id': entity1_id,
                                    'entity2_id': entity2_id,
                                    'location': {
                                        'address': rec1.address or rec2.address,
                                        'city': rec1.city or rec2.city,
                                        'country': rec1.country or rec2.country,
                                        'lat': (rec1.latitude + rec2.latitude) / 2,
                                        'lng': (rec1.longitude + rec2.longitude) / 2
                                    },
                                    'distance_km': distance,
                                    'time_period': time_overlap,
                                    'confidence': self._calculate_overlap_confidence(distance, time_overlap)
                                })

        return overlaps

    def _haversine_distance(
        self,
        lat1: float, lon1: float,
        lat2: float, lon2: float
    ) -> float:
        """Calculate distance between two points in kilometers"""
        import math

        R = 6371  # Earth radius in km

        lat1, lon1 = math.radians(lat1), math.radians(lon1)
        lat2, lon2 = math.radians(lat2), math.radians(lon2)

        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))

        return R * c

    def _check_time_overlap(
        self,
        arr1, dep1,
        arr2, dep2,
        threshold_days: int
    ) -> Optional[Dict[str, str]]:
        """Check if two time periods overlap"""
        if not arr1 or not arr2:
            return None

        try:
            # Convert to dates
            arr1 = datetime.fromisoformat(str(arr1)).date() if arr1 else None
            dep1 = datetime.fromisoformat(str(dep1)).date() if dep1 else arr1
            arr2 = datetime.fromisoformat(str(arr2)).date() if arr2 else None
            dep2 = datetime.fromisoformat(str(dep2)).date() if dep2 else arr2

            if not arr1 or not arr2:
                return None

            # Check overlap
            from datetime import timedelta
            threshold = timedelta(days=threshold_days)

            # Expand date ranges by threshold
            start1 = arr1 - threshold
            end1 = (dep1 or arr1) + threshold
            start2 = arr2 - threshold
            end2 = (dep2 or arr2) + threshold

            # Check if ranges overlap
            if start1 <= end2 and start2 <= end1:
                overlap_start = max(arr1, arr2)
                overlap_end = min(dep1 or arr1, dep2 or arr2)

                return {
                    'start': overlap_start.isoformat(),
                    'end': overlap_end.isoformat()
                }

        except (ValueError, TypeError):
            pass

        return None

    def _calculate_overlap_confidence(
        self,
        distance_km: float,
        time_overlap: Dict[str, str]
    ) -> int:
        """Calculate confidence score for overlap"""
        confidence = 100

        # Distance penalty
        if distance_km > 5:
            confidence -= int((distance_km - 5) * 5)
        if distance_km > 1:
            confidence -= int(distance_km * 2)

        # Time overlap bonus
        try:
            start = datetime.fromisoformat(time_overlap['start']).date()
            end = datetime.fromisoformat(time_overlap['end']).date()
            days = (end - start).days

            if days > 0:
                confidence += min(days * 5, 20)
        except (ValueError, KeyError):
            pass

        return max(0, min(100, confidence))
