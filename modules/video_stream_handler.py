#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Video Stream Handler
Palantir-style real-time video surveillance integration
Supports RTSP, HLS, WebRTC protocols
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class CameraSource:
    """
    Camera metadata and stream configuration
    Palantir-style camera source with real-time status
    """
    id: str
    name: str
    latitude: float
    longitude: float
    stream_url: str  # RTSP/HLS/WebRTC URL
    status: str  # online/offline/error
    type: str  # cikis_kamerasi/drone_kamerasi/guvenlik_kamerasi/trafik_kamerasi
    protocol: str  # rtsp/hls/webrtc
    quality: str = '1080p'  # 1080p/720p/480p/360p
    location_type: str = 'indoor'  # indoor/outdoor/mobile
    last_update: datetime = field(default_factory=datetime.now)
    description: str = ''
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['last_update'] = self.last_update.isoformat()
        return data

    def to_geojson(self) -> Dict[str, Any]:
        """Convert to GeoJSON format for Leaflet map"""
        return {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [self.longitude, self.latitude]
            },
            "properties": {
                "id": self.id,
                "name": self.name,
                "status": self.status,
                "type": self.type,
                "protocol": self.protocol,
                "quality": self.quality,
                "location_type": self.location_type,
                "description": self.description,
                "last_update": self.last_update.isoformat()
            }
        }


class VideoStreamManager:
    """
    Manages active video streams and camera sources
    Palantir-style centralized stream management
    """

    def __init__(self):
        self.cameras: Dict[str, CameraSource] = {}
        self.active_streams: Dict[str, Any] = {}
        self.stream_stats: Dict[str, Dict] = {}

        # Zoom-based camera limits (Palantir-style performance optimization)
        self.zoom_limits = {
            1: 5,    # Country view - 5 cameras
            2: 10,   # Regional view - 10 cameras
            3: 20,   # City view - 20 cameras
            4: 30,   # District view - 30 cameras
            5: 50,   # Neighborhood view - 50 cameras
            6: 100,  # Street view - 100 cameras
            7: 150,  # Building view - 150 cameras
            8: 200   # Detailed view - 200 cameras
        }

        # Initialize with sample Turkish cameras
        self._initialize_sample_cameras()

    def _initialize_sample_cameras(self):
        """
        Initialize with sample cameras from major Turkish cities
        Palantir-style multi-city coverage
        """
        sample_cameras = [
            {
                "id": "cam-istanbul-001",
                "name": "İstanbul Taksim Meydanı",
                "latitude": 41.0378,
                "longitude": 28.9770,
                "stream_url": "rtsp://example.com/istanbul-taksim.stream",
                "status": "online",
                "type": "guvenlik_kamerasi",
                "protocol": "rtsp",
                "quality": "1080p",
                "location_type": "outdoor",
                "description": "Taksim meydanı canlı güvenlik kamerası"
            },
            {
                "id": "cam-ankara-001",
                "name": "Ankara Kızılay Meydanı",
                "latitude": 39.9208,
                "longitude": 32.8541,
                "stream_url": "rtsp://example.com/ankara-kizilay.stream",
                "status": "online",
                "type": "trafik_kamerasi",
                "protocol": "rtsp",
                "quality": "720p",
                "location_type": "outdoor",
                "description": "Kızılay meydanı trafiğe izleme kamerası"
            },
            {
                "id": "cam-izmir-001",
                "name": "İzmir Konak Meydanı",
                "latitude": 38.4237,
                "longitude": 27.1428,
                "stream_url": "rtsp://example.com/izmir-konak.stream",
                "status": "online",
                "type": "guvenlik_kamerasi",
                "protocol": "rtsp",
                "quality": "1080p",
                "location_type": "outdoor",
                "description": "Konak meydanı tarihi yarımada canlı görüntü"
            },
            {
                "id": "cam-bursa-001",
                "name": "Bursa Ulu Cami",
                "latitude": 40.1885,
                "longitude": 29.0610,
                "stream_url": "rtsp://example.com/bursa-ulu.stream",
                "status": "online",
                "type": "guvenlik_kamerasi",
                "protocol": "rtsp",
                "quality": "720p",
                "location_type": "outdoor",
                "description": "Ulu Cami çevresi güvenlik kamerası"
            },
            {
                "id": "cam-drone-001",
                "name": "İstanbul Drone Gözetleme",
                "latitude": 41.0082,
                "longitude": 28.9784,
                "stream_url": "webrtc://example.com/drone-001.stream",
                "status": "online",
                "type": "drone_kamerasi",
                "protocol": "webrtc",
                "quality": "1080p",
                "location_type": "mobile",
                "description": "Havan izleme drone canlı akışı"
            }
        ]

        for cam_data in sample_cameras:
            camera = CameraSource(**cam_data)
            self.add_camera_source(camera)

        logger.info(f"Initialized {len(sample_cameras)} sample cameras")

    def add_camera_source(self, camera: CameraSource) -> bool:
        """
        Add new camera source to the system
        Returns True if successful, False otherwise
        """
        try:
            self.cameras[camera.id] = camera
            self.stream_stats[camera.id] = {
                "added_at": datetime.now().isoformat(),
                "requests_count": 0,
                "last_accessed": None
            }
            logger.info(f"Added camera: {camera.id} - {camera.name}")
            return True
        except Exception as e:
            logger.error(f"Error adding camera {camera.id}: {str(e)}")
            return False

    def remove_camera(self, camera_id: str) -> bool:
        """Remove camera from system"""
        if camera_id in self.cameras:
            del self.cameras[camera_id]
            if camera_id in self.stream_stats:
                del self.stream_stats[camera_id]
            logger.info(f"Removed camera: {camera_id}")
            return True
        return False

    def get_camera(self, camera_id: str) -> Optional[CameraSource]:
        """Get specific camera by ID"""
        return self.cameras.get(camera_id)

    def get_active_cameras(self, zoom_level: int = 6,
                          status_filter: Optional[str] = None) -> List[Dict]:
        """
        Get cameras filtered by zoom level (Palantir-style performance optimization)

        Args:
            zoom_level: Map zoom level (1-8)
            status_filter: Optional status filter ('online', 'offline', 'error')

        Returns:
            List of camera dictionaries
        """
        max_cameras = self.zoom_limits.get(zoom_level, 100)

        cameras = list(self.cameras.values())

        # Filter by status if specified
        if status_filter:
            cameras = [c for c in cameras if c.status == status_filter]

        # Sort by last update (newest first)
        cameras.sort(key=lambda x: x.last_update, reverse=True)

        # Limit by zoom level
        cameras = cameras[:max_cameras]

        # Update stream stats
        for camera in cameras:
            if camera.id in self.stream_stats:
                self.stream_stats[camera.id]["requests_count"] += 1
                self.stream_stats[camera.id]["last_accessed"] = datetime.now().isoformat()

        return [camera.to_dict() for camera in cameras]

    def get_camera_stream_url(self, camera_id: str) -> Optional[str]:
        """
        Get stream URL for specific camera
        Includes authentication token if needed
        """
        camera = self.cameras.get(camera_id)
        if camera:
            # In production, this would generate authenticated URL
            return camera.stream_url
        return None

    def get_cameras_by_region(self, lat: float, lon: float,
                              radius_km: int = 10) -> List[Dict]:
        """
        Get cameras within geographic radius
        Palantir-style regional filtering

        Args:
            lat: Center latitude
            lon: Center longitude
            radius_km: Search radius in kilometers

        Returns:
            List of cameras within radius
        """
        from math import radians, cos, sin, asin, sqrt, degrees

        def haversine_distance(lat1, lon1, lat2, lon2):
            """Calculate distance between two points in km"""
            lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
            dlat = lat2 - lat1
            dlon = lon2 - lon1
            a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
            c = 2 * asin(sqrt(a))
            return 6371 * c

        cameras_in_region = []

        for camera in self.cameras.values():
            distance = haversine_distance(lat, lon, camera.latitude, camera.longitude)
            if distance <= radius_km:
                cameras_in_region.append(camera.to_dict())

        return cameras_in_region

    def get_camera_statistics(self) -> Dict[str, Any]:
        """
        Get overall camera system statistics
        Palantir-style dashboard metrics
        """
        total_cameras = len(self.cameras)
        online_cameras = sum(1 for c in self.cameras.values() if c.status == 'online')
        offline_cameras = sum(1 for c in self.cameras.values() if c.status == 'offline')
        error_cameras = sum(1 for c in self.cameras.values() if c.status == 'error')

        cameras_by_type = {}
        for camera in self.cameras.values():
            cameras_by_type[camera.type] = cameras_by_type.get(camera.type, 0) + 1

        cameras_by_protocol = {}
        for camera in self.cameras.values():
            cameras_by_protocol[camera.protocol] = cameras_by_protocol.get(camera.protocol, 0) + 1

        return {
            "total_cameras": total_cameras,
            "online": online_cameras,
            "offline": offline_cameras,
            "error": error_cameras,
            "uptime_percentage": round((online_cameras / total_cameras * 100) if total_cameras > 0 else 0, 2),
            "by_type": cameras_by_type,
            "by_protocol": cameras_by_protocol,
            "total_requests": sum(stats.get("requests_count", 0) for stats in self.stream_stats.values())
        }

    def update_camera_status(self, camera_id: str, status: str) -> bool:
        """
        Update camera status
        Used for health checks and monitoring
        """
        camera = self.cameras.get(camera_id)
        if camera:
            camera.status = status
            camera.last_update = datetime.now()
            logger.info(f"Updated camera {camera_id} status to {status}")
            return True
        return False

    def get_camera_geojson(self, zoom_level: int = 6) -> Dict[str, Any]:
        """
        Get all cameras as GeoJSON FeatureCollection
        For direct Leaflet.js integration
        """
        cameras = self.get_active_cameras(zoom_level)

        features = []
        for camera_dict in cameras:
            camera = self.cameras.get(camera_dict['id'])
            if camera:
                features.append(camera.to_geojson())

        return {
            "type": "FeatureCollection",
            "features": features
        }


# Global singleton instance
_video_manager = None

def get_video_manager() -> VideoStreamManager:
    """Get or create global video stream manager instance"""
    global _video_manager
    if _video_manager is None:
        _video_manager = VideoStreamManager()
        logger.info("Created global VideoStreamManager instance")
    return _video_manager


# Export key functions for Flask routes
def add_camera_source(camera_data: Dict) -> bool:
    """Add camera from dictionary data"""
    camera = CameraSource(**camera_data)
    manager = get_video_manager()
    return manager.add_camera_source(camera)


def get_active_cameras(zoom_level: int = 6, status_filter: Optional[str] = None) -> List[Dict]:
    """Get active cameras filtered by zoom level"""
    manager = get_video_manager()
    return manager.get_active_cameras(zoom_level, status_filter)


def get_camera_geojson(zoom_level: int = 6) -> Dict[str, Any]:
    """Get cameras as GeoJSON for map display"""
    manager = get_video_manager()
    return manager.get_camera_geojson(zoom_level)


def get_camera_statistics() -> Dict[str, Any]:
    """Get camera system statistics"""
    manager = get_video_manager()
    return manager.get_camera_statistics()


def update_camera_status(camera_id: str, status: str) -> bool:
    """Update camera status"""
    manager = get_video_manager()
    return manager.update_camera_status(camera_id, status)
