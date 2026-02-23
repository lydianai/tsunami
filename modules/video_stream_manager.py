#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Video Stream Manager - FAZ 5
Palantir-style real-time video surveillance integration
Supports RTSP, HLS, WebRTC, HTTP protocols
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from enum import Enum
import asyncio
import json
import logging
import base64
import hashlib
from threading import Thread, Lock
import time

logger = logging.getLogger(__name__)


class StreamProtocol(Enum):
    """Video streaming protocols supported"""
    RTSP = "rtsp"
    HLS = "hls"
    WEBRTC = "webrtc"
    HTTP = "http"
    MJPEG = "mjpeg"


class StreamStatus(Enum):
    """Stream status states"""
    ONLINE = "online"
    OFFLINE = "offline"
    CONNECTING = "connecting"
    ERROR = "error"
    RECORDING = "recording"


class StreamQuality(Enum):
    """Video quality levels"""
    LOW_360P = "360p"
    MEDIUM_480P = "480p"
    HIGH_720P = "720p"
    FULL_HD_1080P = "1080p"
    ULTRA_HD_4K = "4k"


@dataclass
class VideoSource:
    """
    Video source metadata and stream configuration
    Palantir-style comprehensive video source
    """
    source_id: str
    name: str
    location: str  # City, district
    latitude: float
    longitude: float
    stream_url: str
    protocol_type: StreamProtocol
    status: StreamStatus = StreamStatus.OFFLINE
    quality: StreamQuality = StreamQuality.FULL_HD_1080P
    thumbnail: Optional[str] = None  # Base64 encoded thumbnail
    last_update: datetime = field(default_factory=datetime.now)
    last_connected: Optional[datetime] = None
    bitrate: int = 5000  # kbps
    fps: int = 30
    audio_enabled: bool = True
    recording_enabled: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3
    health_check_interval: int = 30  # seconds

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['protocol_type'] = self.protocol_type.value
        data['status'] = self.status.value
        data['quality'] = self.quality.value
        data['last_update'] = self.last_update.isoformat()
        data['last_connected'] = self.last_connected.isoformat() if self.last_connected else None
        return data

    def to_geojson(self) -> Dict[str, Any]:
        """Convert to GeoJSON format for Leaflet map"""
        status_colors = {
            StreamStatus.ONLINE: "#00ff88",
            StreamStatus.OFFLINE: "#ff3355",
            StreamStatus.CONNECTING: "#ffaa00",
            StreamStatus.ERROR: "#ff0055",
            StreamStatus.RECORDING: "#00b4ff"
        }

        return {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [self.longitude, self.latitude]
            },
            "properties": {
                "source_id": self.source_id,
                "name": self.name,
                "location": self.location,
                "status": self.status.value,
                "status_color": status_colors.get(self.status, "#888888"),
                "protocol": self.protocol_type.value,
                "quality": self.quality.value,
                "bitrate": self.bitrate,
                "fps": self.fps,
                "thumbnail": self.thumbnail,
                "audio_enabled": self.audio_enabled,
                "recording_enabled": self.recording_enabled,
                "last_update": self.last_update.isoformat()
            }
        }


class RTSPHandler:
    """RTSP protocol handler for IP cameras"""

    def __init__(self):
        self.active_connections: Dict[str, Any] = {}

    async def connect(self, url: str, timeout: int = 10) -> bool:
        """
        Connect to RTSP stream
        Note: In production, use opencv or av (PyAV) for actual RTSP handling
        """
        try:
            # Simulate connection check
            logger.info(f"RTSP: Connecting to {url}")
            await asyncio.sleep(0.5)  # Simulate connection delay
            return True
        except Exception as e:
            logger.error(f"RTSP connection error: {e}")
            return False

    def extract_frame(self, url: str) -> Optional[str]:
        """
        Extract single frame as thumbnail (base64)
        Note: In production, use OpenCV:
        import cv2
        cap = cv2.VideoCapture(url)
        ret, frame = cap.read()
        _, buffer = cv2.imencode('.jpg', frame)
        return base64.b64encode(buffer).decode()
        """
        # Generate simulated thumbnail
        placeholder = f"data:image/svg+xml;base64,{self._generate_placeholder_svg()}"
        return placeholder

    def _generate_placeholder_svg(self) -> str:
        """Generate placeholder SVG thumbnail"""
        svg = """
        <svg width="320" height="180" xmlns="http://www.w3.org/2000/svg">
            <rect width="320" height="180" fill="#1a1a2e"/>
            <text x="160" y="90" text-anchor="middle" fill="#00b4ff" font-family="Arial" font-size="24">📹 LIVE</text>
        </svg>
        """
        return base64.b64encode(svg.encode()).decode()


class HLSHandler:
    """HLS (HTTP Live Streaming) protocol handler"""

    def __init__(self):
        self.active_playlists: Dict[str, List[str]] = {}

    async def parse_playlist(self, url: str) -> List[str]:
        """
        Parse .m3u8 playlist and return segment URLs
        Note: In production, use m3u8 library
        """
        try:
            logger.info(f"HLS: Parsing playlist {url}")
            # Simulate playlist parsing
            segments = [f"{url}/segment_{i}.ts" for i in range(10)]
            return segments
        except Exception as e:
            logger.error(f"HLS playlist error: {e}")
            return []

    async def get_stream_info(self, url: str) -> Dict[str, Any]:
        """Get HLS stream information"""
        return {
            "protocol": "hls",
            "playlist_url": url,
            "segments": await self.parse_playlist(url),
            "target_duration": 10,
            "version": 3
        }


class WebRTCHandler:
    """WebRTC protocol handler for real-time streaming"""

    def __init__(self):
        self.peer_connections: Dict[str, Any] = {}

    async def create_offer(self, source_id: str) -> Optional[str]:
        """
        Create SDP offer for WebRTC connection
        Note: In production, use aiortc
        """
        try:
            logger.info(f"WebRTC: Creating offer for {source_id}")
            # Simulate SDP offer
            offer = f"v=0\r\no=- {int(time.time())} 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
            return offer
        except Exception as e:
            logger.error(f"WebRTC offer error: {e}")
            return None

    async def handle_answer(self, source_id: str, answer: str) -> bool:
        """Handle SDP answer from remote peer"""
        logger.info(f"WebRTC: Handling answer for {source_id}")
        return True

    async def add_ice_candidate(self, source_id: str, candidate: str) -> bool:
        """Add ICE candidate for connection establishment"""
        logger.debug(f"WebRTC: Adding ICE candidate for {source_id}")
        return True


class VideoStreamManager:
    """
    Manages real-time video streams from multiple sources
    Palantir-style centralized stream management with health monitoring
    """

    def __init__(self):
        self.sources: Dict[str, VideoSource] = {}
        self.active_streams: Dict[str, Any] = {}
        self.stream_stats: Dict[str, Dict] = {}
        self.lock = Lock()

        # Protocol handlers
        self.rtsp_handler = RTSPHandler()
        self.hls_handler = HLSHandler()
        self.webrtc_handler = WebRTCHandler()

        # Zoom-based source limits (Palantir-style performance optimization)
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

        # Health monitoring
        self.health_check_running = False
        self.max_concurrent_streams = 4

        # Initialize with sample Turkish cameras
        self._initialize_sample_sources()

    def _initialize_sample_sources(self):
        """
        Initialize with sample video sources from major Turkish cities
        Palantir-style multi-city coverage with various protocols
        """
        sample_sources = [
            {
                "source_id": "cam-istanbul-001",
                "name": "İstanbul Taksim Meydanı",
                "location": "İstanbul - Beyoğlu",
                "latitude": 41.0378,
                "longitude": 28.9770,
                "stream_url": "rtsp://kameras.istanbul.gov.tr/taksim.stream",
                "protocol_type": StreamProtocol.RTSP,
                "status": StreamStatus.ONLINE,
                "quality": StreamQuality.FULL_HD_1080P,
                "bitrate": 8000,
                "fps": 30,
                "metadata": {"district": "beyoglu", "operator": "ibb"}
            },
            {
                "source_id": "cam-ankara-001",
                "name": "Ankara Kızılay Meydanı",
                "location": "Ankara - Çankaya",
                "latitude": 39.9208,
                "longitude": 32.8541,
                "stream_url": "rtsp://kameras.ankara.gov.tr/kizilay.stream",
                "protocol_type": StreamProtocol.RTSP,
                "status": StreamStatus.ONLINE,
                "quality": StreamQuality.HIGH_720P,
                "bitrate": 5000,
                "fps": 25,
                "metadata": {"district": "cankaya", "operator": "abb"}
            },
            {
                "source_id": "cam-izmir-001",
                "name": "İzmir Konak Meydanı",
                "location": "İzmir - Konak",
                "latitude": 38.4237,
                "longitude": 27.1428,
                "stream_url": "https://stream.izmir.gov.tr/konak.m3u8",
                "protocol_type": StreamProtocol.HLS,
                "status": StreamStatus.ONLINE,
                "quality": StreamQuality.FULL_HD_1080P,
                "bitrate": 6000,
                "fps": 30,
                "metadata": {"district": "konak", "operator": "izzb"}
            },
            {
                "source_id": "cam-bursa-001",
                "name": "Bursa Ulu Cami",
                "location": "Bursa - Osmangazi",
                "latitude": 40.1885,
                "longitude": 29.0610,
                "stream_url": "rtsp://kameras.bursa.gov.tr/ulu-cami.stream",
                "protocol_type": StreamProtocol.RTSP,
                "status": StreamStatus.ONLINE,
                "quality": StreamQuality.HIGH_720P,
                "bitrate": 4500,
                "fps": 25,
                "metadata": {"district": "osmangazi", "operator": "bb"}
            },
            {
                "source_id": "cam-antalya-001",
                "name": "Antalya Kaleiçi Marina",
                "location": "Antalya - Muratpaşa",
                "latitude": 36.8841,
                "longitude": 30.7056,
                "stream_url": "https://stream.antalya.gov.tr/marina.m3u8",
                "protocol_type": StreamProtocol.HLS,
                "status": StreamStatus.ONLINE,
                "quality": StreamQuality.FULL_HD_1080P,
                "bitrate": 7000,
                "fps": 30,
                "metadata": {"district": "muratpasa", "operator": "ayto"}
            },
            {
                "source_id": "cam-drone-001",
                "name": "İstanbul Havan Gözetleme Drone",
                "location": "İstanbul - Havan",
                "latitude": 41.0082,
                "longitude": 28.9784,
                "stream_url": "webrtc://drone.police.gov.tr/havan-001",
                "protocol_type": StreamProtocol.WEBRTC,
                "status": StreamStatus.ONLINE,
                "quality": StreamQuality.FULL_HD_1080P,
                "bitrate": 8000,
                "fps": 60,
                "metadata": {"operator": "tem", "drone_type": "djimavic3", "battery": 85}
            },
            {
                "source_id": "cam-adana-001",
                "name": "Adana Merkez Park",
                "location": "Adana - Seyhan",
                "latitude": 37.0000,
                "longitude": 35.3213,
                "stream_url": "rtsp://kameras.adana.gov.tr/merkez-park.stream",
                "protocol_type": StreamProtocol.RTSP,
                "status": StreamStatus.ONLINE,
                "quality": StreamQuality.HIGH_720P,
                "bitrate": 5000,
                "fps": 25,
                "metadata": {"district": "seyhan", "operator": "ayto"}
            },
            {
                "source_id": "cam-gaziantep-001",
                "name": "Gaziantep Kale",
                "location": "Gaziantep - Şahinbey",
                "latitude": 37.0745,
                "longitude": 37.3833,
                "stream_url": "https://stream.gaziantep.gov.tr/kale.m3u8",
                "protocol_type": StreamProtocol.HLS,
                "status": StreamStatus.ONLINE,
                "quality": StreamQuality.HIGH_720P,
                "bitrate": 4500,
                "fps": 25,
                "metadata": {"district": "sahinbey", "operator": "gb"}
            },
            {
                "source_id": "cam-konya-001",
                "name": "Konya Alaeddin Tepesi",
                "location": "Konya - Selçuklu",
                "latitude": 37.8713,
                "longitude": 32.4846,
                "stream_url": "rtsp://kameras.konya.gov.tr/alaeddin.stream",
                "protocol_type": StreamProtocol.RTSP,
                "status": StreamStatus.ONLINE,
                "quality": StreamQuality.HIGH_720P,
                "bitrate": 5000,
                "fps": 25,
                "metadata": {"district": "selcuklu", "operator": "kbb"}
            },
            {
                "source_id": "cam-trabzon-001",
                "name": "Trabzon Atatürk Alanı",
                "location": "Trabzon - Ortahisar",
                "latitude": 41.0027,
                "longitude": 39.7168,
                "stream_url": "https://stream.trabzon.gov.tr/ataturk.m3u8",
                "protocol_type": StreamProtocol.HLS,
                "status": StreamStatus.ONLINE,
                "quality": StreamQuality.FULL_HD_1080P,
                "bitrate": 6000,
                "fps": 30,
                "metadata": {"district": "ortahisar", "operator": "tbb"}
            }
        ]

        for source_data in sample_sources:
            source = VideoSource(**source_data)
            self.add_video_source(source)

        logger.info(f"Initialized {len(sample_sources)} sample video sources")

    def add_video_source(self, source: VideoSource) -> bool:
        """
        Add new video source to the system
        Returns True if successful, False otherwise
        """
        with self.lock:
            try:
                self.sources[source.source_id] = source
                self.stream_stats[source.source_id] = {
                    "added_at": datetime.now().isoformat(),
                    "requests_count": 0,
                    "last_accessed": None,
                    "connection_failures": 0,
                    "total_uptime": 0,
                    "last_health_check": None
                }

                # Generate thumbnail
                source.thumbnail = self._generate_thumbnail(source)

                logger.info(f"Added video source: {source.source_id} - {source.name}")
                return True
            except Exception as e:
                logger.error(f"Error adding video source {source.source_id}: {str(e)}")
                return False

    def remove_video_source(self, source_id: str) -> bool:
        """Remove video source from system"""
        with self.lock:
            if source_id in self.sources:
                # Stop active stream if exists
                if source_id in self.active_streams:
                    self.stop_stream(source_id)

                del self.sources[source_id]
                if source_id in self.stream_stats:
                    del self.stream_stats[source_id]
                logger.info(f"Removed video source: {source_id}")
                return True
            return False

    def get_video_source(self, source_id: str) -> Optional[VideoSource]:
        """Get specific video source by ID"""
        return self.sources.get(source_id)

    def get_active_streams(self, zoom_level: int = 6,
                          status_filter: Optional[str] = None,
                          protocol_filter: Optional[str] = None) -> List[Dict]:
        """
        Get video streams filtered by zoom level and filters
        Palantir-style performance optimization

        Args:
            zoom_level: Map zoom level (1-8)
            status_filter: Optional status filter
            protocol_filter: Optional protocol filter

        Returns:
            List of video source dictionaries
        """
        max_streams = self.zoom_limits.get(zoom_level, 100)

        sources = list(self.sources.values())

        # Filter by status
        if status_filter:
            sources = [s for s in sources if s.status.value == status_filter]

        # Filter by protocol
        if protocol_filter:
            sources = [s for s in sources if s.protocol_type.value == protocol_filter]

        # Sort by last update (newest first)
        sources.sort(key=lambda x: x.last_update, reverse=True)

        # Limit by zoom level
        sources = sources[:max_streams]

        # Update stream stats
        with self.lock:
            for source in sources:
                if source.source_id in self.stream_stats:
                    self.stream_stats[source.source_id]["requests_count"] += 1
                    self.stream_stats[source.source_id]["last_accessed"] = datetime.now().isoformat()

        return [source.to_dict() for source in sources]

    def get_stream_by_id(self, source_id: str) -> Optional[Dict]:
        """Get specific stream by ID"""
        source = self.sources.get(source_id)
        if source:
            # Update access stats
            with self.lock:
                if source_id in self.stream_stats:
                    self.stream_stats[source_id]["requests_count"] += 1
                    self.stream_stats[source_id]["last_accessed"] = datetime.now().isoformat()
            return source.to_dict()
        return None

    def update_stream_status(self, source_id: str, status: StreamStatus) -> bool:
        """
        Update stream status
        Used for health checks and monitoring
        """
        source = self.sources.get(source_id)
        if source:
            source.status = status
            source.last_update = datetime.now()

            if status == StreamStatus.ONLINE:
                source.last_connected = datetime.now()

            with self.lock:
                if source_id in self.stream_stats:
                    self.stream_stats[source_id]["last_health_check"] = datetime.now().isoformat()

            logger.info(f"Updated stream {source_id} status to {status.value}")
            return True
        return False

    def start_stream(self, source_id: str) -> Dict[str, Any]:
        """
        Start streaming from video source
        Returns stream connection details
        """
        source = self.sources.get(source_id)
        if not source:
            return {"success": False, "error": "Source not found"}

        try:
            # Update status
            source.status = StreamStatus.CONNECTING
            source.last_update = datetime.now()

            # Protocol-specific connection
            if source.protocol_type == StreamProtocol.RTSP:
                # In production: await self.rtsp_handler.connect(source.stream_url)
                stream_url = source.stream_url

            elif source.protocol_type == StreamProtocol.HLS:
                # In production: playlist = await self.hls_handler.parse_playlist(source.stream_url)
                stream_url = source.stream_url

            elif source.protocol_type == StreamProtocol.WEBRTC:
                # In production: offer = await self.webrtc_handler.create_offer(source_id)
                stream_url = source.stream_url

            else:
                stream_url = source.stream_url

            # Mark as online
            source.status = StreamStatus.ONLINE
            source.last_connected = datetime.now()

            # Add to active streams
            self.active_streams[source_id] = {
                "started_at": datetime.now().isoformat(),
                "protocol": source.protocol_type.value,
                "stream_url": stream_url,
                "quality": source.quality.value
            }

            logger.info(f"Started stream: {source_id}")

            return {
                "success": True,
                "source_id": source_id,
                "stream_url": stream_url,
                "protocol": source.protocol_type.value,
                "quality": source.quality.value
            }

        except Exception as e:
            source.status = StreamStatus.ERROR
            source.retry_count += 1
            logger.error(f"Error starting stream {source_id}: {str(e)}")
            return {"success": False, "error": str(e)}

    def stop_stream(self, source_id: str) -> bool:
        """Stop streaming from video source"""
        if source_id in self.active_streams:
            source = self.sources.get(source_id)
            if source:
                source.status = StreamStatus.OFFLINE
                source.last_update = datetime.now()

            del self.active_streams[source_id]
            logger.info(f"Stopped stream: {source_id}")
            return True
        return False

    def control_stream(self, source_id: str, action: str, params: Dict = None) -> Dict[str, Any]:
        """
        Control stream (play, pause, stop, restart, quality_change)
        Palantir-style unified stream control
        """
        source = self.sources.get(source_id)
        if not source:
            return {"success": False, "error": "Source not found"}

        try:
            if action == "play":
                result = self.start_stream(source_id)

            elif action == "pause":
                source.status = StreamStatus.OFFLINE
                result = {"success": True, "action": "paused"}

            elif action == "stop":
                result = self.stop_stream(source_id)

            elif action == "restart":
                self.stop_stream(source_id)
                time.sleep(0.5)
                result = self.start_stream(source_id)

            elif action == "quality_change" and params:
                new_quality = params.get("quality")
                if new_quality:
                    source.quality = StreamQuality(new_quality)
                    result = {"success": True, "quality": new_quality}
                else:
                    result = {"success": False, "error": "Quality parameter required"}

            else:
                result = {"success": False, "error": "Unknown action"}

            logger.info(f"Stream control: {source_id} - {action}")
            return result

        except Exception as e:
            logger.error(f"Error controlling stream {source_id}: {str(e)}")
            return {"success": False, "error": str(e)}

    def get_streams_by_location(self, lat: float, lon: float,
                               radius_km: int = 10) -> List[Dict]:
        """
        Get streams within geographic radius
        Palantir-style regional filtering
        """
        from math import radians, cos, sin, asin, sqrt

        def haversine_distance(lat1, lon1, lat2, lon2):
            """Calculate distance between two points in km"""
            lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
            dlat = lat2 - lat1
            dlon = lon2 - lon1
            a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
            c = 2 * asin(sqrt(a))
            return 6371 * c

        streams_in_region = []

        for source in self.sources.values():
            distance = haversine_distance(lat, lon, source.latitude, source.longitude)
            if distance <= radius_km:
                streams_in_region.append(source.to_dict())

        return streams_in_region

    def get_stream_thumbnail(self, source_id: str) -> Optional[str]:
        """
        Get stream thumbnail image
        Returns base64 encoded image
        """
        source = self.sources.get(source_id)
        if source and source.thumbnail:
            return source.thumbnail
        return None

    def _generate_thumbnail(self, source: VideoSource) -> str:
        """Generate placeholder thumbnail for video source"""
        protocol_colors = {
            StreamProtocol.RTSP: "#00b4ff",
            StreamProtocol.HLS: "#00ff9d",
            StreamProtocol.WEBRTC: "#8855ff",
            StreamProtocol.HTTP: "#ffaa00"
        }

        color = protocol_colors.get(source.protocol_type, "#888888")

        svg = f"""
        <svg width="320" height="180" xmlns="http://www.w3.org/2000/svg">
            <defs>
                <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#0a0a14;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#141428;stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect width="320" height="180" fill="url(#grad)"/>
            <circle cx="160" cy="80" r="30" fill="none" stroke="{color}" stroke-width="2"/>
            <circle cx="160" cy="80" r="10" fill="{color}"/>
            <text x="160" y="130" text-anchor="middle" fill="#e0e0e0" font-family="Arial, sans-serif" font-size="12" font-weight="bold">{source.name}</text>
            <text x="160" y="150" text-anchor="middle" fill="#888" font-family="Arial, sans-serif" font-size="10">{source.location}</text>
            <rect x="10" y="10" width="60" height="20" rx="4" fill="{color}" opacity="0.8"/>
            <text x="40" y="24" text-anchor="middle" fill="#000" font-family="Arial, sans-serif" font-size="10" font-weight="bold">{source.protocol_type.value.upper()}</text>
        </svg>
        """

        return f"data:image/svg+xml;base64,{base64.b64encode(svg.encode()).decode()}"

    def get_stream_statistics(self) -> Dict[str, Any]:
        """
        Get overall stream system statistics
        Palantir-style dashboard metrics
        """
        total_sources = len(self.sources)
        online_sources = sum(1 for s in self.sources.values() if s.status == StreamStatus.ONLINE)
        offline_sources = sum(1 for s in self.sources.values() if s.status == StreamStatus.OFFLINE)
        error_sources = sum(1 for s in self.sources.values() if s.status == StreamStatus.ERROR)
        recording_sources = sum(1 for s in self.sources.values() if s.status == StreamStatus.RECORDING)

        sources_by_protocol = {}
        for source in self.sources.values():
            protocol = source.protocol_type.value
            sources_by_protocol[protocol] = sources_by_protocol.get(protocol, 0) + 1

        sources_by_quality = {}
        for source in self.sources.values():
            quality = source.quality.value
            sources_by_quality[quality] = sources_by_quality.get(quality, 0) + 1

        sources_by_status = {}
        for source in self.sources.values():
            status = source.status.value
            sources_by_status[status] = sources_by_status.get(status, 0) + 1

        return {
            "total_sources": total_sources,
            "online": online_sources,
            "offline": offline_sources,
            "error": error_sources,
            "recording": recording_sources,
            "active_streams": len(self.active_streams),
            "uptime_percentage": round((online_sources / total_sources * 100) if total_sources > 0 else 0, 2),
            "by_protocol": sources_by_protocol,
            "by_quality": sources_by_quality,
            "by_status": sources_by_status,
            "total_requests": sum(stats.get("requests_count", 0) for stats in self.stream_stats.values()),
            "avg_bitrate": round(sum(s.bitrate for s in self.sources.values()) / total_sources, 2) if total_sources > 0 else 0
        }

    def get_streams_geojson(self, zoom_level: int = 6) -> Dict[str, Any]:
        """
        Get all streams as GeoJSON FeatureCollection
        For direct Leaflet.js integration
        """
        sources = self.get_active_streams(zoom_level)

        features = []
        for source_dict in sources:
            source = self.sources.get(source_dict['source_id'])
            if source:
                features.append(source.to_geojson())

        return {
            "type": "FeatureCollection",
            "features": features
        }

    def start_health_monitoring(self, interval_seconds: int = 30):
        """
        Start background health monitoring for all streams
        Palantir-style proactive health checks
        """
        def health_check_loop():
            while self.health_check_running:
                try:
                    for source_id, source in self.sources.items():
                        # Simulate health check
                        # In production: actual ping/connection test
                        if source.status == StreamStatus.ONLINE:
                            # Randomly simulate some streams going offline
                            import random
                            if random.random() < 0.02:  # 2% chance of failure
                                self.update_stream_status(source_id, StreamStatus.ERROR)

                    time.sleep(interval_seconds)
                except Exception as e:
                    logger.error(f"Health monitoring error: {e}")

        if not self.health_check_running:
            self.health_check_running = True
            health_thread = Thread(target=health_check_loop, daemon=True)
            health_thread.start()
            logger.info("Started health monitoring")

    def stop_health_monitoring(self):
        """Stop background health monitoring"""
        self.health_check_running = False
        logger.info("Stopped health monitoring")


# Global singleton instance
_video_stream_manager = None
_manager_lock = Lock()

def get_video_stream_manager() -> VideoStreamManager:
    """Get or create global video stream manager instance"""
    global _video_stream_manager
    with _manager_lock:
        if _video_stream_manager is None:
            _video_stream_manager = VideoStreamManager()
            logger.info("Created global VideoStreamManager instance")
            # Start health monitoring
            _video_stream_manager.start_health_monitoring()
        return _video_stream_manager


# Export key functions for Flask routes
def add_video_source(source_data: Dict) -> bool:
    """Add video source from dictionary data"""
    # Convert string enums to actual enums
    if 'protocol_type' in source_data and isinstance(source_data['protocol_type'], str):
        source_data['protocol_type'] = StreamProtocol(source_data['protocol_type'])
    if 'status' in source_data and isinstance(source_data['status'], str):
        source_data['status'] = StreamStatus(source_data['status'])
    if 'quality' in source_data and isinstance(source_data['quality'], str):
        source_data['quality'] = StreamQuality(source_data['quality'])

    source = VideoSource(**source_data)
    manager = get_video_stream_manager()
    return manager.add_video_source(source)


def get_active_streams(zoom_level: int = 6, status_filter: Optional[str] = None,
                      protocol_filter: Optional[str] = None) -> List[Dict]:
    """Get active streams filtered by zoom level"""
    manager = get_video_stream_manager()
    return manager.get_active_streams(zoom_level, status_filter, protocol_filter)


def get_streams_geojson(zoom_level: int = 6) -> Dict[str, Any]:
    """Get streams as GeoJSON for map display"""
    manager = get_video_stream_manager()
    return manager.get_streams_geojson(zoom_level)


def get_stream_statistics() -> Dict[str, Any]:
    """Get stream system statistics"""
    manager = get_video_stream_manager()
    return manager.get_stream_statistics()
