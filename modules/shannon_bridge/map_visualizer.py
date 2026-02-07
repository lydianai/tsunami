"""
Shannon Map Visualizer
======================
Converts Shannon findings to map markers for TSUNAMI KOMUTA visualization.
Provides geo-location based vulnerability display on the threat map.
"""

import socket
import logging
import hashlib
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse

from .result_parser import ShannonFinding, Severity

logger = logging.getLogger(__name__)


class ShannonMapVisualizer:
    """Converts Shannon findings to map visualization data"""

    # Severity to color mapping (CSS colors)
    SEVERITY_COLORS = {
        Severity.CRITICAL: '#ff3355',  # Red
        Severity.HIGH: '#ff8800',       # Orange
        Severity.MEDIUM: '#ffcc00',     # Yellow
        Severity.LOW: '#00ff88',        # Green
        Severity.INFO: '#00b4ff'        # Blue
    }

    # Vulnerability type icons (emoji for popup, can be replaced with SVG paths)
    VULN_ICONS = {
        'injection': '💉',
        'xss': '📜',
        'ssrf': '🔗',
        'auth': '🔐',
        'authz': '🛡️',
        'idor': '🎯',
        'file_inclusion': '📁',
        'path_traversal': '🗂️',
        'csrf': '🔀',
        'sensitive_data': '🔓',
        'misconfig': '⚙️',
        'other': '⚠️'
    }

    # Leaflet marker class names
    MARKER_CLASSES = {
        Severity.CRITICAL: 'shannon-marker-critical',
        Severity.HIGH: 'shannon-marker-high',
        Severity.MEDIUM: 'shannon-marker-medium',
        Severity.LOW: 'shannon-marker-low',
        Severity.INFO: 'shannon-marker-info'
    }

    def __init__(self):
        self._geo_cache: Dict[str, Dict] = {}
        self._ip_api_enabled = True

    def findings_to_markers(
        self,
        findings: List[ShannonFinding],
        target_url: str,
        session_id: str = ""
    ) -> List[Dict]:
        """
        Convert findings to map markers

        Args:
            findings: List of parsed Shannon findings
            target_url: Target application URL
            session_id: Shannon session ID for reference

        Returns:
            List of marker dictionaries for Leaflet
        """
        markers = []

        if not findings:
            return markers

        # Get base geo location for target
        base_geo = self._get_geo_for_url(target_url)

        for i, finding in enumerate(findings):
            # Offset slightly for multiple findings at same location
            offset = self._calculate_offset(i, len(findings))

            marker = {
                'id': f"shannon_{session_id}_{finding.id}",
                'type': 'shannon_finding',
                'lat': base_geo['lat'] + offset['lat'],
                'lng': base_geo['lng'] + offset['lng'],
                'title': finding.title,
                'severity': finding.severity.value,
                'severity_label': finding.severity.value.upper(),
                'color': self.SEVERITY_COLORS.get(finding.severity, '#ffffff'),
                'vuln_type': finding.vulnerability_type,
                'vuln_type_label': finding.vulnerability_type.upper().replace('_', ' '),
                'location': finding.location,
                'method': finding.method,
                'icon': self.VULN_ICONS.get(finding.vulnerability_type, '⚠️'),
                'marker_class': self.MARKER_CLASSES.get(finding.severity, 'shannon-marker'),
                'popup': self._generate_popup_html(finding),
                'tooltip': f"{finding.severity.value.upper()}: {finding.title[:50]}",
                'pulse': finding.severity in [Severity.CRITICAL, Severity.HIGH],
                'radius': self._calculate_radius(finding.severity),
                'finding_data': finding.to_dict()
            }
            markers.append(marker)

        logger.info(f"[SHANNON→MAP] Generated {len(markers)} markers for visualization")
        return markers

    def _get_geo_for_url(self, url: str) -> Dict[str, float]:
        """Get geo coordinates for URL"""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc.split(':')[0]  # Remove port

            # Check cache
            if hostname in self._geo_cache:
                return self._geo_cache[hostname]

            # Resolve IP
            try:
                ip = socket.gethostbyname(hostname)
            except socket.gaierror:
                logger.warning(f"[SHANNON→MAP] Could not resolve: {hostname}")
                return self._default_geo()

            # Check for local IPs
            if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
                return self._default_geo()  # Ankara for local testing

            # Use IP-API for geo lookup
            if self._ip_api_enabled:
                geo = self._lookup_ip_geo(ip)
                if geo:
                    self._geo_cache[hostname] = geo
                    return geo

        except Exception as e:
            logger.warning(f"[SHANNON→MAP] Geo lookup error: {e}")

        return self._default_geo()

    def _lookup_ip_geo(self, ip: str) -> Optional[Dict[str, float]]:
        """Lookup IP geolocation using ip-api.com"""
        try:
            import requests
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=5,
                headers={'User-Agent': 'TSUNAMI-Shannon/1.0'}
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'lat': float(data.get('lat', 0)),
                        'lng': float(data.get('lon', 0)),
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('isp', 'Unknown')
                    }
        except Exception as e:
            logger.debug(f"[SHANNON→MAP] IP-API error: {e}")
            self._ip_api_enabled = False  # Disable on error

        return None

    def _default_geo(self) -> Dict[str, float]:
        """Default geo coordinates (Ankara, Turkey)"""
        return {'lat': 39.9334, 'lng': 32.8597, 'country': 'Turkey', 'city': 'Ankara'}

    def _calculate_offset(self, index: int, total: int) -> Dict[str, float]:
        """Calculate offset for overlapping markers"""
        if total <= 1:
            return {'lat': 0, 'lng': 0}

        import math
        angle = (2 * math.pi * index) / total
        radius = 0.005  # ~500m offset

        return {
            'lat': radius * math.sin(angle),
            'lng': radius * math.cos(angle)
        }

    def _calculate_radius(self, severity: Severity) -> int:
        """Calculate marker radius based on severity"""
        radii = {
            Severity.CRITICAL: 16,
            Severity.HIGH: 14,
            Severity.MEDIUM: 12,
            Severity.LOW: 10,
            Severity.INFO: 8
        }
        return radii.get(severity, 10)

    def _generate_popup_html(self, finding: ShannonFinding) -> str:
        """Generate popup HTML for marker"""
        color = self.SEVERITY_COLORS.get(finding.severity, '#ffffff')
        icon = self.VULN_ICONS.get(finding.vulnerability_type, '⚠️')

        # Escape HTML in user-provided data
        title = self._escape_html(finding.title)
        impact = self._escape_html(finding.impact[:200]) if finding.impact else "Verified exploitable vulnerability"
        location = self._escape_html(finding.location)

        steps_html = ""
        if finding.exploitation_steps:
            steps_list = "".join(
                f"<li>{self._escape_html(step[:100])}</li>"
                for step in finding.exploitation_steps[:3]
            )
            steps_html = f"<div style='margin-top:6px;'><b>Exploitation:</b><ol style='margin:4px 0;padding-left:16px;font-size:9px;'>{steps_list}</ol></div>"

        return f"""
<div class="shannon-popup" style="min-width:220px;max-width:300px;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
        <span style="font-size:20px;">{icon}</span>
        <div>
            <h4 style="margin:0;color:{color};font-size:12px;font-weight:bold;">{title}</h4>
            <span style="font-size:9px;color:#888;">{finding.vulnerability_type.upper()}</span>
        </div>
    </div>

    <div style="background:rgba(0,0,0,0.2);padding:6px;border-radius:4px;margin-bottom:6px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <span style="color:{color};font-weight:bold;font-size:10px;">
                {finding.severity.value.upper()}
            </span>
            <span style="color:#666;font-size:9px;">
                {finding.method} {location[:30]}{'...' if len(location) > 30 else ''}
            </span>
        </div>
    </div>

    <div style="color:#ccc;font-size:10px;line-height:1.4;">
        <b>Impact:</b> {impact}{'...' if len(finding.impact) > 200 else ''}
    </div>

    {steps_html}

    <div style="margin-top:8px;padding-top:6px;border-top:1px solid rgba(255,255,255,0.1);display:flex;justify-content:space-between;align-items:center;">
        <span style="color:#00ff88;font-size:9px;">✓ Verified Exploit</span>
        <span style="color:#666;font-size:9px;">{finding.id}</span>
    </div>
</div>
"""

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        if not text:
            return ""
        return (
            text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;')
        )

    def generate_layer_data(self, findings: List[ShannonFinding], target_url: str) -> Dict:
        """Generate complete layer data for Leaflet"""
        markers = self.findings_to_markers(findings, target_url)

        return {
            'layer_id': 'shannon_findings',
            'layer_name': 'Shannon AI Pentest Results',
            'layer_type': 'marker_cluster',
            'visible': True,
            'markers': markers,
            'statistics': self._generate_statistics(findings),
            'legend': self._generate_legend(),
            'style': self._get_layer_style()
        }

    def _generate_statistics(self, findings: List[ShannonFinding]) -> Dict:
        """Generate statistics for layer"""
        return {
            'total': len(findings),
            'critical': sum(1 for f in findings if f.severity == Severity.CRITICAL),
            'high': sum(1 for f in findings if f.severity == Severity.HIGH),
            'medium': sum(1 for f in findings if f.severity == Severity.MEDIUM),
            'low': sum(1 for f in findings if f.severity == Severity.LOW),
            'types': list(set(f.vulnerability_type for f in findings))
        }

    def _generate_legend(self) -> List[Dict]:
        """Generate legend items"""
        return [
            {'color': '#ff3355', 'label': 'Critical', 'severity': 'critical'},
            {'color': '#ff8800', 'label': 'High', 'severity': 'high'},
            {'color': '#ffcc00', 'label': 'Medium', 'severity': 'medium'},
            {'color': '#00ff88', 'label': 'Low', 'severity': 'low'},
            {'color': '#00b4ff', 'label': 'Info', 'severity': 'info'}
        ]

    def _get_layer_style(self) -> Dict:
        """Get CSS styles for layer"""
        return {
            'marker_opacity': 0.9,
            'marker_weight': 2,
            'popup_max_width': 350,
            'cluster_color': '#9c27b0',
            'cluster_radius': 60
        }
