#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    MITRE ATT&CK Navigator Layer Generator
    Generate ATT&CK Navigator JSON Layers
================================================================================

    Features:
    - Generate Navigator-compatible JSON layers
    - Create heatmaps from detected techniques
    - Track technique trends over time
    - Export for visualization in ATT&CK Navigator

    ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/

================================================================================
"""

import json
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading
import colorsys

from .attack_data import MITREAttackData, Technique, get_attack_data, CACHE_DIR

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Navigator layer version
NAVIGATOR_VERSION = "4.9.1"
ATTACK_VERSION = "15"


class ColorScheme(Enum):
    """Color schemes for heatmaps"""
    RED = "red"
    BLUE = "blue"
    GREEN = "green"
    YELLOW = "yellow"
    PURPLE = "purple"
    GRAYSCALE = "grayscale"
    SEVERITY = "severity"  # Red-Yellow-Green based on severity


@dataclass
class TechniqueScore:
    """Score for a technique in the layer"""
    technique_id: str
    score: int  # 0-100 for Navigator
    color: str = ""  # Hex color
    comment: str = ""
    enabled: bool = True
    show_subtechniques: bool = True
    metadata: List[Dict] = field(default_factory=list)
    links: List[Dict] = field(default_factory=list)

    def to_nav_dict(self) -> Dict:
        """Convert to Navigator technique format"""
        result = {
            'techniqueID': self.technique_id,
            'score': self.score,
            'enabled': self.enabled,
            'showSubtechniques': self.show_subtechniques
        }
        if self.color:
            result['color'] = self.color
        if self.comment:
            result['comment'] = self.comment
        if self.metadata:
            result['metadata'] = self.metadata
        if self.links:
            result['links'] = self.links
        return result


@dataclass
class NavigatorLayer:
    """ATT&CK Navigator Layer"""
    name: str
    description: str = ""
    domain: str = "enterprise-attack"
    version: str = NAVIGATOR_VERSION
    attack_version: str = ATTACK_VERSION

    # Techniques
    techniques: List[TechniqueScore] = field(default_factory=list)

    # Layer settings
    sorting: int = 0  # 0 = alphabetical, 1 = score ascending, 2 = score descending
    layout: Dict = field(default_factory=lambda: {
        "layout": "side",
        "aggregateFunction": "average",
        "showID": True,
        "showName": True,
        "showAggregateScores": True,
        "countUnscored": False,
        "expandedSubtechniques": "none"
    })

    # Filters
    hide_disabled: bool = False
    platforms: List[str] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)

    # Gradient
    gradient: Dict = field(default_factory=lambda: {
        "colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"],
        "minValue": 0,
        "maxValue": 100
    })

    # Legend
    legend_items: List[Dict] = field(default_factory=list)

    # Metadata
    metadata: List[Dict] = field(default_factory=list)
    links: List[Dict] = field(default_factory=list)

    # Filters
    select_techniques: List[str] = field(default_factory=list)
    select_subtechniques: List[str] = field(default_factory=list)
    select_tactics: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to Navigator JSON format"""
        return {
            'name': self.name,
            'versions': {
                'attack': self.attack_version,
                'navigator': self.version,
                'layer': '4.5'
            },
            'domain': self.domain,
            'description': self.description,
            'filters': {
                'platforms': self.platforms if self.platforms else [
                    'Linux', 'macOS', 'Windows', 'Network',
                    'PRE', 'Containers', 'Office 365', 'SaaS',
                    'Google Workspace', 'IaaS', 'Azure AD'
                ]
            },
            'sorting': self.sorting,
            'layout': self.layout,
            'hideDisabled': self.hide_disabled,
            'techniques': [t.to_nav_dict() for t in self.techniques],
            'gradient': self.gradient,
            'legendItems': self.legend_items,
            'metadata': self.metadata,
            'links': self.links,
            'showTacticRowBackground': True,
            'tacticRowBackground': '#dddddd',
            'selectTechniquesAcrossTactics': True,
            'selectSubtechniquesWithParent': True,
            'selectVisibleTechniques': False
        }

    def to_json(self, indent: int = 2) -> str:
        """Export as JSON string"""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, filepath: Path):
        """Save layer to file"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.to_json())
        logger.info(f"[NAVIGATOR] Layer saved to {filepath}")


@dataclass
class TechniqueHistory:
    """Historical data for a technique"""
    technique_id: str
    first_seen: datetime
    last_seen: datetime
    detections: List[Tuple[datetime, int]] = field(default_factory=list)  # (time, count)
    trend: str = "stable"  # increasing, decreasing, stable

    def to_dict(self) -> Dict:
        return {
            'technique_id': self.technique_id,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'total_detections': sum(d[1] for d in self.detections),
            'detection_count': len(self.detections),
            'trend': self.trend
        }


class NavigatorGenerator:
    """
    Generates ATT&CK Navigator layers from detection data

    Creates heatmaps, coverage layers, and trend visualizations.
    """

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> 'NavigatorGenerator':
        """Get singleton instance"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self._attack_data: Optional[MITREAttackData] = None
        self._technique_history: Dict[str, TechniqueHistory] = {}
        self._color_schemes = self._init_color_schemes()

        logger.info("[NAVIGATOR] Generator initialized")

    def _init_color_schemes(self) -> Dict[str, List[str]]:
        """Initialize color schemes for heatmaps"""
        return {
            ColorScheme.RED.value: ['#fff5f5', '#ffc9c9', '#ff8787', '#ff6b6b', '#fa5252', '#e03131', '#c92a2a'],
            ColorScheme.BLUE.value: ['#e7f5ff', '#a5d8ff', '#74c0fc', '#4dabf7', '#339af0', '#228be6', '#1971c2'],
            ColorScheme.GREEN.value: ['#ebfbee', '#b2f2bb', '#8ce99a', '#69db7c', '#51cf66', '#40c057', '#2f9e44'],
            ColorScheme.YELLOW.value: ['#fff9db', '#fff3bf', '#ffec99', '#ffe066', '#ffd43b', '#fcc419', '#fab005'],
            ColorScheme.PURPLE.value: ['#f8f0fc', '#eebefa', '#da77f2', '#cc5de8', '#be4bdb', '#ae3ec9', '#9c36b5'],
            ColorScheme.GRAYSCALE.value: ['#f8f9fa', '#dee2e6', '#adb5bd', '#868e96', '#495057', '#343a40', '#212529'],
            ColorScheme.SEVERITY.value: ['#40c057', '#82c91e', '#fab005', '#fd7e14', '#fa5252', '#e03131', '#c92a2a']
        }

    def set_attack_data(self, attack_data: MITREAttackData):
        """Set the ATT&CK data source"""
        self._attack_data = attack_data

    def _get_color(self, score: float, scheme: ColorScheme = ColorScheme.RED) -> str:
        """
        Get color for a score (0.0-1.0)

        Args:
            score: Normalized score 0.0-1.0
            scheme: Color scheme to use

        Returns:
            Hex color string
        """
        colors = self._color_schemes.get(scheme.value, self._color_schemes[ColorScheme.RED.value])
        index = min(int(score * len(colors)), len(colors) - 1)
        return colors[index]

    def _interpolate_color(self, score: float, scheme: ColorScheme = ColorScheme.SEVERITY) -> str:
        """
        Interpolate color for smooth gradients

        Args:
            score: Normalized score 0.0-1.0
            scheme: Color scheme to use

        Returns:
            Hex color string
        """
        colors = self._color_schemes.get(scheme.value, self._color_schemes[ColorScheme.SEVERITY.value])

        if score <= 0:
            return colors[0]
        if score >= 1:
            return colors[-1]

        # Find position in color array
        pos = score * (len(colors) - 1)
        idx = int(pos)
        frac = pos - idx

        if idx >= len(colors) - 1:
            return colors[-1]

        # Interpolate between two colors
        c1 = colors[idx]
        c2 = colors[idx + 1]

        # Parse hex colors
        r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
        r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)

        # Interpolate
        r = int(r1 + (r2 - r1) * frac)
        g = int(g1 + (g2 - g1) * frac)
        b = int(b1 + (b2 - b1) * frac)

        return f'#{r:02x}{g:02x}{b:02x}'

    def create_detection_layer(self,
                              detections: Dict[str, int],
                              name: str = "Detected Techniques",
                              description: str = "",
                              color_scheme: ColorScheme = ColorScheme.RED,
                              show_all: bool = True) -> NavigatorLayer:
        """
        Create a layer showing detected techniques

        Args:
            detections: Dict of technique_id -> detection count
            name: Layer name
            description: Layer description
            color_scheme: Color scheme for heatmap
            show_all: Show all techniques (grey for undetected)

        Returns:
            NavigatorLayer ready for export
        """
        if not self._attack_data:
            self._attack_data = get_attack_data()

        # Normalize scores
        max_count = max(detections.values()) if detections else 1
        techniques = []

        # Add detected techniques
        for tech_id, count in detections.items():
            score = min(count / max_count, 1.0)
            color = self._interpolate_color(score, color_scheme)

            technique = self._attack_data.get_technique(tech_id)
            comment = f"Detected {count} time(s)"
            if technique:
                comment = f"{technique.name}: {comment}"

            techniques.append(TechniqueScore(
                technique_id=tech_id,
                score=int(score * 100),
                color=color,
                comment=comment,
                enabled=True,
                show_subtechniques=True
            ))

        # Add undetected techniques if showing all
        if show_all:
            detected_ids = set(detections.keys())
            for tech in self._attack_data.list_techniques(include_subtechniques=True):
                if tech.id not in detected_ids and not tech.x_mitre_deprecated:
                    techniques.append(TechniqueScore(
                        technique_id=tech.id,
                        score=0,
                        color='#ffffff',  # White for undetected
                        comment='Not detected',
                        enabled=True,
                        show_subtechniques=True
                    ))

        # Create legend
        legend_items = [
            {'label': 'High (75-100%)', 'color': self._get_color(0.9, color_scheme)},
            {'label': 'Medium (50-75%)', 'color': self._get_color(0.6, color_scheme)},
            {'label': 'Low (25-50%)', 'color': self._get_color(0.35, color_scheme)},
            {'label': 'Minimal (1-25%)', 'color': self._get_color(0.1, color_scheme)},
            {'label': 'Not detected', 'color': '#ffffff'}
        ]

        layer = NavigatorLayer(
            name=name,
            description=description or f"Detection heatmap generated at {datetime.now().isoformat()}",
            techniques=techniques,
            legend_items=legend_items,
            metadata=[
                {'name': 'generated', 'value': datetime.now().isoformat()},
                {'name': 'total_detections', 'value': str(sum(detections.values()))},
                {'name': 'unique_techniques', 'value': str(len(detections))}
            ]
        )

        return layer

    def create_coverage_layer(self,
                             coverage: Dict[str, float],
                             name: str = "Defense Coverage",
                             description: str = "",
                             invert_colors: bool = False) -> NavigatorLayer:
        """
        Create a layer showing defense coverage

        Args:
            coverage: Dict of technique_id -> coverage score (0.0-1.0)
            name: Layer name
            description: Layer description
            invert_colors: If True, green = covered, red = gaps

        Returns:
            NavigatorLayer ready for export
        """
        if not self._attack_data:
            self._attack_data = get_attack_data()

        techniques = []

        for tech_id, score in coverage.items():
            # For coverage, we typically want green = good (covered)
            if invert_colors:
                # Green to red (1.0 = green/good, 0.0 = red/bad)
                color = self._interpolate_color(score, ColorScheme.SEVERITY)
                # Reverse the color (severity scheme goes green->red for low->high)
            else:
                # Red to green (1.0 = green/good)
                color = self._interpolate_color(1.0 - score, ColorScheme.SEVERITY)

            technique = self._attack_data.get_technique(tech_id)
            comment = f"Coverage: {score*100:.0f}%"
            if technique:
                comment = f"{technique.name}: {comment}"

            techniques.append(TechniqueScore(
                technique_id=tech_id,
                score=int(score * 100),
                color=color,
                comment=comment,
                enabled=True,
                show_subtechniques=True
            ))

        # Add uncovered techniques
        covered_ids = set(coverage.keys())
        for tech in self._attack_data.list_techniques(include_subtechniques=True):
            if tech.id not in covered_ids and not tech.x_mitre_deprecated:
                color = '#c92a2a' if invert_colors else '#c92a2a'  # Red = not covered
                techniques.append(TechniqueScore(
                    technique_id=tech.id,
                    score=0,
                    color=color,
                    comment='No coverage data',
                    enabled=True,
                    show_subtechniques=True
                ))

        # Coverage legend
        legend_items = [
            {'label': 'Full coverage (90-100%)', 'color': '#40c057'},
            {'label': 'Good coverage (70-90%)', 'color': '#82c91e'},
            {'label': 'Partial coverage (50-70%)', 'color': '#fab005'},
            {'label': 'Limited coverage (30-50%)', 'color': '#fd7e14'},
            {'label': 'Minimal coverage (10-30%)', 'color': '#fa5252'},
            {'label': 'No coverage (<10%)', 'color': '#c92a2a'}
        ]

        layer = NavigatorLayer(
            name=name,
            description=description or f"Defense coverage analysis at {datetime.now().isoformat()}",
            techniques=techniques,
            legend_items=legend_items,
            gradient={
                'colors': ['#c92a2a', '#fd7e14', '#fab005', '#82c91e', '#40c057'],
                'minValue': 0,
                'maxValue': 100
            }
        )

        return layer

    def create_comparison_layer(self,
                               layer_a: Dict[str, int],
                               layer_b: Dict[str, int],
                               name: str = "Comparison",
                               label_a: str = "Set A",
                               label_b: str = "Set B") -> NavigatorLayer:
        """
        Create a layer comparing two detection sets

        Args:
            layer_a: First set of detections
            layer_b: Second set of detections
            name: Layer name
            label_a: Label for first set
            label_b: Label for second set

        Returns:
            NavigatorLayer with comparison
        """
        if not self._attack_data:
            self._attack_data = get_attack_data()

        techniques = []
        all_ids = set(layer_a.keys()) | set(layer_b.keys())

        for tech_id in all_ids:
            in_a = tech_id in layer_a
            in_b = tech_id in layer_b
            count_a = layer_a.get(tech_id, 0)
            count_b = layer_b.get(tech_id, 0)

            if in_a and in_b:
                color = '#9c36b5'  # Purple = both
                comment = f"Both: {label_a}={count_a}, {label_b}={count_b}"
                score = 100
            elif in_a:
                color = '#228be6'  # Blue = only A
                comment = f"{label_a} only: {count_a}"
                score = 75
            else:
                color = '#40c057'  # Green = only B
                comment = f"{label_b} only: {count_b}"
                score = 50

            techniques.append(TechniqueScore(
                technique_id=tech_id,
                score=score,
                color=color,
                comment=comment,
                enabled=True
            ))

        legend_items = [
            {'label': f'Both {label_a} and {label_b}', 'color': '#9c36b5'},
            {'label': f'{label_a} only', 'color': '#228be6'},
            {'label': f'{label_b} only', 'color': '#40c057'},
            {'label': 'Neither', 'color': '#ffffff'}
        ]

        layer = NavigatorLayer(
            name=name,
            description=f"Comparison of {label_a} and {label_b}",
            techniques=techniques,
            legend_items=legend_items,
            sorting=2  # Sort by score descending
        )

        return layer

    def create_group_layer(self,
                          group_name: str,
                          color: str = "#fa5252") -> Optional[NavigatorLayer]:
        """
        Create a layer showing techniques used by a specific group

        Args:
            group_name: Threat group name or ID
            color: Highlight color for techniques

        Returns:
            NavigatorLayer or None if group not found
        """
        if not self._attack_data:
            self._attack_data = get_attack_data()

        group = self._attack_data.get_group(group_name)
        if not group:
            logger.warning(f"[NAVIGATOR] Group not found: {group_name}")
            return None

        techniques = []
        for tech_id in group.techniques:
            technique = self._attack_data.get_technique(tech_id)
            comment = f"Used by {group.name}"
            if technique:
                comment += f" ({technique.name})"

            techniques.append(TechniqueScore(
                technique_id=tech_id,
                score=100,
                color=color,
                comment=comment,
                enabled=True,
                show_subtechniques=True
            ))

        description = group.description[:500] if group.description else ""
        if group.aliases:
            description += f"\n\nAliases: {', '.join(group.aliases)}"

        layer = NavigatorLayer(
            name=f"{group.name} TTPs",
            description=description,
            techniques=techniques,
            legend_items=[
                {'label': f'Used by {group.name}', 'color': color},
                {'label': 'Not associated', 'color': '#ffffff'}
            ],
            metadata=[
                {'name': 'group_id', 'value': group.id},
                {'name': 'group_name', 'value': group.name},
                {'name': 'technique_count', 'value': str(len(group.techniques))}
            ]
        )

        return layer

    def create_software_layer(self,
                             software_name: str,
                             color: str = "#228be6") -> Optional[NavigatorLayer]:
        """
        Create a layer showing techniques used by specific software

        Args:
            software_name: Software/malware name or ID
            color: Highlight color for techniques

        Returns:
            NavigatorLayer or None if software not found
        """
        if not self._attack_data:
            self._attack_data = get_attack_data()

        software = self._attack_data.get_software(software_name)
        if not software:
            logger.warning(f"[NAVIGATOR] Software not found: {software_name}")
            return None

        techniques = []
        for tech_id in software.techniques:
            technique = self._attack_data.get_technique(tech_id)
            comment = f"Used by {software.name} ({software.type})"

            techniques.append(TechniqueScore(
                technique_id=tech_id,
                score=100,
                color=color,
                comment=comment,
                enabled=True
            ))

        layer = NavigatorLayer(
            name=f"{software.name} Techniques",
            description=f"{software.type.capitalize()}: {software.description[:500] if software.description else ''}",
            techniques=techniques,
            legend_items=[
                {'label': f'Used by {software.name}', 'color': color}
            ]
        )

        return layer

    def record_detection(self, technique_id: str, timestamp: Optional[datetime] = None,
                        count: int = 1):
        """
        Record a technique detection for trend tracking

        Args:
            technique_id: Detected technique
            timestamp: Detection time (default: now)
            count: Number of detections
        """
        timestamp = timestamp or datetime.now()

        if technique_id not in self._technique_history:
            self._technique_history[technique_id] = TechniqueHistory(
                technique_id=technique_id,
                first_seen=timestamp,
                last_seen=timestamp,
                detections=[]
            )

        history = self._technique_history[technique_id]
        history.detections.append((timestamp, count))
        if timestamp > history.last_seen:
            history.last_seen = timestamp
        if timestamp < history.first_seen:
            history.first_seen = timestamp

        # Update trend
        self._update_trend(technique_id)

    def _update_trend(self, technique_id: str):
        """Update trend analysis for a technique"""
        history = self._technique_history.get(technique_id)
        if not history or len(history.detections) < 2:
            if history:
                history.trend = 'stable'
            return

        # Compare recent vs older detections
        detections = sorted(history.detections, key=lambda x: x[0])
        midpoint = len(detections) // 2

        older_sum = sum(d[1] for d in detections[:midpoint])
        newer_sum = sum(d[1] for d in detections[midpoint:])

        if newer_sum > older_sum * 1.5:
            history.trend = 'increasing'
        elif newer_sum < older_sum * 0.5:
            history.trend = 'decreasing'
        else:
            history.trend = 'stable'

    def get_trends(self, days: int = 30) -> Dict[str, List[TechniqueHistory]]:
        """
        Get technique trends

        Args:
            days: Number of days to consider

        Returns:
            Dict with 'increasing', 'decreasing', 'stable' lists
        """
        cutoff = datetime.now() - timedelta(days=days)
        trends = {
            'increasing': [],
            'decreasing': [],
            'stable': []
        }

        for history in self._technique_history.values():
            # Filter to recent detections
            recent = [d for d in history.detections if d[0] >= cutoff]
            if not recent:
                continue

            trends[history.trend].append(history)

        # Sort by total detections
        for trend_list in trends.values():
            trend_list.sort(key=lambda h: -sum(d[1] for d in h.detections))

        return trends

    def create_trend_layer(self,
                          days: int = 30,
                          name: str = "Detection Trends") -> NavigatorLayer:
        """
        Create a layer showing technique trends

        Args:
            days: Number of days for trend analysis
            name: Layer name

        Returns:
            NavigatorLayer with trend coloring
        """
        if not self._attack_data:
            self._attack_data = get_attack_data()

        trends = self.get_trends(days)
        techniques = []

        # Increasing = red (threat growing)
        for history in trends['increasing']:
            total = sum(d[1] for d in history.detections)
            techniques.append(TechniqueScore(
                technique_id=history.technique_id,
                score=100,
                color='#e03131',
                comment=f"Increasing trend: {total} detections",
                enabled=True
            ))

        # Decreasing = blue (threat diminishing)
        for history in trends['decreasing']:
            total = sum(d[1] for d in history.detections)
            techniques.append(TechniqueScore(
                technique_id=history.technique_id,
                score=50,
                color='#228be6',
                comment=f"Decreasing trend: {total} detections",
                enabled=True
            ))

        # Stable = yellow
        for history in trends['stable']:
            total = sum(d[1] for d in history.detections)
            techniques.append(TechniqueScore(
                technique_id=history.technique_id,
                score=75,
                color='#fab005',
                comment=f"Stable trend: {total} detections",
                enabled=True
            ))

        legend_items = [
            {'label': 'Increasing trend', 'color': '#e03131'},
            {'label': 'Stable', 'color': '#fab005'},
            {'label': 'Decreasing trend', 'color': '#228be6'},
            {'label': 'No recent data', 'color': '#ffffff'}
        ]

        layer = NavigatorLayer(
            name=name,
            description=f"Detection trends over the past {days} days",
            techniques=techniques,
            legend_items=legend_items,
            metadata=[
                {'name': 'analysis_period', 'value': f'{days} days'},
                {'name': 'increasing_count', 'value': str(len(trends['increasing']))},
                {'name': 'decreasing_count', 'value': str(len(trends['decreasing']))},
                {'name': 'stable_count', 'value': str(len(trends['stable']))}
            ]
        )

        return layer

    def export_layer(self, layer: NavigatorLayer, filepath: Optional[Path] = None) -> str:
        """
        Export layer to file or return JSON

        Args:
            layer: Layer to export
            filepath: Optional file path (exports to CACHE_DIR if not specified)

        Returns:
            File path as string
        """
        if filepath is None:
            # Generate filename from layer name
            safe_name = ''.join(c if c.isalnum() else '_' for c in layer.name.lower())
            filepath = CACHE_DIR / f"layer_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        filepath = Path(filepath)
        layer.save(filepath)

        return str(filepath)

    def get_statistics(self) -> Dict[str, Any]:
        """Get generator statistics"""
        return {
            'tracked_techniques': len(self._technique_history),
            'total_detections': sum(
                sum(d[1] for d in h.detections)
                for h in self._technique_history.values()
            ),
            'available_color_schemes': list(ColorScheme.__members__.keys()),
            'attack_data_loaded': self._attack_data.is_loaded() if self._attack_data else False
        }


# Singleton accessor
def get_navigator_generator() -> NavigatorGenerator:
    """Get the global navigator generator instance"""
    generator = NavigatorGenerator.get_instance()
    if not generator._attack_data:
        generator.set_attack_data(get_attack_data())
    return generator
