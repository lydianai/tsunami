#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 UNIFIED DASHBOARD
    Aggregated metrics and data for the security dashboard
================================================================================

    Features:
    - Aggregate metrics from all v5 modules
    - Real-time status updates
    - Alert consolidation across all sources
    - Risk score calculation
    - Executive summary generation

================================================================================
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict
import json
import math

logger = logging.getLogger("unified_dashboard")


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    """Alert status values"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class ConsolidatedAlert:
    """A consolidated alert from any source"""
    id: str
    title: str
    description: str
    severity: AlertSeverity
    status: AlertStatus
    source: str  # Which module generated it
    timestamp: datetime
    related_alerts: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "related_alerts": self.related_alerts,
            "mitre_techniques": self.mitre_techniques,
            "affected_assets": self.affected_assets,
            "recommended_actions": self.recommended_actions,
            "evidence": self.evidence,
            "risk_score": self.risk_score
        }


@dataclass
class DashboardMetrics:
    """Aggregated metrics for the dashboard"""
    timestamp: datetime
    total_events_24h: int = 0
    total_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    open_incidents: int = 0
    blocked_threats: int = 0
    active_investigations: int = 0
    threat_intel_matches: int = 0
    vulnerabilities_found: int = 0
    auto_remediated: int = 0
    mean_time_to_detect: float = 0.0  # Minutes
    mean_time_to_respond: float = 0.0  # Minutes
    overall_risk_score: float = 0.0
    module_metrics: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "total_events_24h": self.total_events_24h,
            "total_alerts": self.total_alerts,
            "alerts_by_severity": {
                "critical": self.critical_alerts,
                "high": self.high_alerts,
                "medium": self.medium_alerts,
                "low": self.low_alerts
            },
            "open_incidents": self.open_incidents,
            "blocked_threats": self.blocked_threats,
            "active_investigations": self.active_investigations,
            "threat_intel_matches": self.threat_intel_matches,
            "vulnerabilities_found": self.vulnerabilities_found,
            "auto_remediated": self.auto_remediated,
            "mean_time_to_detect": self.mean_time_to_detect,
            "mean_time_to_respond": self.mean_time_to_respond,
            "overall_risk_score": self.overall_risk_score,
            "module_metrics": self.module_metrics
        }


class RiskScoreCalculator:
    """
    Calculate overall and per-asset risk scores.
    Uses multiple factors weighted by importance.
    """

    # Risk factor weights
    WEIGHTS = {
        "critical_vulnerabilities": 25.0,
        "active_threats": 20.0,
        "unpatched_systems": 15.0,
        "open_incidents": 15.0,
        "attack_surface": 10.0,
        "compliance_gaps": 10.0,
        "threat_intel_exposure": 5.0
    }

    @classmethod
    def calculate_overall_score(cls, factors: Dict[str, float]) -> float:
        """
        Calculate overall risk score (0-100).

        Args:
            factors: Dict of factor_name -> normalized value (0-1)

        Returns:
            Risk score 0-100
        """
        total_weight = sum(cls.WEIGHTS.values())
        weighted_sum = 0.0

        for factor, value in factors.items():
            weight = cls.WEIGHTS.get(factor, 0)
            # Ensure value is in 0-1 range
            normalized_value = max(0, min(1, value))
            weighted_sum += normalized_value * weight

        return round(weighted_sum * 100 / total_weight, 1)

    @classmethod
    def calculate_asset_risk(cls, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate risk score for a specific asset.

        Args:
            asset_data: Asset information including vulnerabilities, threats, etc.

        Returns:
            Risk assessment with score and breakdown
        """
        factors = {
            "critical_vulnerabilities": asset_data.get("critical_vulns", 0) / 10,  # Max 10
            "active_threats": 1.0 if asset_data.get("has_active_threats", False) else 0.0,
            "unpatched_systems": asset_data.get("patch_compliance", 1.0),  # Inverse
            "open_incidents": asset_data.get("open_incidents", 0) / 5,  # Max 5
            "attack_surface": asset_data.get("exposure_score", 0),
            "compliance_gaps": 1 - asset_data.get("compliance_score", 1.0),
            "threat_intel_exposure": asset_data.get("threat_intel_hits", 0) / 10
        }

        score = cls.calculate_overall_score(factors)

        # Determine risk level
        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 40:
            level = "MEDIUM"
        elif score >= 20:
            level = "LOW"
        else:
            level = "MINIMAL"

        return {
            "score": score,
            "level": level,
            "factors": factors,
            "calculated_at": datetime.now().isoformat()
        }


class AlertConsolidator:
    """
    Consolidate and deduplicate alerts from multiple sources.
    """

    def __init__(self):
        self._alerts: Dict[str, ConsolidatedAlert] = {}
        self._alert_groups: Dict[str, List[str]] = defaultdict(list)  # Group by correlation
        self._lock = threading.Lock()

    def add_alert(self, alert: ConsolidatedAlert) -> str:
        """Add or update an alert"""
        with self._lock:
            # Check for duplicates based on title and source within time window
            existing = self._find_duplicate(alert)
            if existing:
                # Merge with existing alert
                existing.related_alerts.append(alert.id)
                if alert.severity.value < existing.severity.value:  # More severe
                    existing.severity = alert.severity
                return existing.id

            self._alerts[alert.id] = alert
            return alert.id

    def _find_duplicate(self, alert: ConsolidatedAlert, time_window_minutes: int = 30) -> Optional[ConsolidatedAlert]:
        """Find potential duplicate alert"""
        cutoff = datetime.now() - timedelta(minutes=time_window_minutes)

        for existing in self._alerts.values():
            if (existing.title == alert.title and
                    existing.source == alert.source and
                    existing.timestamp > cutoff):
                return existing
        return None

    def get_alerts(self, severity: Optional[AlertSeverity] = None,
                   status: Optional[AlertStatus] = None,
                   source: Optional[str] = None,
                   limit: int = 100) -> List[ConsolidatedAlert]:
        """Get alerts with optional filtering"""
        with self._lock:
            alerts = list(self._alerts.values())

            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            if status:
                alerts = [a for a in alerts if a.status == status]
            if source:
                alerts = [a for a in alerts if a.source == source]

            # Sort by timestamp descending
            alerts.sort(key=lambda a: a.timestamp, reverse=True)
            return alerts[:limit]

    def get_alert_counts(self) -> Dict[str, int]:
        """Get alert counts by severity"""
        with self._lock:
            counts = defaultdict(int)
            for alert in self._alerts.values():
                counts[alert.severity.value] += 1
            return dict(counts)

    def update_alert_status(self, alert_id: str, status: AlertStatus) -> bool:
        """Update alert status"""
        with self._lock:
            if alert_id in self._alerts:
                self._alerts[alert_id].status = status
                return True
            return False

    def correlate_alerts(self, correlation_key: str, alert_ids: List[str]) -> None:
        """Group related alerts together"""
        with self._lock:
            self._alert_groups[correlation_key].extend(alert_ids)
            for alert_id in alert_ids:
                if alert_id in self._alerts:
                    self._alerts[alert_id].related_alerts.extend(
                        [aid for aid in alert_ids if aid != alert_id]
                    )


@dataclass
class ExecutiveSummary:
    """Executive-level security summary"""
    generated_at: datetime
    period: str  # "daily", "weekly", "monthly"
    risk_posture: str  # "CRITICAL", "HIGH", "MODERATE", "LOW", "EXCELLENT"
    overall_score: float
    key_findings: List[str]
    top_threats: List[Dict[str, Any]]
    incident_summary: Dict[str, int]
    improvement_areas: List[str]
    recommendations: List[str]
    trend_analysis: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "period": self.period,
            "risk_posture": self.risk_posture,
            "overall_score": self.overall_score,
            "key_findings": self.key_findings,
            "top_threats": self.top_threats,
            "incident_summary": self.incident_summary,
            "improvement_areas": self.improvement_areas,
            "recommendations": self.recommendations,
            "trend_analysis": self.trend_analysis
        }


class UnifiedDashboard:
    """
    Central dashboard aggregating data from all v5 modules.
    """

    def __init__(self):
        self.alert_consolidator = AlertConsolidator()
        self.risk_calculator = RiskScoreCalculator()
        self._metrics_cache: Optional[DashboardMetrics] = None
        self._cache_ttl = 60  # Seconds
        self._last_cache_time: Optional[datetime] = None
        self._lock = threading.Lock()

        # Historical data for trends
        self._metrics_history: List[DashboardMetrics] = []
        self._max_history = 1000

    def _get_orchestrator(self):
        """Get orchestrator instance (lazy import to avoid circular deps)"""
        from .v5_orchestrator import get_orchestrator
        return get_orchestrator()

    def collect_metrics(self, force_refresh: bool = False) -> DashboardMetrics:
        """
        Collect and aggregate metrics from all modules.

        Args:
            force_refresh: Bypass cache and collect fresh data

        Returns:
            Aggregated metrics
        """
        # Check cache
        if not force_refresh and self._metrics_cache and self._last_cache_time:
            age = (datetime.now() - self._last_cache_time).total_seconds()
            if age < self._cache_ttl:
                return self._metrics_cache

        with self._lock:
            metrics = DashboardMetrics(timestamp=datetime.now())
            orchestrator = self._get_orchestrator()

            # Collect from threat_intel module
            threat_intel = orchestrator.get_module("threat_intel")
            if threat_intel:
                try:
                    correlator = threat_intel.get_correlator()
                    if correlator:
                        ti_stats = correlator.get_stats() if hasattr(correlator, 'get_stats') else {}
                        metrics.threat_intel_matches = ti_stats.get("total_matches", 0)
                        metrics.module_metrics["threat_intel"] = ti_stats
                except Exception as e:
                    logger.warning(f"Error collecting threat_intel metrics: {e}")

            # Collect from ai_prediction module
            ai_prediction = orchestrator.get_module("ai_prediction")
            if ai_prediction:
                try:
                    if hasattr(ai_prediction, 'ThreatPredictor'):
                        predictor = ai_prediction.ThreatPredictor()
                        metrics.module_metrics["ai_prediction"] = {
                            "model_loaded": True,
                            "predictions_made": 0  # Would track actual predictions
                        }
                except Exception as e:
                    logger.warning(f"Error collecting ai_prediction metrics: {e}")

            # Collect from soar_xdr module
            soar_xdr = orchestrator.get_module("soar_xdr")
            if soar_xdr:
                try:
                    incident_manager = soar_xdr.get_incident_manager()
                    if incident_manager:
                        metrics.open_incidents = incident_manager.get_open_count() if hasattr(incident_manager, 'get_open_count') else 0
                        metrics.active_investigations = incident_manager.get_active_investigations() if hasattr(incident_manager, 'get_active_investigations') else 0
                        metrics.module_metrics["soar_xdr"] = {
                            "playbooks_executed": 0,
                            "actions_taken": 0
                        }
                except Exception as e:
                    logger.warning(f"Error collecting soar_xdr metrics: {e}")

            # Collect from self_healing module
            self_healing = orchestrator.get_module("self_healing")
            if self_healing:
                try:
                    metrics.auto_remediated = 0  # Would track actual remediations
                    metrics.module_metrics["self_healing"] = {
                        "policies_active": 0,
                        "remediations_24h": 0
                    }
                except Exception as e:
                    logger.warning(f"Error collecting self_healing metrics: {e}")

            # Collect from auto_pentest module
            auto_pentest = orchestrator.get_module("auto_pentest")
            if auto_pentest:
                try:
                    metrics.vulnerabilities_found = 0  # Would track actual vulns
                    metrics.module_metrics["auto_pentest"] = {
                        "scans_completed": 0,
                        "critical_vulns": 0
                    }
                except Exception as e:
                    logger.warning(f"Error collecting auto_pentest metrics: {e}")

            # Collect from agentic_soc module
            agentic_soc = orchestrator.get_module("agentic_soc")
            if agentic_soc:
                try:
                    metrics.module_metrics["agentic_soc"] = {
                        "alerts_triaged": 0,
                        "investigations_auto": 0
                    }
                except Exception as e:
                    logger.warning(f"Error collecting agentic_soc metrics: {e}")

            # Aggregate alert counts
            alert_counts = self.alert_consolidator.get_alert_counts()
            metrics.critical_alerts = alert_counts.get("critical", 0)
            metrics.high_alerts = alert_counts.get("high", 0)
            metrics.medium_alerts = alert_counts.get("medium", 0)
            metrics.low_alerts = alert_counts.get("low", 0)
            metrics.total_alerts = sum(alert_counts.values())

            # Calculate overall risk score
            risk_factors = {
                "critical_vulnerabilities": min(metrics.vulnerabilities_found / 50, 1.0),
                "active_threats": min(metrics.critical_alerts / 10, 1.0),
                "open_incidents": min(metrics.open_incidents / 20, 1.0),
                "threat_intel_exposure": min(metrics.threat_intel_matches / 100, 1.0)
            }
            metrics.overall_risk_score = self.risk_calculator.calculate_overall_score(risk_factors)

            # Update cache
            self._metrics_cache = metrics
            self._last_cache_time = datetime.now()

            # Store in history
            self._metrics_history.append(metrics)
            if len(self._metrics_history) > self._max_history:
                self._metrics_history = self._metrics_history[-self._max_history:]

            return metrics

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get complete dashboard data package"""
        metrics = self.collect_metrics()
        orchestrator = self._get_orchestrator()

        return {
            "metrics": metrics.to_dict(),
            "alerts": {
                "recent": [a.to_dict() for a in self.alert_consolidator.get_alerts(limit=20)],
                "counts": self.alert_consolidator.get_alert_counts()
            },
            "system_status": orchestrator.get_status(),
            "risk_assessment": {
                "overall_score": metrics.overall_risk_score,
                "level": self._score_to_level(metrics.overall_risk_score),
                "trend": self._calculate_trend()
            }
        }

    def _score_to_level(self, score: float) -> str:
        """Convert risk score to level string"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MODERATE"
        elif score >= 20:
            return "LOW"
        else:
            return "EXCELLENT"

    def _calculate_trend(self) -> Dict[str, Any]:
        """Calculate risk trend from historical data"""
        if len(self._metrics_history) < 2:
            return {"direction": "stable", "change": 0}

        current = self._metrics_history[-1].overall_risk_score
        previous = self._metrics_history[-2].overall_risk_score
        change = current - previous

        if change > 5:
            direction = "increasing"
        elif change < -5:
            direction = "decreasing"
        else:
            direction = "stable"

        return {
            "direction": direction,
            "change": round(change, 1),
            "current": current,
            "previous": previous
        }

    def generate_executive_summary(self, period: str = "daily") -> ExecutiveSummary:
        """Generate executive-level security summary"""
        metrics = self.collect_metrics(force_refresh=True)

        # Determine risk posture
        risk_posture = self._score_to_level(metrics.overall_risk_score)

        # Generate key findings
        key_findings = []
        if metrics.critical_alerts > 0:
            key_findings.append(f"{metrics.critical_alerts} critical alerts require immediate attention")
        if metrics.threat_intel_matches > 10:
            key_findings.append(f"{metrics.threat_intel_matches} threat intelligence matches detected")
        if metrics.open_incidents > 5:
            key_findings.append(f"{metrics.open_incidents} security incidents currently open")
        if metrics.auto_remediated > 0:
            key_findings.append(f"{metrics.auto_remediated} threats automatically remediated")

        # Top threats
        top_threats = [a.to_dict() for a in self.alert_consolidator.get_alerts(
            severity=AlertSeverity.CRITICAL, limit=5
        )]

        # Recommendations based on current state
        recommendations = []
        if metrics.overall_risk_score > 60:
            recommendations.append("Immediate review of all critical alerts recommended")
        if metrics.mean_time_to_respond > 60:
            recommendations.append("Consider automation to reduce response time")
        if metrics.open_incidents > 10:
            recommendations.append("Allocate additional resources for incident response")

        return ExecutiveSummary(
            generated_at=datetime.now(),
            period=period,
            risk_posture=risk_posture,
            overall_score=metrics.overall_risk_score,
            key_findings=key_findings,
            top_threats=top_threats,
            incident_summary={
                "open": metrics.open_incidents,
                "investigating": metrics.active_investigations,
                "remediated": metrics.auto_remediated
            },
            improvement_areas=self._identify_improvement_areas(metrics),
            recommendations=recommendations,
            trend_analysis=self._calculate_trend()
        )

    def _identify_improvement_areas(self, metrics: DashboardMetrics) -> List[str]:
        """Identify areas needing improvement"""
        areas = []

        if metrics.mean_time_to_detect > 30:
            areas.append("Detection time above target (30 min)")
        if metrics.mean_time_to_respond > 60:
            areas.append("Response time above target (60 min)")
        if metrics.vulnerabilities_found > 20:
            areas.append("High number of unaddressed vulnerabilities")

        return areas


# Singleton instance
_dashboard_instance: Optional[UnifiedDashboard] = None
_dashboard_lock = threading.Lock()


def get_dashboard() -> UnifiedDashboard:
    """Get or create the singleton dashboard instance"""
    global _dashboard_instance
    with _dashboard_lock:
        if _dashboard_instance is None:
            _dashboard_instance = UnifiedDashboard()
        return _dashboard_instance
