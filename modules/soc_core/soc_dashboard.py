#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Real-Time Command Dashboard Backend
    Production-Grade SOC Dashboard API & SSE Engine
================================================================================

    Features:
    - Real-time Server-Sent Events (SSE) push for live dashboard updates
    - Alert queue statistics (active, by severity, SLA breaches)
    - MTTD / MTTR / MTTA SOC performance metrics
    - MITRE ATT&CK heatmap data (tactics × techniques matrix)
    - Analyst workload distribution
    - Top alert sources & rules
    - Shift management (SOC analyst shift tracking)
    - Dashboard widget data aggregation
    - Historical trend data (24h/7d/30d)
    - Thread-safe, no external dependencies beyond stdlib + Flask

================================================================================
"""

import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from queue import Queue, Empty
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple

logger = logging.getLogger("soc.dashboard")


# ============================================================================
# SSE (Server-Sent Events) Engine
# ============================================================================

class SSEClient:
    """Represents a connected SSE client."""
    __slots__ = ('client_id', 'queue', 'channels', 'created_at', 'user_id', 'last_activity')

    def __init__(self, client_id: str, user_id: str = "", channels: Optional[Set[str]] = None):
        self.client_id = client_id
        self.queue: Queue = Queue(maxsize=500)
        self.channels = channels or {'alerts', 'stats', 'sla'}
        self.created_at = datetime.now(timezone.utc)
        self.user_id = user_id
        self.last_activity = time.time()


class SSEBroker:
    """
    Publish/Subscribe SSE message broker.
    Manages connected clients and broadcasts events.
    """

    def __init__(self):
        self._clients: Dict[str, SSEClient] = {}
        self._lock = threading.Lock()
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def subscribe(self, user_id: str = "", channels: Optional[Set[str]] = None) -> SSEClient:
        """Register a new SSE client."""
        client = SSEClient(
            client_id=f"sse_{uuid.uuid4().hex[:12]}",
            user_id=user_id,
            channels=channels,
        )
        with self._lock:
            self._clients[client.client_id] = client
        logger.info(f"[SSE] Client connected: {client.client_id} (channels={client.channels})")
        return client

    def unsubscribe(self, client_id: str):
        """Remove a client."""
        with self._lock:
            if client_id in self._clients:
                del self._clients[client_id]
                logger.info(f"[SSE] Client disconnected: {client_id}")

    def publish(self, channel: str, event_type: str, data: Any):
        """Broadcast an event to all subscribed clients on the given channel."""
        message = f"event: {event_type}\ndata: {json.dumps(data, default=str)}\n\n"
        disconnected = []

        with self._lock:
            for cid, client in self._clients.items():
                if channel in client.channels:
                    try:
                        client.queue.put_nowait(message)
                        client.last_activity = time.time()
                    except Exception:
                        disconnected.append(cid)

            for cid in disconnected:
                del self._clients[cid]

    def stream(self, client: SSEClient) -> Generator[str, None, None]:
        """Generate SSE stream for a client."""
        # Send initial connection event
        yield f"event: connected\ndata: {json.dumps({'client_id': client.client_id})}\n\n"

        try:
            while True:
                try:
                    message = client.queue.get(timeout=30)
                    yield message
                except Empty:
                    # Send keepalive
                    yield ": keepalive\n\n"
        except GeneratorExit:
            self.unsubscribe(client.client_id)

    def get_client_count(self) -> int:
        with self._lock:
            return len(self._clients)

    def _cleanup_loop(self):
        """Remove stale clients (no activity for 5 minutes)."""
        while True:
            time.sleep(60)
            now = time.time()
            stale = []
            with self._lock:
                for cid, client in self._clients.items():
                    if now - client.last_activity > 300:
                        stale.append(cid)
                for cid in stale:
                    del self._clients[cid]
            if stale:
                logger.info(f"[SSE] Cleaned up {len(stale)} stale clients")


# ============================================================================
# SOC Shift Management
# ============================================================================

class ShiftType(Enum):
    DAY = "day"         # 08:00 - 16:00
    EVENING = "evening"  # 16:00 - 00:00
    NIGHT = "night"      # 00:00 - 08:00


class ShiftManager:
    """Manage SOC analyst shift schedules."""

    SHIFT_HOURS = {
        ShiftType.DAY: (8, 16),
        ShiftType.EVENING: (16, 24),
        ShiftType.NIGHT: (0, 8),
    }

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_dir = Path.home() / '.dalga'
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / 'soc_shifts.db')

        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS shift_schedule (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analyst_id TEXT NOT NULL,
                    analyst_name TEXT NOT NULL,
                    shift_type TEXT NOT NULL,
                    shift_date TEXT NOT NULL,
                    is_oncall INTEGER DEFAULT 0,
                    notes TEXT DEFAULT '',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(analyst_id, shift_date, shift_type)
                );

                CREATE TABLE IF NOT EXISTS shift_handoff (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_analyst TEXT NOT NULL,
                    to_analyst TEXT NOT NULL,
                    shift_date TEXT NOT NULL,
                    open_alerts INTEGER DEFAULT 0,
                    open_incidents INTEGER DEFAULT 0,
                    notes TEXT DEFAULT '',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_shift_date ON shift_schedule(shift_date);
                CREATE INDEX IF NOT EXISTS idx_shift_analyst ON shift_schedule(analyst_id);
            """)
            conn.commit()
        finally:
            conn.close()

    def get_current_shift(self) -> ShiftType:
        """Get the current shift based on UTC hour."""
        hour = datetime.now(timezone.utc).hour
        if 8 <= hour < 16:
            return ShiftType.DAY
        elif 16 <= hour < 24:
            return ShiftType.EVENING
        else:
            return ShiftType.NIGHT

    def get_on_duty(self, shift_date: Optional[str] = None,
                    shift_type: Optional[ShiftType] = None) -> List[Dict[str, Any]]:
        """Get analysts on duty for a given shift."""
        if shift_date is None:
            shift_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        if shift_type is None:
            shift_type = self.get_current_shift()

        conn = self._get_conn()
        try:
            rows = conn.execute(
                """SELECT * FROM shift_schedule
                   WHERE shift_date = ? AND shift_type = ?""",
                (shift_date, shift_type.value)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def assign_shift(self, analyst_id: str, analyst_name: str,
                     shift_type: ShiftType, shift_date: str,
                     is_oncall: bool = False) -> bool:
        """Assign an analyst to a shift."""
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO shift_schedule
                   (analyst_id, analyst_name, shift_type, shift_date, is_oncall)
                   VALUES (?, ?, ?, ?, ?)""",
                (analyst_id, analyst_name, shift_type.value, shift_date, 1 if is_oncall else 0)
            )
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"[SHIFT] Assignment error: {e}")
            return False
        finally:
            conn.close()

    def create_handoff(self, from_analyst: str, to_analyst: str,
                       open_alerts: int = 0, open_incidents: int = 0,
                       notes: str = "") -> bool:
        """Record a shift handoff."""
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT INTO shift_handoff
                   (from_analyst, to_analyst, shift_date, open_alerts, open_incidents, notes)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (from_analyst, to_analyst,
                 datetime.now(timezone.utc).strftime('%Y-%m-%d'),
                 open_alerts, open_incidents, notes)
            )
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"[SHIFT] Handoff error: {e}")
            return False
        finally:
            conn.close()


# ============================================================================
# Dashboard Data Aggregator
# ============================================================================

class DashboardAggregator:
    """
    Aggregates data from alert queue, RBAC, and other modules
    into dashboard-ready widget data.
    """

    def __init__(self, alert_db_path: Optional[str] = None):
        if alert_db_path is None:
            db_dir = Path.home() / '.dalga'
            self._alert_db = str(db_dir / 'soc_alerts.db')
        else:
            self._alert_db = alert_db_path

        self._shift_mgr = ShiftManager()
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._cache_ttl = 5  # seconds
        self._lock = threading.Lock()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._alert_db, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _cached(self, key: str) -> Optional[Any]:
        """Get cached value if not expired."""
        with self._lock:
            if key in self._cache:
                ts, val = self._cache[key]
                if time.time() - ts < self._cache_ttl:
                    return val
        return None

    def _set_cache(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = (time.time(), value)

    # ---- Widget Data Methods ----

    def get_overview(self) -> Dict[str, Any]:
        """Main overview widget: counts, SLA, performance metrics."""
        cached = self._cached('overview')
        if cached is not None:
            return cached

        conn = self._get_conn()
        try:
            now = datetime.now(timezone.utc)
            yesterday = (now - timedelta(hours=24)).isoformat()
            week_ago = (now - timedelta(days=7)).isoformat()

            # Active alerts by severity
            severity_counts = {}
            for sev_val, sev_name in [(1, 'CRITICAL'), (2, 'HIGH'), (3, 'MEDIUM'), (4, 'LOW'), (5, 'INFO')]:
                row = conn.execute(
                    """SELECT COUNT(*) FROM alerts
                       WHERE severity = ? AND status NOT IN ('resolved', 'false_positive', 'merged', 'expired')""",
                    (sev_val,)
                ).fetchone()
                severity_counts[sev_name] = row[0] if row else 0

            total_active = sum(severity_counts.values())

            # New alerts in last 24h
            new_24h = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE created_at >= ?", (yesterday,)
            ).fetchone()[0]

            # Resolved in last 24h
            resolved_24h = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'resolved' AND updated_at >= ?",
                (yesterday,)
            ).fetchone()[0]

            # False positives 24h
            fp_24h = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'false_positive' AND updated_at >= ?",
                (yesterday,)
            ).fetchone()[0]

            # SLA breaches (active)
            sla_breached = conn.execute(
                """SELECT COUNT(*) FROM alerts
                   WHERE sla_breached = 1
                   AND status NOT IN ('resolved', 'false_positive', 'merged', 'expired')"""
            ).fetchone()[0]

            # MTTD, MTTA, MTTR
            mttd, mtta, mttr = self._calculate_metrics(conn, yesterday)

            # Unassigned alerts
            unassigned = conn.execute(
                """SELECT COUNT(*) FROM alerts
                   WHERE assigned_to = '' AND status NOT IN ('resolved', 'false_positive', 'merged', 'expired')"""
            ).fetchone()[0]

            result = {
                'timestamp': now.isoformat(),
                'active_alerts': {
                    'total': total_active,
                    'by_severity': severity_counts,
                },
                'new_24h': new_24h,
                'resolved_24h': resolved_24h,
                'false_positives_24h': fp_24h,
                'sla_breached_active': sla_breached,
                'unassigned_alerts': unassigned,
                'metrics': {
                    'mttd_seconds': mttd,
                    'mttd_human': self._human_time(mttd),
                    'mtta_seconds': mtta,
                    'mtta_human': self._human_time(mtta),
                    'mttr_seconds': mttr,
                    'mttr_human': self._human_time(mttr),
                },
                'current_shift': self._shift_mgr.get_current_shift().value,
                'on_duty': self._shift_mgr.get_on_duty(),
                'sse_clients': 0,  # Will be set by blueprint
            }

            self._set_cache('overview', result)
            return result

        except sqlite3.OperationalError:
            # DB doesn't exist yet
            return {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'active_alerts': {'total': 0, 'by_severity': {}},
                'new_24h': 0, 'resolved_24h': 0, 'false_positives_24h': 0,
                'sla_breached_active': 0, 'unassigned_alerts': 0,
                'metrics': {'mttd_seconds': 0, 'mttd_human': 'N/A',
                            'mtta_seconds': 0, 'mtta_human': 'N/A',
                            'mttr_seconds': 0, 'mttr_human': 'N/A'},
                'current_shift': self._shift_mgr.get_current_shift().value,
                'on_duty': [], 'sse_clients': 0,
            }
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _calculate_metrics(self, conn, since: str) -> Tuple[float, float, float]:
        """Calculate MTTD, MTTA, MTTR from alert data."""
        rows = conn.execute(
            "SELECT data FROM alerts WHERE updated_at >= ? LIMIT 500", (since,)
        ).fetchall()

        mttd_vals = []
        mtta_vals = []
        mttr_vals = []

        for row in rows:
            try:
                d = json.loads(row['data'])
                created = d.get('created_at')
                triaged = d.get('triaged_at')
                assigned = d.get('assigned_at')
                resolved = d.get('resolved_at')

                if created and triaged:
                    dt_c = datetime.fromisoformat(created)
                    dt_t = datetime.fromisoformat(triaged)
                    mttd_vals.append((dt_t - dt_c).total_seconds())

                if created and assigned:
                    dt_c = datetime.fromisoformat(created)
                    dt_a = datetime.fromisoformat(assigned)
                    mtta_vals.append((dt_a - dt_c).total_seconds())

                if created and resolved:
                    dt_c = datetime.fromisoformat(created)
                    dt_r = datetime.fromisoformat(resolved)
                    mttr_vals.append((dt_r - dt_c).total_seconds())
            except (json.JSONDecodeError, ValueError, TypeError):
                continue

        mttd = round(sum(mttd_vals) / len(mttd_vals), 1) if mttd_vals else 0
        mtta = round(sum(mtta_vals) / len(mtta_vals), 1) if mtta_vals else 0
        mttr = round(sum(mttr_vals) / len(mttr_vals), 1) if mttr_vals else 0

        return mttd, mtta, mttr

    def get_mitre_heatmap(self) -> Dict[str, Any]:
        """Generate MITRE ATT&CK heatmap data from active alerts."""
        cached = self._cached('mitre_heatmap')
        if cached is not None:
            return cached

        # MITRE ATT&CK Enterprise tactics
        tactics = [
            'TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004',
            'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0010',
            'TA0011', 'TA0040',
        ]
        tactic_names = {
            'TA0043': 'Reconnaissance', 'TA0042': 'Resource Development',
            'TA0001': 'Initial Access', 'TA0002': 'Execution',
            'TA0003': 'Persistence', 'TA0004': 'Privilege Escalation',
            'TA0005': 'Defense Evasion', 'TA0006': 'Credential Access',
            'TA0007': 'Discovery', 'TA0008': 'Lateral Movement',
            'TA0009': 'Collection', 'TA0010': 'Exfiltration',
            'TA0011': 'Command & Control', 'TA0040': 'Impact',
        }

        tactic_counts = Counter()
        technique_counts = Counter()
        tactic_technique_map = defaultdict(Counter)

        try:
            conn = self._get_conn()
            rows = conn.execute(
                """SELECT data FROM alerts
                   WHERE status NOT IN ('resolved', 'false_positive', 'merged', 'expired')"""
            ).fetchall()
            conn.close()

            for row in rows:
                try:
                    d = json.loads(row['data'])
                    alert_tactics = d.get('mitre_tactics', [])
                    alert_techniques = d.get('mitre_techniques', [])

                    for t in alert_tactics:
                        tactic_counts[t] += 1
                    for tech in alert_techniques:
                        technique_counts[tech] += 1
                        for t in alert_tactics:
                            tactic_technique_map[t][tech] += 1
                except (json.JSONDecodeError, KeyError):
                    continue

        except sqlite3.OperationalError:
            pass

        # Build heatmap matrix
        heatmap = []
        for tactic_id in tactics:
            techniques = dict(tactic_technique_map.get(tactic_id, {}))
            heatmap.append({
                'tactic_id': tactic_id,
                'tactic_name': tactic_names.get(tactic_id, tactic_id),
                'count': tactic_counts.get(tactic_id, 0),
                'techniques': techniques,
            })

        result = {
            'heatmap': heatmap,
            'top_techniques': technique_counts.most_common(20),
            'top_tactics': tactic_counts.most_common(14),
            'total_mapped_alerts': sum(tactic_counts.values()),
        }

        self._set_cache('mitre_heatmap', result)
        return result

    def get_analyst_workload(self) -> Dict[str, Any]:
        """Get alert distribution per analyst."""
        cached = self._cached('analyst_workload')
        if cached is not None:
            return cached

        try:
            conn = self._get_conn()
            rows = conn.execute(
                """SELECT assigned_to, severity, COUNT(*) as cnt
                   FROM alerts
                   WHERE status NOT IN ('resolved', 'false_positive', 'merged', 'expired')
                   AND assigned_to != ''
                   GROUP BY assigned_to, severity"""
            ).fetchall()
            conn.close()

            workload = defaultdict(lambda: {'total': 0, 'by_severity': {}})
            severity_map = {1: 'CRITICAL', 2: 'HIGH', 3: 'MEDIUM', 4: 'LOW', 5: 'INFO'}

            for row in rows:
                analyst = row['assigned_to']
                sev_name = severity_map.get(row['severity'], 'UNKNOWN')
                workload[analyst]['by_severity'][sev_name] = row['cnt']
                workload[analyst]['total'] += row['cnt']

            result = {
                'analysts': dict(workload),
                'analyst_count': len(workload),
            }

            self._set_cache('analyst_workload', result)
            return result

        except sqlite3.OperationalError:
            return {'analysts': {}, 'analyst_count': 0}

    def get_top_sources(self, limit: int = 10) -> Dict[str, Any]:
        """Get top alert sources and rules."""
        cached = self._cached('top_sources')
        if cached is not None:
            return cached

        try:
            conn = self._get_conn()
            now = datetime.now(timezone.utc)
            yesterday = (now - timedelta(hours=24)).isoformat()

            # Top sources
            source_rows = conn.execute(
                """SELECT json_extract(data, '$.source') as source, COUNT(*) as cnt
                   FROM alerts WHERE created_at >= ?
                   GROUP BY source ORDER BY cnt DESC LIMIT ?""",
                (yesterday, limit)
            ).fetchall()

            # Top rules
            rule_rows = conn.execute(
                """SELECT json_extract(data, '$.source_rule') as rule, COUNT(*) as cnt
                   FROM alerts WHERE created_at >= ?
                   AND json_extract(data, '$.source_rule') != ''
                   GROUP BY rule ORDER BY cnt DESC LIMIT ?""",
                (yesterday, limit)
            ).fetchall()

            conn.close()

            result = {
                'top_sources': [{'source': r['source'], 'count': r['cnt']} for r in source_rows],
                'top_rules': [{'rule': r['rule'], 'count': r['cnt']} for r in rule_rows],
            }

            self._set_cache('top_sources', result)
            return result

        except sqlite3.OperationalError:
            return {'top_sources': [], 'top_rules': []}

    def get_trend_data(self, hours: int = 24) -> Dict[str, Any]:
        """Get alert trend data for charting (hourly buckets)."""
        cache_key = f'trend_{hours}'
        cached = self._cached(cache_key)
        if cached is not None:
            return cached

        try:
            conn = self._get_conn()
            now = datetime.now(timezone.utc)
            since = (now - timedelta(hours=hours)).isoformat()

            rows = conn.execute(
                "SELECT data, created_at FROM alerts WHERE created_at >= ? ORDER BY created_at",
                (since,)
            ).fetchall()
            conn.close()

            # Bucket by hour
            buckets = defaultdict(lambda: {'total': 0, 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0})

            for row in rows:
                try:
                    d = json.loads(row['data'])
                    created = d.get('created_at', '')
                    if created:
                        dt = datetime.fromisoformat(created)
                        bucket_key = dt.strftime('%Y-%m-%d %H:00')
                        sev = d.get('severity', 'MEDIUM')
                        buckets[bucket_key]['total'] += 1
                        if sev in buckets[bucket_key]:
                            buckets[bucket_key][sev] += 1
                except (json.JSONDecodeError, ValueError):
                    continue

            # Convert to sorted list
            trend = [{'time': k, **v} for k, v in sorted(buckets.items())]

            result = {
                'hours': hours,
                'buckets': trend,
                'total_alerts': sum(b['total'] for b in trend),
            }

            self._set_cache(cache_key, result)
            return result

        except sqlite3.OperationalError:
            return {'hours': hours, 'buckets': [], 'total_alerts': 0}

    def get_recent_alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get most recent alerts for live feed."""
        try:
            conn = self._get_conn()
            rows = conn.execute(
                """SELECT data FROM alerts
                   ORDER BY created_at DESC LIMIT ?""",
                (limit,)
            ).fetchall()
            conn.close()

            return [json.loads(r['data']) for r in rows]

        except sqlite3.OperationalError:
            return []

    def get_full_dashboard(self) -> Dict[str, Any]:
        """Get all dashboard data in a single call."""
        return {
            'overview': self.get_overview(),
            'mitre_heatmap': self.get_mitre_heatmap(),
            'analyst_workload': self.get_analyst_workload(),
            'top_sources': self.get_top_sources(),
            'trend_24h': self.get_trend_data(24),
            'recent_alerts': self.get_recent_alerts(20),
        }

    @staticmethod
    def _human_time(seconds: float) -> str:
        if seconds <= 0:
            return "N/A"
        if seconds < 60:
            return f"{int(seconds)}s"
        if seconds < 3600:
            return f"{int(seconds / 60)}m {int(seconds % 60)}s"
        hours = seconds / 3600
        return f"{hours:.1f}h"


# ============================================================================
# Dashboard Push Engine (Periodic SSE Publisher)
# ============================================================================

class DashboardPushEngine:
    """
    Periodically pushes dashboard updates to connected SSE clients.
    Integrates with AlertQueue callbacks for real-time event push.
    """

    def __init__(self, broker: SSEBroker, aggregator: DashboardAggregator,
                 push_interval: int = 10):
        self._broker = broker
        self._aggregator = aggregator
        self._push_interval = push_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start the push engine."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._push_loop, daemon=True)
        self._thread.start()
        logger.info(f"[DASHBOARD] Push engine started (interval={self._push_interval}s)")

    def stop(self):
        """Stop the push engine."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _push_loop(self):
        """Main push loop - sends periodic updates."""
        while self._running:
            try:
                if self._broker.get_client_count() > 0:
                    # Push overview stats
                    overview = self._aggregator.get_overview()
                    overview['sse_clients'] = self._broker.get_client_count()
                    self._broker.publish('stats', 'dashboard_update', overview)

                    # Push recent alerts
                    recent = self._aggregator.get_recent_alerts(5)
                    if recent:
                        self._broker.publish('alerts', 'recent_alerts', recent)

            except Exception as e:
                logger.error(f"[DASHBOARD] Push error: {e}")

            time.sleep(self._push_interval)

    # --- Alert Queue Integration Callbacks ---

    def on_new_alert(self, alert):
        """Callback: push new alert to all SSE clients."""
        try:
            data = alert.to_dict() if hasattr(alert, 'to_dict') else alert
            self._broker.publish('alerts', 'new_alert', data)
        except Exception as e:
            logger.error(f"[DASHBOARD] New alert push error: {e}")

    def on_sla_breach(self, alert):
        """Callback: push SLA breach notification."""
        try:
            data = alert.to_dict() if hasattr(alert, 'to_dict') else alert
            self._broker.publish('sla', 'sla_breach', {
                'alert_id': data.get('alert_id', ''),
                'title': data.get('title', ''),
                'severity': data.get('severity', ''),
                'sla_deadline': data.get('sla_deadline', ''),
            })
        except Exception as e:
            logger.error(f"[DASHBOARD] SLA breach push error: {e}")

    def on_status_change(self, alert, old_status, new_status):
        """Callback: push status change."""
        try:
            data = alert.to_dict() if hasattr(alert, 'to_dict') else alert
            self._broker.publish('alerts', 'status_change', {
                'alert_id': data.get('alert_id', ''),
                'title': data.get('title', ''),
                'old_status': old_status.value if hasattr(old_status, 'value') else str(old_status),
                'new_status': new_status.value if hasattr(new_status, 'value') else str(new_status),
            })
        except Exception as e:
            logger.error(f"[DASHBOARD] Status change push error: {e}")


# ============================================================================
# Flask Blueprint
# ============================================================================

def create_dashboard_blueprint(aggregator: Optional[DashboardAggregator] = None,
                                broker: Optional[SSEBroker] = None):
    """Create Flask Blueprint for SOC Dashboard API."""
    try:
        from flask import Blueprint, jsonify, request, Response
    except ImportError:
        logger.warning("[DASHBOARD] Flask not installed. Blueprint unavailable.")
        return None

    if aggregator is None:
        aggregator = DashboardAggregator()
    if broker is None:
        broker = SSEBroker()

    bp = Blueprint('soc_dashboard', __name__, url_prefix='/api/v1/soc/dashboard')

    @bp.route('/overview', methods=['GET'])
    def dashboard_overview():
        """Get dashboard overview data."""
        data = aggregator.get_overview()
        data['sse_clients'] = broker.get_client_count()
        return jsonify({'success': True, 'data': data})

    @bp.route('/full', methods=['GET'])
    def dashboard_full():
        """Get all dashboard data in a single call."""
        data = aggregator.get_full_dashboard()
        data['overview']['sse_clients'] = broker.get_client_count()
        return jsonify({'success': True, 'data': data})

    @bp.route('/mitre-heatmap', methods=['GET'])
    def mitre_heatmap():
        """Get MITRE ATT&CK heatmap data."""
        return jsonify({'success': True, 'data': aggregator.get_mitre_heatmap()})

    @bp.route('/analyst-workload', methods=['GET'])
    def analyst_workload():
        """Get analyst workload distribution."""
        return jsonify({'success': True, 'data': aggregator.get_analyst_workload()})

    @bp.route('/top-sources', methods=['GET'])
    def top_sources():
        """Get top alert sources and rules."""
        limit = request.args.get('limit', 10, type=int)
        return jsonify({'success': True, 'data': aggregator.get_top_sources(limit)})

    @bp.route('/trend', methods=['GET'])
    def trend_data():
        """Get alert trend data for charting."""
        hours = request.args.get('hours', 24, type=int)
        hours = min(hours, 720)  # Max 30 days
        return jsonify({'success': True, 'data': aggregator.get_trend_data(hours)})

    @bp.route('/recent-alerts', methods=['GET'])
    def recent_alerts():
        """Get most recent alerts."""
        limit = request.args.get('limit', 20, type=int)
        limit = min(limit, 100)
        return jsonify({'success': True, 'data': aggregator.get_recent_alerts(limit)})

    @bp.route('/stream', methods=['GET'])
    def sse_stream():
        """SSE stream endpoint for real-time updates."""
        channels_param = request.args.get('channels', 'alerts,stats,sla')
        channels = set(c.strip() for c in channels_param.split(','))

        user_id = request.args.get('user_id', '')
        client = broker.subscribe(user_id=user_id, channels=channels)

        return Response(
            broker.stream(client),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no',
            }
        )

    @bp.route('/shift/current', methods=['GET'])
    def current_shift():
        """Get current shift info and on-duty analysts."""
        shift_mgr = aggregator._shift_mgr
        return jsonify({
            'success': True,
            'data': {
                'current_shift': shift_mgr.get_current_shift().value,
                'on_duty': shift_mgr.get_on_duty(),
            }
        })

    @bp.route('/shift/assign', methods=['POST'])
    def assign_shift():
        """Assign analyst to a shift."""
        data = request.get_json(force=True)
        shift_mgr = aggregator._shift_mgr

        shift_type_str = data.get('shift_type', 'day')
        try:
            shift_type = ShiftType(shift_type_str)
        except ValueError:
            return jsonify({'success': False, 'error': 'Gecersiz shift tipi'}), 400

        success = shift_mgr.assign_shift(
            analyst_id=data.get('analyst_id', ''),
            analyst_name=data.get('analyst_name', ''),
            shift_type=shift_type,
            shift_date=data.get('shift_date', datetime.now(timezone.utc).strftime('%Y-%m-%d')),
            is_oncall=data.get('is_oncall', False),
        )

        return jsonify({'success': success})

    @bp.route('/shift/handoff', methods=['POST'])
    def shift_handoff():
        """Record a shift handoff."""
        data = request.get_json(force=True)
        shift_mgr = aggregator._shift_mgr

        success = shift_mgr.create_handoff(
            from_analyst=data.get('from_analyst', ''),
            to_analyst=data.get('to_analyst', ''),
            open_alerts=data.get('open_alerts', 0),
            open_incidents=data.get('open_incidents', 0),
            notes=data.get('notes', ''),
        )

        return jsonify({'success': success})

    return bp


# ============================================================================
# Global Instances
# ============================================================================

_sse_broker: Optional[SSEBroker] = None
_dashboard_aggregator: Optional[DashboardAggregator] = None
_push_engine: Optional[DashboardPushEngine] = None
_init_lock = threading.Lock()


def get_sse_broker() -> SSEBroker:
    global _sse_broker
    if _sse_broker is None:
        with _init_lock:
            if _sse_broker is None:
                _sse_broker = SSEBroker()
    return _sse_broker


def get_dashboard_aggregator() -> DashboardAggregator:
    global _dashboard_aggregator
    if _dashboard_aggregator is None:
        with _init_lock:
            if _dashboard_aggregator is None:
                _dashboard_aggregator = DashboardAggregator()
    return _dashboard_aggregator


def get_push_engine() -> DashboardPushEngine:
    global _push_engine
    if _push_engine is None:
        with _init_lock:
            if _push_engine is None:
                _push_engine = DashboardPushEngine(
                    broker=get_sse_broker(),
                    aggregator=get_dashboard_aggregator(),
                )
    return _push_engine


def init_dashboard_system():
    """Initialize the full dashboard system and start push engine."""
    broker = get_sse_broker()
    aggregator = get_dashboard_aggregator()
    engine = get_push_engine()

    # Wire up alert queue callbacks if available
    try:
        from modules.soc_core.alert_queue import get_alert_queue
        queue = get_alert_queue()
        queue.on_new_alert(engine.on_new_alert)
        queue.on_sla_breach(engine.on_sla_breach)
        queue.on_status_change(engine.on_status_change)
        logger.info("[DASHBOARD] Alert queue callbacks wired")
    except ImportError:
        logger.warning("[DASHBOARD] Alert queue not available")

    engine.start()
    return broker, aggregator, engine


__all__ = [
    'SSEBroker', 'SSEClient', 'ShiftType', 'ShiftManager',
    'DashboardAggregator', 'DashboardPushEngine',
    'create_dashboard_blueprint',
    'get_sse_broker', 'get_dashboard_aggregator', 'get_push_engine',
    'init_dashboard_system',
]
