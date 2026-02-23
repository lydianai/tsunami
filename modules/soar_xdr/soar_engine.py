#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOAR Engine - Facade for SOAR/XDR subsystem.
Provides unified access to PlaybookEngine, IncidentManager,
CorrelationEngine, ResponseOrchestrator, and ActionLibrary.
"""

from datetime import datetime
from typing import Dict, Any, Optional

from .playbook_engine import get_playbook_engine
from .action_library import get_action_library
from .incident_manager import get_incident_manager
from .correlation_engine import get_correlation_engine
from .response_orchestrator import get_response_orchestrator


class SOAREngine:
    """Unified SOAR/XDR engine facade."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._start_time = datetime.now()

        # Initialize sub-engines (lazy - they use singletons)
        self._playbook_engine = None
        self._action_library = None
        self._incident_manager = None
        self._correlation_engine = None
        self._response_orchestrator = None

    @property
    def playbook_engine(self):
        if self._playbook_engine is None:
            self._playbook_engine = get_playbook_engine()
        return self._playbook_engine

    @property
    def action_library(self):
        if self._action_library is None:
            self._action_library = get_action_library()
        return self._action_library

    @property
    def incident_manager(self):
        if self._incident_manager is None:
            self._incident_manager = get_incident_manager()
        return self._incident_manager

    @property
    def correlation_engine(self):
        if self._correlation_engine is None:
            self._correlation_engine = get_correlation_engine()
        return self._correlation_engine

    @property
    def response_orchestrator(self):
        if self._response_orchestrator is None:
            self._response_orchestrator = get_response_orchestrator()
        return self._response_orchestrator

    def get_stats(self) -> Dict[str, Any]:
        """Get combined SOAR statistics from all sub-engines."""
        stats = {
            'uptime_seconds': (datetime.now() - self._start_time).total_seconds(),
            'engine_version': '5.0.0',
        }

        # Playbook stats
        try:
            pe = self.playbook_engine
            playbooks = pe.list_playbooks() if hasattr(pe, 'list_playbooks') else []
            executions = pe.list_executions() if hasattr(pe, 'list_executions') else []
            stats['total_playbooks'] = len(playbooks)
            stats['total_executions'] = len(executions)
            stats['successful_executions'] = len([
                e for e in executions
                if hasattr(e, 'status') and str(e.status) in ('completed', 'success')
            ])
        except Exception:
            stats['total_playbooks'] = 0
            stats['total_executions'] = 0
            stats['successful_executions'] = 0

        # Action library stats
        try:
            al = self.action_library
            stats['available_actions'] = len(al._actions) if hasattr(al, '_actions') else 0
        except Exception:
            stats['available_actions'] = 0

        # Incident stats
        try:
            im = self.incident_manager
            incidents = im.list_incidents() if hasattr(im, 'list_incidents') else []
            stats['total_incidents'] = len(incidents)
            stats['open_incidents'] = len([
                i for i in incidents
                if hasattr(i, 'status') and str(i.status) in ('open', 'investigating', 'in_progress')
            ])
            stats['pending_approvals'] = 0
        except Exception:
            stats['total_incidents'] = 0
            stats['open_incidents'] = 0
            stats['pending_approvals'] = 0

        # Correlation stats
        try:
            ce = self.correlation_engine
            rules = ce.list_rules() if hasattr(ce, 'list_rules') else []
            stats['correlation_rules'] = len(rules)
            stats['active_rules'] = len([
                r for r in rules
                if hasattr(r, 'enabled') and r.enabled
            ])
        except Exception:
            stats['correlation_rules'] = 0
            stats['active_rules'] = 0

        # Response stats
        try:
            ro = self.response_orchestrator
            stats['auto_responses'] = ro.auto_response_count if hasattr(ro, 'auto_response_count') else 0
        except Exception:
            stats['auto_responses'] = 0

        return stats

    def is_active(self) -> bool:
        """Check if SOAR engine is active."""
        return self._initialized


def get_soar_engine() -> SOAREngine:
    """Get or create singleton SOAREngine instance."""
    return SOAREngine()
