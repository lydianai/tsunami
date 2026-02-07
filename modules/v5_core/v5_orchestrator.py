#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 ORCHESTRATOR
    Central orchestration for all TSUNAMI v5 modules
================================================================================

    Features:
    - Initialize and manage all v5 modules
    - Event bus for inter-module communication
    - Health monitoring and status tracking
    - Graceful startup/shutdown coordination
    - Central configuration distribution

================================================================================
"""

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from collections import defaultdict
import json
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("v5_orchestrator")


class ModuleState(Enum):
    """Module lifecycle states"""
    UNINITIALIZED = "uninitialized"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"
    STOPPED = "stopped"


@dataclass
class ModuleStatus:
    """Status information for a module"""
    name: str
    state: ModuleState = ModuleState.UNINITIALIZED
    enabled: bool = True
    last_heartbeat: Optional[datetime] = None
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    version: str = "5.0.0"
    dependencies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "enabled": self.enabled,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "error_message": self.error_message,
            "metrics": self.metrics,
            "version": self.version,
            "dependencies": self.dependencies
        }


class EventBus:
    """
    Central event bus for inter-module communication.
    Supports pub/sub pattern with async and sync handlers.
    """

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._async_subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._event_history: List[Dict] = []
        self._max_history = 1000
        self._lock = threading.Lock()

    def subscribe(self, event_type: str, handler: Callable) -> None:
        """Subscribe to an event type with a sync handler"""
        with self._lock:
            self._subscribers[event_type].append(handler)
            logger.debug(f"Subscribed to {event_type}: {handler.__name__}")

    def subscribe_async(self, event_type: str, handler: Callable) -> None:
        """Subscribe to an event type with an async handler"""
        with self._lock:
            self._async_subscribers[event_type].append(handler)
            logger.debug(f"Async subscribed to {event_type}: {handler.__name__}")

    def unsubscribe(self, event_type: str, handler: Callable) -> None:
        """Unsubscribe from an event type"""
        with self._lock:
            if handler in self._subscribers[event_type]:
                self._subscribers[event_type].remove(handler)
            if handler in self._async_subscribers[event_type]:
                self._async_subscribers[event_type].remove(handler)

    def publish(self, event_type: str, data: Any = None, source: str = "unknown") -> None:
        """Publish an event to all subscribers"""
        event = {
            "type": event_type,
            "data": data,
            "source": source,
            "timestamp": datetime.now().isoformat()
        }

        # Store in history
        with self._lock:
            self._event_history.append(event)
            if len(self._event_history) > self._max_history:
                self._event_history = self._event_history[-self._max_history:]

        # Call sync handlers
        for handler in self._subscribers.get(event_type, []):
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Error in event handler {handler.__name__}: {e}")

        # Call wildcard handlers
        for handler in self._subscribers.get("*", []):
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Error in wildcard handler {handler.__name__}: {e}")

    async def publish_async(self, event_type: str, data: Any = None, source: str = "unknown") -> None:
        """Publish an event asynchronously"""
        event = {
            "type": event_type,
            "data": data,
            "source": source,
            "timestamp": datetime.now().isoformat()
        }

        # Store in history
        with self._lock:
            self._event_history.append(event)
            if len(self._event_history) > self._max_history:
                self._event_history = self._event_history[-self._max_history:]

        # Call async handlers
        tasks = []
        for handler in self._async_subscribers.get(event_type, []):
            tasks.append(asyncio.create_task(handler(event)))

        for handler in self._async_subscribers.get("*", []):
            tasks.append(asyncio.create_task(handler(event)))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Also call sync handlers
        self.publish(event_type, data, source)

    def get_history(self, event_type: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get event history, optionally filtered by type"""
        with self._lock:
            if event_type:
                filtered = [e for e in self._event_history if e["type"] == event_type]
                return filtered[-limit:]
            return self._event_history[-limit:]


class V5Orchestrator:
    """
    Central orchestrator for all TSUNAMI v5 modules.
    Manages lifecycle, health, and coordination of all security modules.
    """

    # Module registry with dependencies
    MODULE_REGISTRY = {
        "threat_intel": {
            "import_path": "modules.threat_intel",
            "dependencies": [],
            "description": "STIX/TAXII threat intelligence"
        },
        "mitre_attack": {
            "import_path": "modules.mitre_attack",
            "dependencies": [],
            "description": "MITRE ATT&CK framework integration"
        },
        "ai_prediction": {
            "import_path": "modules.ai_prediction",
            "dependencies": ["threat_intel"],
            "description": "ML-based threat prediction"
        },
        "self_healing": {
            "import_path": "modules.self_healing",
            "dependencies": [],
            "description": "Auto-remediation system"
        },
        "quantum_crypto": {
            "import_path": "modules.quantum_crypto",
            "dependencies": [],
            "description": "Post-quantum cryptography"
        },
        "soar_xdr": {
            "import_path": "modules.soar_xdr",
            "dependencies": ["threat_intel", "mitre_attack"],
            "description": "Security orchestration & XDR"
        },
        "auto_pentest": {
            "import_path": "modules.auto_pentest",
            "dependencies": ["threat_intel"],
            "description": "Autonomous penetration testing"
        },
        "agentic_soc": {
            "import_path": "modules.agentic_soc",
            "dependencies": ["ai_prediction", "soar_xdr"],
            "description": "AI-powered SOC automation"
        },
        "darkweb_intel": {
            "import_path": "modules.darkweb_intel",
            "dependencies": ["threat_intel"],
            "description": "Dark web monitoring"
        }
    }

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or str(Path.home() / ".dalga" / "v5_config.json")
        self.event_bus = EventBus()
        self.modules: Dict[str, ModuleStatus] = {}
        self._module_instances: Dict[str, Any] = {}
        self._running = False
        self._health_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Initialize module status
        for name, info in self.MODULE_REGISTRY.items():
            self.modules[name] = ModuleStatus(
                name=name,
                dependencies=info.get("dependencies", [])
            )

        logger.info("V5 Orchestrator initialized")

    def _load_module(self, name: str) -> bool:
        """Dynamically load a module"""
        if name not in self.MODULE_REGISTRY:
            logger.error(f"Unknown module: {name}")
            return False

        module_info = self.MODULE_REGISTRY[name]
        status = self.modules[name]

        try:
            status.state = ModuleState.INITIALIZING

            # Check dependencies
            for dep in module_info.get("dependencies", []):
                if dep not in self._module_instances:
                    logger.warning(f"Module {name} depends on {dep} which is not loaded")

            # Dynamic import
            import importlib
            module = importlib.import_module(module_info["import_path"])
            self._module_instances[name] = module

            status.state = ModuleState.RUNNING
            status.last_heartbeat = datetime.now()
            logger.info(f"Module {name} loaded successfully")

            # Publish module loaded event
            self.event_bus.publish("module.loaded", {"module": name}, source="orchestrator")

            return True

        except ImportError as e:
            status.state = ModuleState.ERROR
            status.error_message = f"Import error: {str(e)}"
            logger.error(f"Failed to load module {name}: {e}")
            return False
        except Exception as e:
            status.state = ModuleState.ERROR
            status.error_message = str(e)
            logger.error(f"Error loading module {name}: {e}")
            return False

    def _unload_module(self, name: str) -> bool:
        """Unload a module"""
        if name in self._module_instances:
            # Check if other modules depend on this one
            for other_name, other_status in self.modules.items():
                if name in other_status.dependencies and other_status.state == ModuleState.RUNNING:
                    logger.warning(f"Cannot unload {name}: {other_name} depends on it")
                    return False

            del self._module_instances[name]
            self.modules[name].state = ModuleState.STOPPED
            self.event_bus.publish("module.unloaded", {"module": name}, source="orchestrator")
            logger.info(f"Module {name} unloaded")
            return True
        return False

    def initialize(self, enabled_modules: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Initialize all or specified modules.
        Returns dict of module_name -> success status.
        """
        results = {}

        # Determine which modules to load
        modules_to_load = enabled_modules or list(self.MODULE_REGISTRY.keys())

        # Sort by dependencies (topological sort)
        sorted_modules = self._topological_sort(modules_to_load)

        for name in sorted_modules:
            if self.modules[name].enabled:
                results[name] = self._load_module(name)
            else:
                results[name] = False
                self.modules[name].state = ModuleState.STOPPED

        self._running = True
        self._start_health_monitor()

        self.event_bus.publish("system.initialized", {"modules": results}, source="orchestrator")

        return results

    def _topological_sort(self, modules: List[str]) -> List[str]:
        """Sort modules by dependencies"""
        visited = set()
        result = []

        def visit(name: str):
            if name in visited:
                return
            visited.add(name)

            if name in self.MODULE_REGISTRY:
                for dep in self.MODULE_REGISTRY[name].get("dependencies", []):
                    if dep in modules:
                        visit(dep)

            result.append(name)

        for name in modules:
            visit(name)

        return result

    def _start_health_monitor(self) -> None:
        """Start background health monitoring thread"""
        if self._health_thread and self._health_thread.is_alive():
            return

        def health_check_loop():
            while self._running:
                self._perform_health_checks()
                time.sleep(30)  # Check every 30 seconds

        self._health_thread = threading.Thread(target=health_check_loop, daemon=True)
        self._health_thread.start()
        logger.info("Health monitor started")

    def _perform_health_checks(self) -> None:
        """Perform health checks on all modules"""
        for name, status in self.modules.items():
            if status.state == ModuleState.RUNNING:
                try:
                    module = self._module_instances.get(name)
                    if module:
                        # Check if module has health_check method
                        if hasattr(module, 'health_check'):
                            health = module.health_check()
                            status.metrics.update(health)

                        status.last_heartbeat = datetime.now()
                except Exception as e:
                    logger.warning(f"Health check failed for {name}: {e}")

    def get_module(self, name: str) -> Optional[Any]:
        """Get a loaded module instance"""
        return self._module_instances.get(name)

    def get_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        running_count = sum(1 for s in self.modules.values() if s.state == ModuleState.RUNNING)
        error_count = sum(1 for s in self.modules.values() if s.state == ModuleState.ERROR)

        return {
            "orchestrator": {
                "running": self._running,
                "uptime": "N/A",  # TODO: Track actual uptime
                "version": "5.0.0"
            },
            "modules": {
                "total": len(self.modules),
                "running": running_count,
                "errors": error_count,
                "details": {name: status.to_dict() for name, status in self.modules.items()}
            },
            "event_bus": {
                "subscribers": sum(len(h) for h in self.event_bus._subscribers.values()),
                "recent_events": len(self.event_bus.get_history(limit=100))
            }
        }

    def get_module_status(self, name: str) -> Optional[Dict]:
        """Get status of a specific module"""
        if name in self.modules:
            return self.modules[name].to_dict()
        return None

    def toggle_module(self, name: str, enabled: bool) -> bool:
        """Enable or disable a module"""
        if name not in self.modules:
            return False

        with self._lock:
            if enabled and not self.modules[name].enabled:
                self.modules[name].enabled = True
                return self._load_module(name)
            elif not enabled and self.modules[name].enabled:
                self.modules[name].enabled = False
                return self._unload_module(name)

        return True

    def shutdown(self) -> None:
        """Gracefully shutdown all modules"""
        logger.info("Shutting down V5 Orchestrator...")
        self._running = False

        # Stop modules in reverse dependency order
        modules_to_stop = list(reversed(self._topological_sort(list(self._module_instances.keys()))))

        for name in modules_to_stop:
            self._unload_module(name)

        self.event_bus.publish("system.shutdown", {}, source="orchestrator")
        logger.info("V5 Orchestrator shutdown complete")


# Singleton instance
_orchestrator_instance: Optional[V5Orchestrator] = None
_orchestrator_lock = threading.Lock()


def get_orchestrator(config_path: Optional[str] = None) -> V5Orchestrator:
    """Get or create the singleton orchestrator instance"""
    global _orchestrator_instance
    with _orchestrator_lock:
        if _orchestrator_instance is None:
            _orchestrator_instance = V5Orchestrator(config_path)
        return _orchestrator_instance


def initialize_v5(enabled_modules: Optional[List[str]] = None, config_path: Optional[str] = None) -> V5Orchestrator:
    """Initialize the V5 system with specified modules"""
    orchestrator = get_orchestrator(config_path)
    orchestrator.initialize(enabled_modules)
    return orchestrator
