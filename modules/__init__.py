#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 MODULES
    Otonom Siber Istihbarat ve Guvenlik Platformu
================================================================================

    Moduller:
    - threat_intel: STIX 2.1 / TAXII 2.1 Tehdit Istihbarati
    - mitre_attack: MITRE ATT&CK v18 Framework Entegrasyonu
    - ai_prediction: AI Tehdit Tahmini ve Sifir-Gun Tespiti
    - self_healing: Self-Healing Ag Mimarisi
    - quantum_crypto: Kuantum-Direncli Kriptografi (ML-KEM, ML-DSA)
    - soar_xdr: SOAR/XDR Playbook Otomasyonu
    - auto_pentest: Otonom Sizma Testi
    - agentic_soc: Ajansal SOC AI
    - darkweb_intel: Dark Web Istihbarat Monitoru
    - v5_core: V5 Orchestrator ve Dashboard

================================================================================
"""

import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger("tsunami_modules")

__version__ = "5.0.0"
__author__ = "TSUNAMI Security Team"

# Module availability tracking
_available_modules: Dict[str, bool] = {}


def _try_import(module_name: str, package_name: str = None):
    """
    Try to import a module and track availability.

    Args:
        module_name: Name of the module
        package_name: Actual package name if different from module_name
    """
    pkg = package_name or module_name
    try:
        import importlib
        mod = importlib.import_module(f".{pkg}", package="modules")
        _available_modules[module_name] = True
        return mod
    except ImportError as e:
        logger.debug(f"Module {module_name} not available: {e}")
        _available_modules[module_name] = False
        return None


# Import v5_core (central orchestration) - always try first
v5_core = _try_import("v5_core")

# Import threat intelligence modules
threat_intel = _try_import("threat_intel")
mitre_attack = _try_import("mitre_attack")
darkweb_intel = _try_import("darkweb_intel")

# Import AI/ML modules
ai_prediction = _try_import("ai_prediction")
agentic_soc = _try_import("agentic_soc")

# Import response/orchestration modules
soar_xdr = _try_import("soar_xdr")
self_healing = _try_import("self_healing")

# Import security testing modules
auto_pentest = _try_import("auto_pentest")

# Import cryptography modules
quantum_crypto = _try_import("quantum_crypto")


def get_available_modules() -> Dict[str, bool]:
    """
    Get dictionary of module names and their availability.

    Returns:
        Dict mapping module name to availability boolean
    """
    return _available_modules.copy()


def get_loaded_modules() -> List[str]:
    """
    Get list of successfully loaded modules.

    Returns:
        List of module names that were successfully imported
    """
    return [name for name, available in _available_modules.items() if available]


def get_missing_modules() -> List[str]:
    """
    Get list of modules that failed to load.

    Returns:
        List of module names that could not be imported
    """
    return [name for name, available in _available_modules.items() if not available]


def initialize_all(app=None, enabled_modules: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Initialize all v5 modules.

    Args:
        app: Optional Flask app to register routes with
        enabled_modules: Optional list of specific modules to enable

    Returns:
        Initialization report dictionary
    """
    if v5_core is None:
        return {
            "success": False,
            "error": "v5_core module not available",
            "available_modules": _available_modules
        }

    try:
        from .v5_core.v5_init import init_v5_system
        return init_v5_system(app=app, modules=enabled_modules)
    except ImportError as e:
        return {
            "success": False,
            "error": f"Could not import v5_init: {e}",
            "available_modules": _available_modules
        }


def get_orchestrator():
    """
    Get the v5 orchestrator instance.

    Returns:
        V5Orchestrator instance or None if not available
    """
    if v5_core is None:
        return None
    return v5_core.get_orchestrator()


def get_dashboard():
    """
    Get the unified dashboard instance.

    Returns:
        UnifiedDashboard instance or None if not available
    """
    if v5_core is None:
        return None
    return v5_core.get_dashboard()


def get_event_pipeline():
    """
    Get the event pipeline instance.

    Returns:
        EventPipeline instance or None if not available
    """
    if v5_core is None:
        return None
    return v5_core.get_pipeline()


def get_config_manager():
    """
    Get the config manager instance.

    Returns:
        ConfigManager instance or None if not available
    """
    if v5_core is None:
        return None
    return v5_core.get_config_manager()


__all__ = [
    # Version info
    "__version__",
    "__author__",

    # Core modules
    "v5_core",
    "threat_intel",
    "mitre_attack",
    "darkweb_intel",
    "ai_prediction",
    "agentic_soc",
    "soar_xdr",
    "self_healing",
    "auto_pentest",
    "quantum_crypto",

    # Utility functions
    "get_available_modules",
    "get_loaded_modules",
    "get_missing_modules",
    "initialize_all",
    "get_orchestrator",
    "get_dashboard",
    "get_event_pipeline",
    "get_config_manager",
]

# Log initialization status
loaded = get_loaded_modules()
missing = get_missing_modules()
logger.info(f"TSUNAMI Modules loaded: {len(loaded)}/{len(_available_modules)}")
if missing:
    logger.debug(f"Missing modules: {missing}")
