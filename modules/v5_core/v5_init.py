#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 INITIALIZATION SCRIPT
    System initialization and startup procedures
================================================================================

    Procedures:
    - Check dependencies
    - Create required directories
    - Initialize databases
    - Start background workers
    - Register with main Flask app

================================================================================
"""

import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("v5_init")

# Required Python packages for v5 modules
REQUIRED_PACKAGES = {
    "core": ["flask", "flask-socketio"],
    "threat_intel": ["requests", "stix2"],
    "ai_prediction": ["numpy", "scikit-learn"],
    "mitre_attack": ["requests"],
    "self_healing": ["psutil"],
    "soar_xdr": ["pyyaml"],
    "auto_pentest": ["requests"],
    "agentic_soc": ["numpy"],
    "darkweb_intel": ["requests", "pysocks"],
    "quantum_crypto": ["cryptography"]
}

# Required directories
REQUIRED_DIRECTORIES = [
    "data",
    "data/threat_intel",
    "data/mitre_attack",
    "data/ai_models",
    "data/incidents",
    "data/scans",
    "data/playbooks",
    "logs",
    "config",
    "temp",
    ".keys"
]

# Required database tables (SQLite schema)
DATABASE_SCHEMA = """
-- Events table
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    raw_data TEXT,
    enriched_data TEXT,
    risk_score REAL DEFAULT 0,
    processed INTEGER DEFAULT 0
);

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT DEFAULT 'new',
    source TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    mitre_techniques TEXT,
    affected_assets TEXT,
    evidence TEXT,
    risk_score REAL DEFAULT 0
);

-- Incidents table
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME,
    resolved_at DATETIME,
    assigned_to TEXT,
    related_alerts TEXT,
    timeline TEXT
);

-- Threat Intel Cache table
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    indicator TEXT PRIMARY KEY,
    indicator_type TEXT NOT NULL,
    data TEXT,
    source TEXT,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
);

-- MITRE Mappings table
CREATE TABLE IF NOT EXISTS mitre_mappings (
    event_id TEXT,
    technique_id TEXT NOT NULL,
    tactic TEXT,
    confidence REAL DEFAULT 0,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (event_id, technique_id)
);

-- Playbook Executions table
CREATE TABLE IF NOT EXISTS playbook_executions (
    id TEXT PRIMARY KEY,
    playbook_id TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    started_at DATETIME,
    completed_at DATETIME,
    trigger_event TEXT,
    steps_completed INTEGER DEFAULT 0,
    steps_total INTEGER DEFAULT 0,
    result TEXT
);

-- Audit Log table
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    user TEXT,
    resource TEXT,
    details TEXT,
    ip_address TEXT
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intel_cache(indicator_type);
"""


class V5SystemInitializer:
    """
    Handles system initialization for TSUNAMI v5.
    """

    def __init__(self, base_path: Optional[str] = None):
        self.base_path = Path(base_path) if base_path else Path.home() / ".dalga"
        self.db_path = self.base_path / "v5_data.db"
        self._initialized = False
        self._init_errors: List[str] = []

    def check_python_version(self) -> Tuple[bool, str]:
        """Check Python version compatibility"""
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            return False, f"Python 3.8+ required, found {version.major}.{version.minor}"
        return True, f"Python {version.major}.{version.minor}.{version.micro}"

    def check_dependencies(self, modules: Optional[List[str]] = None) -> Dict[str, Dict[str, bool]]:
        """
        Check if required packages are installed.

        Args:
            modules: List of module names to check, or None for all

        Returns:
            Dict of module -> {package: installed}
        """
        import importlib

        results = {}
        modules_to_check = modules or list(REQUIRED_PACKAGES.keys())

        for module in modules_to_check:
            if module not in REQUIRED_PACKAGES:
                continue

            results[module] = {}
            for package in REQUIRED_PACKAGES[module]:
                try:
                    # Handle package names that differ from import names
                    import_name = package.replace("-", "_")
                    importlib.import_module(import_name)
                    results[module][package] = True
                except ImportError:
                    results[module][package] = False

        return results

    def create_directories(self) -> Dict[str, bool]:
        """
        Create required directories.

        Returns:
            Dict of directory -> created successfully
        """
        results = {}

        for directory in REQUIRED_DIRECTORIES:
            dir_path = self.base_path / directory
            try:
                dir_path.mkdir(parents=True, exist_ok=True)

                # Set permissions for sensitive directories
                if directory == ".keys":
                    os.chmod(dir_path, 0o700)

                results[directory] = True
            except Exception as e:
                logger.error(f"Failed to create directory {directory}: {e}")
                results[directory] = False
                self._init_errors.append(f"Directory creation failed: {directory}")

        return results

    def initialize_database(self) -> bool:
        """
        Initialize SQLite database with schema.

        Returns:
            True if successful
        """
        try:
            import sqlite3

            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Execute schema
            cursor.executescript(DATABASE_SCHEMA)

            conn.commit()
            conn.close()

            logger.info(f"Database initialized at {self.db_path}")
            return True

        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            self._init_errors.append(f"Database init failed: {e}")
            return False

    def start_background_workers(self) -> Dict[str, bool]:
        """
        Start background worker threads.

        Returns:
            Dict of worker_name -> started successfully
        """
        results = {}

        # Start event pipeline
        try:
            from .event_pipeline import get_pipeline
            pipeline = get_pipeline()
            pipeline.start(num_workers=4)
            results["event_pipeline"] = True
            logger.info("Event pipeline started")
        except Exception as e:
            logger.error(f"Failed to start event pipeline: {e}")
            results["event_pipeline"] = False

        # Start orchestrator health monitor (implicit in initialize)
        try:
            from .v5_orchestrator import get_orchestrator
            orchestrator = get_orchestrator()
            results["health_monitor"] = True
        except Exception as e:
            logger.error(f"Failed to initialize orchestrator: {e}")
            results["health_monitor"] = False

        return results

    def register_with_flask(self, app) -> bool:
        """
        Register v5 API routes with Flask app.

        Args:
            app: Flask application instance

        Returns:
            True if successful
        """
        try:
            from .api_routes import v5_core_bp

            app.register_blueprint(v5_core_bp)
            logger.info("V5 API routes registered with Flask")
            return True

        except Exception as e:
            logger.error(f"Failed to register Flask routes: {e}")
            self._init_errors.append(f"Flask registration failed: {e}")
            return False

    def register_all_module_routes(self, app) -> Dict[str, bool]:
        """
        Register API routes from all v5 modules.

        Args:
            app: Flask application instance

        Returns:
            Dict of module -> registered successfully
        """
        results = {}

        module_blueprints = {
            "threat_intel": "modules.threat_intel:threat_intel_bp",
            "soar_xdr": "modules.soar_xdr:soar_xdr_bp",
            "agentic_soc": "modules.agentic_soc:agentic_soc_bp"
        }

        for module, bp_path in module_blueprints.items():
            try:
                module_path, bp_name = bp_path.split(":")
                import importlib
                mod = importlib.import_module(module_path)
                bp = getattr(mod, bp_name, None)

                if bp:
                    app.register_blueprint(bp)
                    results[module] = True
                    logger.info(f"Registered {module} routes")
                else:
                    results[module] = False
            except Exception as e:
                logger.warning(f"Could not register {module} routes: {e}")
                results[module] = False

        return results

    def full_initialization(self, app=None, modules: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform full system initialization.

        Args:
            app: Optional Flask app to register routes with
            modules: Optional list of modules to initialize

        Returns:
            Initialization report
        """
        report = {
            "success": True,
            "python_version": None,
            "dependencies": {},
            "directories": {},
            "database": False,
            "workers": {},
            "flask_registered": False,
            "modules_initialized": {},
            "errors": []
        }

        # Check Python version
        py_ok, py_version = self.check_python_version()
        report["python_version"] = py_version
        if not py_ok:
            report["success"] = False
            report["errors"].append(f"Python version check failed: {py_version}")
            return report

        # Check dependencies
        report["dependencies"] = self.check_dependencies(modules)

        # Create directories
        report["directories"] = self.create_directories()
        if not all(report["directories"].values()):
            report["success"] = False

        # Initialize database
        report["database"] = self.initialize_database()
        if not report["database"]:
            report["success"] = False

        # Start background workers
        report["workers"] = self.start_background_workers()

        # Initialize orchestrator and modules
        try:
            from .v5_orchestrator import initialize_v5
            orchestrator = initialize_v5(enabled_modules=modules)
            status = orchestrator.get_status()
            report["modules_initialized"] = status.get("modules", {}).get("details", {})
        except Exception as e:
            logger.error(f"Module initialization failed: {e}")
            report["errors"].append(f"Module init failed: {e}")
            report["success"] = False

        # Register with Flask if provided
        if app:
            report["flask_registered"] = self.register_with_flask(app)
            self.register_all_module_routes(app)

        # Collect any errors
        report["errors"].extend(self._init_errors)

        self._initialized = report["success"]
        return report

    def is_initialized(self) -> bool:
        """Check if system is initialized"""
        return self._initialized

    def get_status(self) -> Dict[str, Any]:
        """Get current initialization status"""
        return {
            "initialized": self._initialized,
            "base_path": str(self.base_path),
            "db_path": str(self.db_path),
            "errors": self._init_errors
        }


def init_v5_system(app=None, base_path: Optional[str] = None,
                   modules: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Convenience function to initialize the v5 system.

    Args:
        app: Flask application (optional)
        base_path: Base directory for data (optional)
        modules: List of modules to enable (optional, None for all)

    Returns:
        Initialization report
    """
    initializer = V5SystemInitializer(base_path)
    return initializer.full_initialization(app=app, modules=modules)


def quick_init(app=None) -> bool:
    """
    Quick initialization with defaults.

    Args:
        app: Flask application (optional)

    Returns:
        True if successful
    """
    report = init_v5_system(app=app)
    return report.get("success", False)


# For use when run directly
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("=" * 60)
    print("TSUNAMI v5.0 System Initialization")
    print("=" * 60)

    report = init_v5_system()

    print("\nInitialization Report:")
    print(f"  Python Version: {report['python_version']}")
    print(f"  Database: {'OK' if report['database'] else 'FAILED'}")
    print(f"  Success: {report['success']}")

    if report['errors']:
        print("\nErrors:")
        for error in report['errors']:
            print(f"  - {error}")

    print("\nDependencies:")
    for module, deps in report['dependencies'].items():
        status = 'OK' if all(deps.values()) else 'MISSING'
        print(f"  {module}: {status}")
        if not all(deps.values()):
            for pkg, installed in deps.items():
                if not installed:
                    print(f"    - Missing: {pkg}")

    print("\nWorkers:")
    for worker, running in report['workers'].items():
        print(f"  {worker}: {'Running' if running else 'Failed'}")

    print("\nModules:")
    for module, status in report.get('modules_initialized', {}).items():
        state = status.get('state', 'unknown') if isinstance(status, dict) else 'unknown'
        print(f"  {module}: {state}")

    sys.exit(0 if report['success'] else 1)
