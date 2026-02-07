#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 CONFIGURATION MANAGER
    Central configuration management for all modules
================================================================================

    Features:
    - Load/save module configurations
    - Encrypted API key management
    - Feature toggles
    - License management
    - Environment detection

================================================================================
"""

import base64
import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import secrets

logger = logging.getLogger("config_manager")


class Environment(Enum):
    """Deployment environment types"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class LicenseType(Enum):
    """License types"""
    COMMUNITY = "community"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    TRIAL = "trial"


@dataclass
class ModuleConfig:
    """Configuration for a single module"""
    name: str
    enabled: bool = True
    settings: Dict[str, Any] = field(default_factory=dict)
    api_keys: Dict[str, str] = field(default_factory=dict)
    feature_flags: Dict[str, bool] = field(default_factory=dict)
    rate_limits: Dict[str, int] = field(default_factory=dict)

    def to_dict(self, include_secrets: bool = False) -> Dict[str, Any]:
        result = {
            "name": self.name,
            "enabled": self.enabled,
            "settings": self.settings,
            "feature_flags": self.feature_flags,
            "rate_limits": self.rate_limits
        }
        if include_secrets:
            result["api_keys"] = self.api_keys
        else:
            result["api_keys"] = {k: "***" for k in self.api_keys.keys()}
        return result


@dataclass
class FeatureToggle:
    """Feature toggle with metadata"""
    name: str
    enabled: bool
    description: str = ""
    requires_license: Optional[LicenseType] = None
    deprecated: bool = False
    rollout_percentage: int = 100
    allowed_environments: List[Environment] = field(default_factory=list)

    def is_available(self, license_type: LicenseType, environment: Environment) -> bool:
        """Check if feature is available for given license and environment"""
        if self.deprecated:
            return False
        if self.requires_license:
            license_hierarchy = [LicenseType.COMMUNITY, LicenseType.TRIAL,
                                 LicenseType.PROFESSIONAL, LicenseType.ENTERPRISE]
            if license_hierarchy.index(license_type) < license_hierarchy.index(self.requires_license):
                return False
        if self.allowed_environments and environment not in self.allowed_environments:
            return False
        return self.enabled


@dataclass
class LicenseInfo:
    """License information"""
    type: LicenseType
    organization: str
    issued_at: datetime
    expires_at: Optional[datetime]
    max_users: int = 0
    max_assets: int = 0
    features: List[str] = field(default_factory=list)
    license_key: str = ""

    def is_valid(self) -> bool:
        """Check if license is still valid"""
        if self.expires_at and datetime.now() > self.expires_at:
            return False
        return True

    def to_dict(self, include_key: bool = False) -> Dict[str, Any]:
        result = {
            "type": self.type.value,
            "organization": self.organization,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "max_users": self.max_users,
            "max_assets": self.max_assets,
            "features": self.features,
            "is_valid": self.is_valid()
        }
        if include_key:
            result["license_key"] = self.license_key
        return result


class SecretManager:
    """
    Manage encrypted secrets and API keys.
    Uses simple encryption for local storage.
    """

    def __init__(self, key_file: Path):
        self.key_file = key_file
        self._key: Optional[bytes] = None
        self._load_or_create_key()

    def _load_or_create_key(self) -> None:
        """Load existing key or create new one"""
        if self.key_file.exists():
            self._key = self.key_file.read_bytes()
        else:
            self._key = secrets.token_bytes(32)
            self.key_file.parent.mkdir(parents=True, exist_ok=True)
            self.key_file.write_bytes(self._key)
            os.chmod(self.key_file, 0o600)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string using XOR (simple encryption for local use)"""
        if not plaintext:
            return ""

        # Simple XOR encryption - adequate for local API key storage
        key_bytes = self._key
        plaintext_bytes = plaintext.encode('utf-8')

        encrypted = bytes(p ^ k for p, k in zip(
            plaintext_bytes,
            (key_bytes * (len(plaintext_bytes) // len(key_bytes) + 1))[:len(plaintext_bytes)]
        ))

        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a string"""
        if not ciphertext:
            return ""

        try:
            encrypted = base64.b64decode(ciphertext.encode('utf-8'))
            key_bytes = self._key

            decrypted = bytes(e ^ k for e, k in zip(
                encrypted,
                (key_bytes * (len(encrypted) // len(key_bytes) + 1))[:len(encrypted)]
            ))

            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return ""


class LicenseManager:
    """Manage software licensing"""

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.license_file = config_dir / "license.json"
        self._license: Optional[LicenseInfo] = None
        self._load_license()

    def _load_license(self) -> None:
        """Load license from file"""
        if self.license_file.exists():
            try:
                data = json.loads(self.license_file.read_text())
                self._license = LicenseInfo(
                    type=LicenseType(data.get("type", "community")),
                    organization=data.get("organization", ""),
                    issued_at=datetime.fromisoformat(data.get("issued_at", datetime.now().isoformat())),
                    expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
                    max_users=data.get("max_users", 0),
                    max_assets=data.get("max_assets", 0),
                    features=data.get("features", []),
                    license_key=data.get("license_key", "")
                )
            except Exception as e:
                logger.warning(f"Could not load license: {e}")
                self._create_community_license()
        else:
            self._create_community_license()

    def _create_community_license(self) -> None:
        """Create default community license"""
        self._license = LicenseInfo(
            type=LicenseType.COMMUNITY,
            organization="Community User",
            issued_at=datetime.now(),
            expires_at=None,
            max_users=1,
            max_assets=100,
            features=["basic_scanning", "threat_intel", "dashboard"]
        )
        self._save_license()

    def _save_license(self) -> None:
        """Save license to file"""
        if self._license:
            self.license_file.parent.mkdir(parents=True, exist_ok=True)
            self.license_file.write_text(json.dumps(self._license.to_dict(include_key=True), indent=2))

    def get_license(self) -> Optional[LicenseInfo]:
        """Get current license"""
        return self._license

    def activate_license(self, license_key: str) -> bool:
        """Activate a new license"""
        # In a real implementation, this would validate against a license server
        # For now, we'll do a simple key validation
        try:
            # Decode license key (simplified for demo)
            if len(license_key) < 20:
                return False

            # Parse license data from key
            # In production, this would be cryptographically verified
            parts = license_key.split("-")
            if len(parts) < 4:
                return False

            license_type = LicenseType.PROFESSIONAL if "PRO" in license_key else LicenseType.ENTERPRISE

            self._license = LicenseInfo(
                type=license_type,
                organization="Licensed Organization",
                issued_at=datetime.now(),
                expires_at=datetime.now() + timedelta(days=365),
                max_users=100,
                max_assets=10000,
                features=["all"],
                license_key=license_key
            )
            self._save_license()
            logger.info(f"License activated: {license_type.value}")
            return True

        except Exception as e:
            logger.error(f"License activation failed: {e}")
            return False

    def check_feature(self, feature: str) -> bool:
        """Check if a feature is licensed"""
        if not self._license:
            return False
        if "all" in self._license.features:
            return True
        return feature in self._license.features


class ConfigManager:
    """
    Central configuration manager for TSUNAMI v5.
    Handles all module configurations, secrets, and feature flags.
    """

    DEFAULT_CONFIG = {
        "environment": "development",
        "debug": False,
        "log_level": "INFO",
        "data_dir": str(Path.home() / ".dalga"),
        "modules": {},
        "global_settings": {
            "event_retention_days": 90,
            "alert_retention_days": 365,
            "max_concurrent_scans": 5,
            "api_rate_limit": 100,
            "enable_telemetry": False
        },
        "integrations": {
            "slack": {"enabled": False},
            "teams": {"enabled": False},
            "email": {"enabled": False},
            "siem": {"enabled": False}
        }
    }

    def __init__(self, config_path: Optional[str] = None):
        self.config_dir = Path(config_path) if config_path else Path.home() / ".dalga"
        self.config_file = self.config_dir / "v5_config.json"
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self._config: Dict[str, Any] = {}
        self._module_configs: Dict[str, ModuleConfig] = {}
        self._feature_toggles: Dict[str, FeatureToggle] = {}
        self._lock = threading.Lock()

        # Initialize sub-managers
        self.secret_manager = SecretManager(self.config_dir / ".keys" / "secret.key")
        self.license_manager = LicenseManager(self.config_dir)

        self._load_config()
        self._setup_default_features()

    def _load_config(self) -> None:
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                self._config = json.loads(self.config_file.read_text())
                logger.info(f"Loaded config from {self.config_file}")
            except Exception as e:
                logger.warning(f"Could not load config: {e}, using defaults")
                self._config = self.DEFAULT_CONFIG.copy()
        else:
            self._config = self.DEFAULT_CONFIG.copy()
            self._save_config()

        # Load module configs
        for name, module_data in self._config.get("modules", {}).items():
            self._module_configs[name] = ModuleConfig(
                name=name,
                enabled=module_data.get("enabled", True),
                settings=module_data.get("settings", {}),
                api_keys=module_data.get("api_keys", {}),
                feature_flags=module_data.get("feature_flags", {}),
                rate_limits=module_data.get("rate_limits", {})
            )

    def _save_config(self) -> None:
        """Save configuration to file"""
        with self._lock:
            # Update modules in config
            self._config["modules"] = {
                name: config.to_dict(include_secrets=True)
                for name, config in self._module_configs.items()
            }

            self.config_file.write_text(json.dumps(self._config, indent=2))
            logger.debug(f"Saved config to {self.config_file}")

    def _setup_default_features(self) -> None:
        """Setup default feature toggles"""
        defaults = [
            FeatureToggle("threat_intel", True, "Threat intelligence integration"),
            FeatureToggle("ai_prediction", True, "AI-based threat prediction"),
            FeatureToggle("auto_remediation", True, "Automatic threat remediation"),
            FeatureToggle("quantum_crypto", False, "Post-quantum cryptography", LicenseType.ENTERPRISE),
            FeatureToggle("darkweb_monitoring", True, "Dark web monitoring"),
            FeatureToggle("agentic_soc", True, "AI-powered SOC automation", LicenseType.PROFESSIONAL),
            FeatureToggle("auto_pentest", True, "Autonomous penetration testing", LicenseType.PROFESSIONAL),
            FeatureToggle("soar_playbooks", True, "SOAR playbook execution"),
            FeatureToggle("mitre_mapping", True, "MITRE ATT&CK mapping"),
            FeatureToggle("xdr_correlation", True, "XDR event correlation"),
        ]

        for toggle in defaults:
            self._feature_toggles[toggle.name] = toggle

    def get_environment(self) -> Environment:
        """Get current environment"""
        env_str = os.getenv("TSUNAMI_ENV", self._config.get("environment", "development"))
        try:
            return Environment(env_str.lower())
        except ValueError:
            return Environment.DEVELOPMENT

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value by key (supports dot notation)"""
        parts = key.split(".")
        value = self._config
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return default
            if value is None:
                return default
        return value

    def set(self, key: str, value: Any) -> None:
        """Set a config value (supports dot notation)"""
        with self._lock:
            parts = key.split(".")
            config = self._config
            for part in parts[:-1]:
                if part not in config:
                    config[part] = {}
                config = config[part]
            config[parts[-1]] = value
            self._save_config()

    def get_module_config(self, module_name: str) -> Optional[ModuleConfig]:
        """Get configuration for a specific module"""
        return self._module_configs.get(module_name)

    def set_module_config(self, module_name: str, config: ModuleConfig) -> None:
        """Set configuration for a module"""
        with self._lock:
            self._module_configs[module_name] = config
            self._save_config()

    def set_api_key(self, module_name: str, key_name: str, value: str) -> None:
        """Set an API key for a module (encrypted)"""
        with self._lock:
            if module_name not in self._module_configs:
                self._module_configs[module_name] = ModuleConfig(name=module_name)

            encrypted = self.secret_manager.encrypt(value)
            self._module_configs[module_name].api_keys[key_name] = encrypted
            self._save_config()

    def get_api_key(self, module_name: str, key_name: str) -> Optional[str]:
        """Get a decrypted API key"""
        config = self._module_configs.get(module_name)
        if not config:
            return None

        encrypted = config.api_keys.get(key_name)
        if not encrypted:
            # Fall back to environment variable
            env_key = f"{module_name.upper()}_{key_name.upper()}"
            return os.getenv(env_key)

        return self.secret_manager.decrypt(encrypted)

    def is_feature_enabled(self, feature_name: str) -> bool:
        """Check if a feature is enabled"""
        toggle = self._feature_toggles.get(feature_name)
        if not toggle:
            return False

        license_info = self.license_manager.get_license()
        if not license_info:
            return False

        return toggle.is_available(license_info.type, self.get_environment())

    def set_feature_toggle(self, feature_name: str, enabled: bool) -> None:
        """Set a feature toggle"""
        if feature_name in self._feature_toggles:
            self._feature_toggles[feature_name].enabled = enabled

    def get_all_features(self) -> Dict[str, Dict[str, Any]]:
        """Get all feature toggles with their status"""
        license_info = self.license_manager.get_license()
        env = self.get_environment()

        return {
            name: {
                "enabled": toggle.enabled,
                "available": toggle.is_available(license_info.type, env) if license_info else False,
                "description": toggle.description,
                "requires_license": toggle.requires_license.value if toggle.requires_license else None,
                "deprecated": toggle.deprecated
            }
            for name, toggle in self._feature_toggles.items()
        }

    def get_full_config(self, include_secrets: bool = False) -> Dict[str, Any]:
        """Get full configuration"""
        return {
            "environment": self.get_environment().value,
            "config": self._config,
            "modules": {
                name: config.to_dict(include_secrets)
                for name, config in self._module_configs.items()
            },
            "features": self.get_all_features(),
            "license": self.license_manager.get_license().to_dict() if self.license_manager.get_license() else None
        }

    def reload(self) -> None:
        """Reload configuration from file"""
        self._load_config()
        logger.info("Configuration reloaded")


# Singleton instance
_config_manager_instance: Optional[ConfigManager] = None
_config_manager_lock = threading.Lock()


def get_config_manager(config_path: Optional[str] = None) -> ConfigManager:
    """Get or create the singleton config manager instance"""
    global _config_manager_instance
    with _config_manager_lock:
        if _config_manager_instance is None:
            _config_manager_instance = ConfigManager(config_path)
        return _config_manager_instance
