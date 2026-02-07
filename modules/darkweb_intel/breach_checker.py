#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 - Breach Database Checker
    Real integration with HaveIBeenPwned API and breach databases
================================================================================
"""

import os
import time
import hashlib
import logging
import threading
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BreachSeverity(Enum):
    """Severity of a breach"""
    CRITICAL = "critical"  # Passwords, financial data exposed
    HIGH = "high"          # Personal data, emails exposed
    MEDIUM = "medium"      # Some PII exposed
    LOW = "low"            # Limited exposure
    INFO = "info"          # No sensitive data


@dataclass
class BreachInfo:
    """Information about a single breach"""
    name: str
    title: str
    domain: str
    breach_date: str
    added_date: str
    modified_date: str
    pwn_count: int
    description: str
    logo_path: Optional[str] = None
    data_classes: List[str] = field(default_factory=list)
    is_verified: bool = True
    is_fabricated: bool = False
    is_sensitive: bool = False
    is_retired: bool = False
    is_spam_list: bool = False
    is_malware: bool = False
    is_subscription_free: bool = False


@dataclass
class BreachResult:
    """Result of a breach check"""
    query: str
    query_type: str  # email, domain, phone
    found_in_breach: bool
    total_breaches: int
    total_pastes: int
    breaches: List[BreachInfo] = field(default_factory=list)
    pastes: List[Dict[str, Any]] = field(default_factory=list)
    severity: BreachSeverity = BreachSeverity.INFO
    first_breach_date: Optional[str] = None
    last_breach_date: Optional[str] = None
    exposed_data_types: List[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.now)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class PasswordCheckResult:
    """Result of password exposure check"""
    password_hash: str  # k-Anonymity partial hash
    is_pwned: bool
    pwn_count: int
    checked_at: datetime = field(default_factory=datetime.now)
    recommendations: List[str] = field(default_factory=list)


class HaveIBeenPwnedClient:
    """
    Official HaveIBeenPwned API v3 client

    Requires an API key for most endpoints.
    Get one at: https://haveibeenpwned.com/API/Key
    """

    BASE_URL = "https://haveibeenpwned.com/api/v3"
    PASSWORD_API_URL = "https://api.pwnedpasswords.com"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize HIBP client

        Args:
            api_key: HaveIBeenPwned API key (required for breach/paste endpoints)
        """
        self.api_key = api_key or os.getenv("HIBP_API_KEY")
        self._session = self._create_session()
        self._rate_limit_remaining = 10
        self._rate_limit_reset = datetime.now()
        self._lock = threading.Lock()

        if not self.api_key:
            logger.warning("[HIBP] No API key configured - breach/paste endpoints unavailable")
        else:
            logger.info("[HIBP] Client initialized with API key")

    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic"""
        session = requests.Session()

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # HIBP requires a User-Agent header
        session.headers.update({
            "User-Agent": "TSUNAMI-SecurityPlatform/5.0",
            "Accept": "application/json",
        })

        if self.api_key:
            session.headers["hibp-api-key"] = self.api_key

        return session

    def _handle_rate_limit(self, response: requests.Response):
        """Handle rate limiting from API"""
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 2))
            logger.warning(f"[HIBP] Rate limited, waiting {retry_after} seconds")
            time.sleep(retry_after)
            return True
        return False

    def check_email(self, email: str, include_unverified: bool = False) -> List[BreachInfo]:
        """
        Check if an email has been in any breaches

        Args:
            email: Email address to check
            include_unverified: Include unverified breaches

        Returns:
            List of BreachInfo objects
        """
        if not self.api_key:
            raise ValueError("HIBP API key required for email breach check")

        email = email.lower().strip()
        endpoint = f"{self.BASE_URL}/breachedaccount/{email}"

        params = {"truncateResponse": "false"}
        if include_unverified:
            params["includeUnverified"] = "true"

        try:
            with self._lock:
                # Respect rate limiting (1 request per 1.5 seconds for free tier)
                time.sleep(1.5)

            response = self._session.get(endpoint, params=params, timeout=30)

            if response.status_code == 404:
                # Email not found in any breaches
                return []

            if self._handle_rate_limit(response):
                # Retry after rate limit
                response = self._session.get(endpoint, params=params, timeout=30)

            response.raise_for_status()

            breaches = []
            for breach_data in response.json():
                breaches.append(BreachInfo(
                    name=breach_data.get("Name", ""),
                    title=breach_data.get("Title", ""),
                    domain=breach_data.get("Domain", ""),
                    breach_date=breach_data.get("BreachDate", ""),
                    added_date=breach_data.get("AddedDate", ""),
                    modified_date=breach_data.get("ModifiedDate", ""),
                    pwn_count=breach_data.get("PwnCount", 0),
                    description=breach_data.get("Description", ""),
                    logo_path=breach_data.get("LogoPath"),
                    data_classes=breach_data.get("DataClasses", []),
                    is_verified=breach_data.get("IsVerified", True),
                    is_fabricated=breach_data.get("IsFabricated", False),
                    is_sensitive=breach_data.get("IsSensitive", False),
                    is_retired=breach_data.get("IsRetired", False),
                    is_spam_list=breach_data.get("IsSpamList", False),
                    is_malware=breach_data.get("IsMalware", False),
                    is_subscription_free=breach_data.get("IsSubscriptionFree", False)
                ))

            return breaches

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                logger.error("[HIBP] Invalid API key")
            elif e.response.status_code == 403:
                logger.error("[HIBP] API key doesn't have permission for this endpoint")
            else:
                logger.error(f"[HIBP] HTTP error: {e}")
            raise

        except Exception as e:
            logger.error(f"[HIBP] Error checking email: {e}")
            raise

    def check_email_pastes(self, email: str) -> List[Dict[str, Any]]:
        """
        Check if an email has been found in any pastes

        Args:
            email: Email address to check

        Returns:
            List of paste information dictionaries
        """
        if not self.api_key:
            raise ValueError("HIBP API key required for paste check")

        email = email.lower().strip()
        endpoint = f"{self.BASE_URL}/pasteaccount/{email}"

        try:
            with self._lock:
                time.sleep(1.5)

            response = self._session.get(endpoint, timeout=30)

            if response.status_code == 404:
                return []

            if self._handle_rate_limit(response):
                response = self._session.get(endpoint, timeout=30)

            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            if e.response.status_code in [401, 403]:
                logger.error("[HIBP] API key issue for paste check")
            raise

        except Exception as e:
            logger.error(f"[HIBP] Error checking pastes: {e}")
            raise

    def get_all_breaches(self, domain: Optional[str] = None) -> List[BreachInfo]:
        """
        Get all breaches in the system, optionally filtered by domain

        Args:
            domain: Optional domain to filter by

        Returns:
            List of BreachInfo objects
        """
        endpoint = f"{self.BASE_URL}/breaches"
        params = {}

        if domain:
            params["domain"] = domain

        try:
            response = self._session.get(endpoint, params=params, timeout=30)
            response.raise_for_status()

            breaches = []
            for breach_data in response.json():
                breaches.append(BreachInfo(
                    name=breach_data.get("Name", ""),
                    title=breach_data.get("Title", ""),
                    domain=breach_data.get("Domain", ""),
                    breach_date=breach_data.get("BreachDate", ""),
                    added_date=breach_data.get("AddedDate", ""),
                    modified_date=breach_data.get("ModifiedDate", ""),
                    pwn_count=breach_data.get("PwnCount", 0),
                    description=breach_data.get("Description", ""),
                    logo_path=breach_data.get("LogoPath"),
                    data_classes=breach_data.get("DataClasses", []),
                    is_verified=breach_data.get("IsVerified", True),
                    is_fabricated=breach_data.get("IsFabricated", False),
                    is_sensitive=breach_data.get("IsSensitive", False),
                    is_retired=breach_data.get("IsRetired", False),
                    is_spam_list=breach_data.get("IsSpamList", False),
                    is_malware=breach_data.get("IsMalware", False),
                    is_subscription_free=breach_data.get("IsSubscriptionFree", False)
                ))

            return breaches

        except Exception as e:
            logger.error(f"[HIBP] Error getting breaches: {e}")
            raise

    def get_breach(self, breach_name: str) -> Optional[BreachInfo]:
        """
        Get details about a specific breach

        Args:
            breach_name: Name of the breach

        Returns:
            BreachInfo or None
        """
        endpoint = f"{self.BASE_URL}/breach/{breach_name}"

        try:
            response = self._session.get(endpoint, timeout=30)

            if response.status_code == 404:
                return None

            response.raise_for_status()
            breach_data = response.json()

            return BreachInfo(
                name=breach_data.get("Name", ""),
                title=breach_data.get("Title", ""),
                domain=breach_data.get("Domain", ""),
                breach_date=breach_data.get("BreachDate", ""),
                added_date=breach_data.get("AddedDate", ""),
                modified_date=breach_data.get("ModifiedDate", ""),
                pwn_count=breach_data.get("PwnCount", 0),
                description=breach_data.get("Description", ""),
                logo_path=breach_data.get("LogoPath"),
                data_classes=breach_data.get("DataClasses", []),
                is_verified=breach_data.get("IsVerified", True),
                is_fabricated=breach_data.get("IsFabricated", False),
                is_sensitive=breach_data.get("IsSensitive", False),
                is_retired=breach_data.get("IsRetired", False),
                is_spam_list=breach_data.get("IsSpamList", False),
                is_malware=breach_data.get("IsMalware", False),
                is_subscription_free=breach_data.get("IsSubscriptionFree", False)
            )

        except Exception as e:
            logger.error(f"[HIBP] Error getting breach {breach_name}: {e}")
            return None

    def get_data_classes(self) -> List[str]:
        """Get all data classes in the system"""
        endpoint = f"{self.BASE_URL}/dataclasses"

        try:
            response = self._session.get(endpoint, timeout=30)
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.error(f"[HIBP] Error getting data classes: {e}")
            return []


class PasswordChecker:
    """
    Check if passwords have been exposed using k-Anonymity

    Uses HaveIBeenPwned's Pwned Passwords API with k-Anonymity
    to check passwords without revealing them.
    """

    API_URL = "https://api.pwnedpasswords.com/range"

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "TSUNAMI-SecurityPlatform/5.0",
            "Add-Padding": "true"  # Add padding to prevent response size analysis
        })

        logger.info("[PASSWORD-CHECK] Initialized with k-Anonymity")

    def check_password(self, password: str) -> PasswordCheckResult:
        """
        Check if a password has been exposed in breaches

        Uses k-Anonymity - only sends first 5 characters of SHA1 hash

        Args:
            password: Password to check (not sent to API)

        Returns:
            PasswordCheckResult
        """
        # Hash the password with SHA1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

        # Split into prefix (first 5 chars) and suffix
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            # Only send the prefix (k-Anonymity)
            response = self._session.get(
                f"{self.API_URL}/{prefix}",
                timeout=30
            )
            response.raise_for_status()

            # Search for our suffix in the results
            pwn_count = 0
            for line in response.text.splitlines():
                parts = line.split(":")
                if len(parts) == 2:
                    hash_suffix = parts[0]
                    count = int(parts[1])

                    if hash_suffix == suffix:
                        pwn_count = count
                        break

            is_pwned = pwn_count > 0

            # Generate recommendations
            recommendations = []
            if is_pwned:
                recommendations = [
                    "This password has been exposed in data breaches",
                    "Change this password immediately on all accounts",
                    "Use a unique, strong password for each account",
                    "Consider using a password manager",
                    "Enable two-factor authentication where possible"
                ]
                if pwn_count > 1000:
                    recommendations.insert(0, f"CRITICAL: This password has been seen {pwn_count:,} times in breaches")
            else:
                recommendations = [
                    "Password not found in known breaches",
                    "Still recommended to use unique passwords per account",
                    "Consider password manager for better security"
                ]

            return PasswordCheckResult(
                password_hash=f"{prefix}{'*' * 35}",  # Partial hash for reference
                is_pwned=is_pwned,
                pwn_count=pwn_count,
                recommendations=recommendations
            )

        except Exception as e:
            logger.error(f"[PASSWORD-CHECK] Error: {e}")
            raise

    def check_password_hash(self, sha1_hash: str) -> PasswordCheckResult:
        """
        Check if a SHA1 password hash has been exposed

        Args:
            sha1_hash: Full SHA1 hash of password

        Returns:
            PasswordCheckResult
        """
        sha1_hash = sha1_hash.upper()

        if len(sha1_hash) != 40:
            raise ValueError("Invalid SHA1 hash length")

        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            response = self._session.get(
                f"{self.API_URL}/{prefix}",
                timeout=30
            )
            response.raise_for_status()

            pwn_count = 0
            for line in response.text.splitlines():
                parts = line.split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    pwn_count = int(parts[1])
                    break

            return PasswordCheckResult(
                password_hash=sha1_hash,
                is_pwned=pwn_count > 0,
                pwn_count=pwn_count,
                recommendations=self._generate_recommendations(pwn_count)
            )

        except Exception as e:
            logger.error(f"[PASSWORD-CHECK] Hash check error: {e}")
            raise

    def _generate_recommendations(self, pwn_count: int) -> List[str]:
        """Generate recommendations based on pwn count"""
        if pwn_count == 0:
            return ["Password hash not found in known breaches"]
        elif pwn_count < 10:
            return [
                "Password seen in a small number of breaches",
                "Consider changing to a more unique password"
            ]
        elif pwn_count < 1000:
            return [
                f"Password seen {pwn_count} times in breaches",
                "This password should be changed",
                "Use a password manager to generate unique passwords"
            ]
        else:
            return [
                f"CRITICAL: Password seen {pwn_count:,} times in breaches",
                "Change this password immediately",
                "This is a commonly used password - avoid it completely"
            ]


class BreachChecker:
    """
    Main breach checking orchestrator

    Combines HIBP API with other breach databases for comprehensive checks.
    """

    def __init__(self, hibp_api_key: Optional[str] = None):
        """
        Initialize breach checker

        Args:
            hibp_api_key: HaveIBeenPwned API key
        """
        self.hibp = HaveIBeenPwnedClient(api_key=hibp_api_key)
        self.password_checker = PasswordChecker()
        self._cache: Dict[str, Tuple[BreachResult, datetime]] = {}
        self._cache_ttl = 3600  # 1 hour cache
        self._lock = threading.Lock()

        logger.info("[BREACH-CHECKER] Initialized")

    def check_email(self, email: str, check_pastes: bool = True) -> BreachResult:
        """
        Comprehensive breach check for an email

        Args:
            email: Email address to check
            check_pastes: Also check paste sites

        Returns:
            BreachResult with all findings
        """
        email = email.lower().strip()

        # Check cache
        cache_key = f"email:{email}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        breaches = []
        pastes = []
        exposed_data_types = set()

        try:
            # Check breaches
            breaches = self.hibp.check_email(email)

            # Check pastes if requested
            if check_pastes:
                try:
                    pastes = self.hibp.check_email_pastes(email)
                except:
                    pass  # Paste check might fail without API key

            # Collect exposed data types
            for breach in breaches:
                exposed_data_types.update(breach.data_classes)

        except ValueError as e:
            # No API key
            logger.warning(f"[BREACH-CHECKER] {e}")
        except Exception as e:
            logger.error(f"[BREACH-CHECKER] Error checking email: {e}")

        # Calculate severity
        severity = self._calculate_severity(breaches, pastes, exposed_data_types)

        # Get date range
        breach_dates = [b.breach_date for b in breaches if b.breach_date]
        first_breach = min(breach_dates) if breach_dates else None
        last_breach = max(breach_dates) if breach_dates else None

        # Generate recommendations
        recommendations = self._generate_email_recommendations(
            breaches, pastes, exposed_data_types
        )

        result = BreachResult(
            query=email,
            query_type="email",
            found_in_breach=len(breaches) > 0 or len(pastes) > 0,
            total_breaches=len(breaches),
            total_pastes=len(pastes),
            breaches=breaches,
            pastes=pastes,
            severity=severity,
            first_breach_date=first_breach,
            last_breach_date=last_breach,
            exposed_data_types=list(exposed_data_types),
            recommendations=recommendations
        )

        # Cache result
        self._set_cached(cache_key, result)

        return result

    def check_domain(self, domain: str) -> BreachResult:
        """
        Check if any breaches are associated with a domain

        Args:
            domain: Domain to check

        Returns:
            BreachResult
        """
        domain = domain.lower().strip()

        cache_key = f"domain:{domain}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        breaches = []
        exposed_data_types = set()

        try:
            breaches = self.hibp.get_all_breaches(domain=domain)

            for breach in breaches:
                exposed_data_types.update(breach.data_classes)

        except Exception as e:
            logger.error(f"[BREACH-CHECKER] Error checking domain: {e}")

        severity = self._calculate_severity(breaches, [], exposed_data_types)

        recommendations = []
        if breaches:
            recommendations = [
                f"Domain {domain} has been involved in {len(breaches)} breach(es)",
                "Review all user accounts associated with this domain",
                "Force password resets for affected users",
                "Enable multi-factor authentication",
                "Review and update security practices"
            ]

        result = BreachResult(
            query=domain,
            query_type="domain",
            found_in_breach=len(breaches) > 0,
            total_breaches=len(breaches),
            total_pastes=0,
            breaches=breaches,
            severity=severity,
            exposed_data_types=list(exposed_data_types),
            recommendations=recommendations
        )

        self._set_cached(cache_key, result)
        return result

    def check_password(self, password: str) -> PasswordCheckResult:
        """
        Check if a password has been exposed

        Args:
            password: Password to check

        Returns:
            PasswordCheckResult
        """
        return self.password_checker.check_password(password)

    def get_breach_info(self, breach_name: str) -> Optional[BreachInfo]:
        """Get information about a specific breach"""
        return self.hibp.get_breach(breach_name)

    def get_all_breaches(self) -> List[BreachInfo]:
        """Get list of all known breaches"""
        return self.hibp.get_all_breaches()

    def _calculate_severity(self,
                           breaches: List[BreachInfo],
                           pastes: List[Dict],
                           data_types: set) -> BreachSeverity:
        """Calculate overall severity based on findings"""
        if not breaches and not pastes:
            return BreachSeverity.INFO

        # Critical data types
        critical_types = {"Passwords", "Credit cards", "Bank account numbers", "Social security numbers"}
        high_types = {"Phone numbers", "Physical addresses", "Dates of birth", "Government issued IDs"}

        if data_types & critical_types:
            return BreachSeverity.CRITICAL

        if data_types & high_types or len(breaches) > 5:
            return BreachSeverity.HIGH

        if len(breaches) > 2 or pastes:
            return BreachSeverity.MEDIUM

        return BreachSeverity.LOW

    def _generate_email_recommendations(self,
                                        breaches: List[BreachInfo],
                                        pastes: List[Dict],
                                        data_types: set) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []

        if not breaches and not pastes:
            recommendations.append("No breaches found - maintain good security hygiene")
            recommendations.append("Continue using unique passwords for each account")
            return recommendations

        if breaches:
            recommendations.append(f"Found in {len(breaches)} breach(es) - take immediate action")

        if "Passwords" in data_types:
            recommendations.append("CRITICAL: Change passwords on all affected accounts immediately")
            recommendations.append("Do not reuse passwords across multiple sites")

        if "Credit cards" in data_types:
            recommendations.append("Monitor credit card statements for unauthorized transactions")
            recommendations.append("Consider placing a fraud alert on credit reports")

        if "Email addresses" in data_types:
            recommendations.append("Be vigilant for phishing attempts")
            recommendations.append("Enable email filtering for suspicious messages")

        if pastes:
            recommendations.append(f"Found in {len(pastes)} paste(s) - credentials may be publicly available")

        # General recommendations
        recommendations.append("Enable two-factor authentication on all important accounts")
        recommendations.append("Use a password manager to generate and store unique passwords")
        recommendations.append("Regularly monitor your accounts for suspicious activity")

        return recommendations

    def _get_cached(self, key: str) -> Optional[BreachResult]:
        """Get cached result if still valid"""
        with self._lock:
            if key in self._cache:
                result, timestamp = self._cache[key]
                if (datetime.now() - timestamp).total_seconds() < self._cache_ttl:
                    return result
                del self._cache[key]
        return None

    def _set_cached(self, key: str, result: BreachResult):
        """Cache a result"""
        with self._lock:
            self._cache[key] = (result, datetime.now())

            # Limit cache size
            if len(self._cache) > 1000:
                # Remove oldest entries
                sorted_items = sorted(
                    self._cache.items(),
                    key=lambda x: x[1][1]
                )
                for old_key, _ in sorted_items[:100]:
                    del self._cache[old_key]

    def get_statistics(self) -> Dict[str, Any]:
        """Get checker statistics"""
        return {
            "cache_size": len(self._cache),
            "hibp_api_configured": self.hibp.api_key is not None,
            "cache_ttl_seconds": self._cache_ttl
        }


# Convenience function
_breach_checker: Optional[BreachChecker] = None

def get_breach_checker() -> BreachChecker:
    """Get or create global breach checker instance"""
    global _breach_checker
    if _breach_checker is None:
        _breach_checker = BreachChecker()
    return _breach_checker
