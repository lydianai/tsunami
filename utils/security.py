"""
TSUNAMI Security Utilities - AILYDIAN AutoFix Generated
Production-ready security helpers for input validation and protection
"""

import hashlib
import hmac
import html
import logging
import os
import re
import secrets
import time
from functools import wraps
from typing import Any, Callable, Dict, Optional, Tuple
import unicodedata

logger = logging.getLogger(__name__)

# Rate limiting storage
_rate_limit_data: Dict[str, Dict[str, Any]] = {}


def sanitize_html(text: str, allow_basic: bool = False) -> str:
    """
    Sanitize HTML to prevent XSS attacks.

    Usage:
        safe_text = sanitize_html(user_input)
        # With basic formatting allowed:
        safe_text = sanitize_html(user_input, allow_basic=True)

    Args:
        text: Input text to sanitize
        allow_basic: If True, allow <b>, <i>, <u>, <br> tags

    Returns:
        Sanitized text safe for HTML rendering
    """
    if not text:
        return ''

    # Normalize unicode to prevent bypass attacks
    text = unicodedata.normalize('NFKC', str(text))

    # Escape all HTML
    text = html.escape(text, quote=True)

    if allow_basic:
        # Re-enable basic formatting tags (already escaped)
        safe_tags = {
            '&lt;b&gt;': '<b>', '&lt;/b&gt;': '</b>',
            '&lt;i&gt;': '<i>', '&lt;/i&gt;': '</i>',
            '&lt;u&gt;': '<u>', '&lt;/u&gt;': '</u>',
            '&lt;br&gt;': '<br>', '&lt;br/&gt;': '<br/>',
        }
        for escaped, original in safe_tags.items():
            text = text.replace(escaped, original)

    return text


def sanitize_sql_identifier(identifier: str) -> str:
    """
    Sanitize SQL identifiers (table/column names).
    Only allows alphanumeric and underscore.

    Usage:
        safe_column = sanitize_sql_identifier(user_column_name)
    """
    if not identifier:
        raise ValueError("SQL identifier cannot be empty")

    # Only allow alphanumeric and underscore
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
        raise ValueError(f"Invalid SQL identifier: {identifier}")

    return identifier


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal attacks.

    Usage:
        safe_name = sanitize_filename(uploaded_file.filename)
    """
    if not filename:
        return 'unnamed'

    # Remove path components
    filename = os.path.basename(filename)

    # Remove null bytes and other dangerous chars
    filename = filename.replace('\x00', '')

    # Only allow safe characters
    filename = re.sub(r'[^\w\-_\. ]', '', filename)

    # Prevent hidden files
    filename = filename.lstrip('.')

    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255 - len(ext)] + ext

    return filename or 'unnamed'


def rate_limit_check(
    key: str,
    max_requests: int = 100,
    window_seconds: int = 60
) -> Tuple[bool, int]:
    """
    Check if a request should be rate limited.

    Usage:
        allowed, remaining = rate_limit_check(f"user:{user_id}", max_requests=10, window_seconds=60)
        if not allowed:
            return jsonify({'error': 'Rate limited'}), 429

    Args:
        key: Unique identifier for rate limiting (e.g., user ID, IP)
        max_requests: Maximum requests allowed in window
        window_seconds: Time window in seconds

    Returns:
        Tuple of (is_allowed, remaining_requests)
    """
    now = time.time()
    window_start = now - window_seconds

    # Initialize or get existing data
    if key not in _rate_limit_data:
        _rate_limit_data[key] = {'requests': [], 'blocked_until': 0}

    data = _rate_limit_data[key]

    # Check if currently blocked
    if now < data['blocked_until']:
        return False, 0

    # Remove old requests outside window
    data['requests'] = [t for t in data['requests'] if t > window_start]

    # Check rate limit
    if len(data['requests']) >= max_requests:
        # Block for remaining window time
        data['blocked_until'] = now + window_seconds
        return False, 0

    # Add current request
    data['requests'].append(now)
    remaining = max_requests - len(data['requests'])

    return True, remaining


def rate_limit(
    max_requests: int = 100,
    window_seconds: int = 60,
    key_func: Optional[Callable] = None
):
    """
    Rate limiting decorator for Flask routes.

    Usage:
        @app.route('/api/data')
        @rate_limit(max_requests=10, window_seconds=60)
        def api_data():
            ...

    Args:
        max_requests: Maximum requests allowed in window
        window_seconds: Time window in seconds
        key_func: Function to generate rate limit key (default: uses request IP)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            from flask import request, jsonify

            # Generate key
            if key_func:
                key = key_func()
            else:
                key = f"ip:{request.remote_addr}"

            allowed, remaining = rate_limit_check(key, max_requests, window_seconds)

            if not allowed:
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': window_seconds
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(window_seconds)
                response.headers['X-RateLimit-Remaining'] = '0'
                return response

            # Add rate limit headers to response
            result = func(*args, **kwargs)

            # If result is a Response object, add headers
            if hasattr(result, 'headers'):
                result.headers['X-RateLimit-Limit'] = str(max_requests)
                result.headers['X-RateLimit-Remaining'] = str(remaining)

            return result

        return wrapper
    return decorator


def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """
    Hash a password using PBKDF2-SHA256 (secure but lighter than Argon2).
    For new projects, prefer Argon2 via passlib.

    Usage:
        hashed, salt = hash_password(user_password)
        # Store both in database

    Args:
        password: Plain text password
        salt: Optional salt (generated if not provided)

    Returns:
        Tuple of (password_hash, salt) as hex strings
    """
    if salt is None:
        salt = secrets.token_bytes(32)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)

    # Use PBKDF2 with 600,000 iterations (OWASP 2023 recommendation)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations=600000
    )

    return password_hash.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """
    Verify a password against stored hash.

    Usage:
        if verify_password(input_password, user.password_hash, user.salt):
            # Login successful

    Args:
        password: Plain text password to verify
        stored_hash: Stored password hash (hex string)
        salt: Stored salt (hex string)

    Returns:
        True if password matches
    """
    computed_hash, _ = hash_password(password, salt)
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(computed_hash, stored_hash)


def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)


def constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())


class InputValidator:
    """
    Input validation helper for common patterns.

    Usage:
        validator = InputValidator()
        if validator.is_valid_email(email):
            ...
    """

    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )

    IP_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )

    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )

    URL_PATTERN = re.compile(
        r'^https?://(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})'
        r'(?:/[^\s]*)?$'
    )

    def is_valid_email(self, email: str) -> bool:
        """Validate email address format."""
        if not email or len(email) > 254:
            return False
        return bool(self.EMAIL_PATTERN.match(email))

    def is_valid_ip(self, ip: str) -> bool:
        """Validate IPv4 address format."""
        if not ip:
            return False
        return bool(self.IP_PATTERN.match(ip))

    def is_valid_domain(self, domain: str) -> bool:
        """Validate domain name format."""
        if not domain or len(domain) > 253:
            return False
        return bool(self.DOMAIN_PATTERN.match(domain))

    def is_valid_url(self, url: str) -> bool:
        """Validate URL format (http/https only)."""
        if not url or len(url) > 2048:
            return False
        return bool(self.URL_PATTERN.match(url))

    def is_safe_path(self, path: str, base_dir: str) -> bool:
        """Check if path is safe (no traversal outside base_dir)."""
        if not path or not base_dir:
            return False

        # Resolve to absolute paths
        abs_base = os.path.abspath(base_dir)
        abs_path = os.path.abspath(os.path.join(base_dir, path))

        # Check if path is within base directory
        return abs_path.startswith(abs_base)


# Global validator instance
validator = InputValidator()
