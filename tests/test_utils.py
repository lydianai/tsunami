#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Utils Tests
===================

Comprehensive tests for utility modules.
"""

import pytest
import asyncio
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

sys.path.insert(0, str(Path(__file__).parent.parent))

# Check if pytest-asyncio is available
try:
    import pytest_asyncio
    HAS_ASYNCIO = True
except ImportError:
    HAS_ASYNCIO = False

# Skip async tests if pytest-asyncio not installed
asyncio_test = pytest.mark.asyncio if HAS_ASYNCIO else pytest.mark.skip(reason="pytest-asyncio not installed")


class TestCacheUtils:
    """Cache utility tests"""

    def test_timed_lru_cache_basic(self):
        """Test basic timed LRU cache functionality"""
        from utils.cache import timed_lru_cache

        call_count = 0

        @timed_lru_cache(seconds=60)
        def cached_func(x):
            nonlocal call_count
            call_count += 1
            return x ** 2

        # First call
        assert cached_func(5) == 25
        assert call_count == 1

        # Cached call
        assert cached_func(5) == 25
        assert call_count == 1

        # Different arg
        assert cached_func(6) == 36
        assert call_count == 2

    def test_cache_clear(self):
        """Test cache clearing"""
        from utils.cache import timed_lru_cache

        @timed_lru_cache(seconds=60)
        def cached_func(x):
            return x * 2

        cached_func(5)
        cached_func.cache_clear()

        # After clear, cache_info should show 0 hits
        info = cached_func.cache_info()
        assert info.hits == 0

    def test_cache_manager_memory_fallback(self):
        """Test CacheManager falls back to memory when Redis unavailable"""
        from utils.cache import CacheManager

        # Create manager without Redis
        manager = CacheManager(redis_url=None)

        # Should work with memory cache
        manager.set('test_key', {'data': 'value'}, ttl=60)
        result = manager.get('test_key')
        assert result == {'data': 'value'}

        # Delete
        manager.delete('test_key')
        assert manager.get('test_key') is None


class TestAsyncUtils:
    """Async utility tests"""

    @asyncio_test
    async def test_gather_with_concurrency(self):
        """Test concurrent gathering with limit"""
        from utils.async_utils import gather_with_concurrency

        async def slow_task(n):
            await asyncio.sleep(0.01)
            return n * 2

        results = await gather_with_concurrency(
            2,  # Only 2 concurrent
            slow_task(1),
            slow_task(2),
            slow_task(3),
            slow_task(4)
        )

        assert results == [2, 4, 6, 8]

    @asyncio_test
    async def test_retry_async_success(self):
        """Test retry succeeds on first try"""
        from utils.async_utils import retry_async

        async def success_func():
            return 'success'

        result = await retry_async(success_func, max_retries=3)
        assert result == 'success'

    @asyncio_test
    async def test_retry_async_eventual_success(self):
        """Test retry succeeds after failures"""
        from utils.async_utils import retry_async

        attempt = 0

        async def flaky_func():
            nonlocal attempt
            attempt += 1
            if attempt < 3:
                raise ValueError("Not yet")
            return 'success'

        result = await retry_async(
            flaky_func,
            max_retries=5,
            delay=0.01,
            backoff=1
        )
        assert result == 'success'
        assert attempt == 3

    @asyncio_test
    async def test_retry_async_all_fail(self):
        """Test retry raises after all attempts fail"""
        from utils.async_utils import retry_async

        async def always_fail():
            raise ValueError("Always fails")

        with pytest.raises(ValueError):
            await retry_async(
                always_fail,
                max_retries=2,
                delay=0.01
            )

    @asyncio_test
    async def test_timeout_async(self):
        """Test async timeout"""
        from utils.async_utils import timeout_async

        async def slow_task():
            await asyncio.sleep(1)
            return 'done'

        # Should timeout and return default
        result = await timeout_async(slow_task(), timeout=0.01, default='timeout')
        assert result == 'timeout'

    @asyncio_test
    async def test_parallel_map(self):
        """Test parallel map"""
        from utils.async_utils import parallel_map

        async def double(x):
            await asyncio.sleep(0.01)
            return x * 2

        results = await parallel_map(double, [1, 2, 3, 4, 5], concurrency=2)
        assert results == [2, 4, 6, 8, 10]


class TestSecurityUtils:
    """Security utility tests"""

    def test_sanitize_html_basic(self):
        """Test basic HTML sanitization"""
        from utils.security import sanitize_html

        # Script tags
        assert '&lt;script&gt;' in sanitize_html('<script>alert(1)</script>')

        # Event handlers
        result = sanitize_html('<img onerror="alert(1)">')
        assert 'onerror=' not in result or '&' in result

    def test_sanitize_html_preserves_text(self):
        """Test sanitization preserves normal text"""
        from utils.security import sanitize_html

        text = "Hello, this is normal text."
        assert sanitize_html(text) == text

    def test_sanitize_html_unicode_normalization(self):
        """Test unicode normalization in sanitization"""
        from utils.security import sanitize_html

        # Unicode that looks like < but isn't
        weird = '\uff1cscript\uff1e'  # Fullwidth < and >
        result = sanitize_html(weird)
        # Should be normalized
        assert 'script' in result.lower()

    def test_rate_limit_different_keys(self):
        """Test rate limit tracks different keys separately"""
        from utils.security import rate_limit_check

        key1 = f'user1_{time.time()}'
        key2 = f'user2_{time.time()}'

        # Exhaust key1
        for _ in range(5):
            rate_limit_check(key1, max_requests=5, window_seconds=60)

        # key1 should be blocked
        allowed1, _ = rate_limit_check(key1, max_requests=5, window_seconds=60)
        assert allowed1 == False

        # key2 should still be allowed
        allowed2, _ = rate_limit_check(key2, max_requests=5, window_seconds=60)
        assert allowed2 == True

    def test_generate_token(self):
        """Test secure token generation"""
        from utils.security import generate_token

        token1 = generate_token(32)
        token2 = generate_token(32)

        # Should be different
        assert token1 != token2
        # Should be URL-safe
        assert all(c.isalnum() or c in '-_' for c in token1)

    def test_constant_time_compare(self):
        """Test constant time comparison"""
        from utils.security import constant_time_compare

        assert constant_time_compare('secret', 'secret') == True
        assert constant_time_compare('secret', 'different') == False
        assert constant_time_compare('', '') == True


class TestInputValidator:
    """Input validator tests"""

    def test_email_edge_cases(self):
        """Test email validation edge cases"""
        from utils.security import validator

        # Valid edge cases
        assert validator.is_valid_email('a@b.co') == True
        assert validator.is_valid_email('user+tag@example.com') == True

        # Invalid edge cases
        assert validator.is_valid_email('@example.com') == False
        assert validator.is_valid_email('user@') == False
        assert validator.is_valid_email('user@.com') == False

    def test_ip_edge_cases(self):
        """Test IP validation edge cases"""
        from utils.security import validator

        # Edge cases
        assert validator.is_valid_ip('1.2.3.4') == True
        assert validator.is_valid_ip('01.02.03.04') == True  # Leading zeros

        # Invalid
        assert validator.is_valid_ip('1.2.3.256') == False
        assert validator.is_valid_ip('1.2.3') == False
        assert validator.is_valid_ip('1.2.3.4.5') == False

    def test_domain_edge_cases(self):
        """Test domain validation edge cases"""
        from utils.security import validator

        # Valid
        assert validator.is_valid_domain('a.co') == True
        assert validator.is_valid_domain('sub.domain.example.com') == True

        # Invalid
        assert validator.is_valid_domain('-invalid.com') == False
        assert validator.is_valid_domain('invalid-.com') == False

    def test_safe_path_edge_cases(self):
        """Test path safety edge cases"""
        from utils.security import validator

        base = '/var/www/uploads'

        # Safe paths
        assert validator.is_safe_path('image.jpg', base) == True
        assert validator.is_safe_path('user123/avatar.png', base) == True

        # Unsafe paths
        assert validator.is_safe_path('../etc/passwd', base) == False
        assert validator.is_safe_path('foo/../../etc/passwd', base) == False
        assert validator.is_safe_path('/etc/passwd', base) == False


class TestFilenameValidation:
    """Filename validation tests"""

    def test_sanitize_filename_traversal(self):
        """Test path traversal prevention"""
        from utils.security import sanitize_filename

        dangerous = '../../../etc/passwd'
        safe = sanitize_filename(dangerous)
        assert '..' not in safe
        assert '/' not in safe

    def test_sanitize_filename_special_chars(self):
        """Test special character removal"""
        from utils.security import sanitize_filename

        dangerous = 'file<>:"|?*.txt'
        safe = sanitize_filename(dangerous)
        assert '<' not in safe
        assert '>' not in safe
        assert ':' not in safe

    def test_sanitize_filename_preserves_extension(self):
        """Test extension is preserved"""
        from utils.security import sanitize_filename

        result = sanitize_filename('document.pdf')
        assert result.endswith('.pdf')

    def test_sanitize_filename_empty(self):
        """Test empty filename handling"""
        from utils.security import sanitize_filename

        assert sanitize_filename('') == 'unnamed'
        assert sanitize_filename(None) == 'unnamed'
