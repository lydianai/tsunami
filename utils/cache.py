"""
TSUNAMI Cache Utilities - AILYDIAN AutoFix Generated
Production-ready caching with TTL support for Redis and in-memory
"""

import functools
import hashlib
import json
import time
from typing import Any, Callable, Optional
import logging

logger = logging.getLogger(__name__)

# In-memory cache storage
_memory_cache = {}
_cache_timestamps = {}


def cache_key(*args, **kwargs) -> str:
    """Generate a unique cache key from arguments"""
    key_data = json.dumps({'args': args, 'kwargs': kwargs}, sort_keys=True, default=str)
    return hashlib.md5(key_data.encode()).hexdigest()


def timed_lru_cache(seconds: int = 300, maxsize: int = 128):
    """
    LRU cache with TTL (Time To Live) support.

    Usage:
        @timed_lru_cache(seconds=60)
        def expensive_function(arg1, arg2):
            ...

    Args:
        seconds: Cache TTL in seconds (default: 5 minutes)
        maxsize: Maximum cache size (default: 128)
    """
    def decorator(func: Callable) -> Callable:
        func = functools.lru_cache(maxsize=maxsize)(func)
        func.expiration = time.time() + seconds
        func.ttl = seconds

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if time.time() > func.expiration:
                func.cache_clear()
                func.expiration = time.time() + func.ttl
            return func(*args, **kwargs)

        wrapper.cache_clear = func.cache_clear
        wrapper.cache_info = func.cache_info
        return wrapper

    return decorator


def redis_cache(
    ttl: int = 300,
    prefix: str = 'tsunami',
    redis_client: Optional[Any] = None
):
    """
    Redis-based caching decorator with automatic fallback to memory cache.

    Usage:
        @redis_cache(ttl=60, prefix='api')
        def api_call(endpoint):
            ...

    Args:
        ttl: Cache TTL in seconds (default: 5 minutes)
        prefix: Cache key prefix (default: 'tsunami')
        redis_client: Optional Redis client instance
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            key = f"{prefix}:{func.__name__}:{cache_key(*args, **kwargs)}"

            # Try Redis first
            if redis_client:
                try:
                    cached = redis_client.get(key)
                    if cached:
                        logger.debug(f"Redis cache HIT: {key}")
                        return json.loads(cached)
                except Exception as e:
                    logger.warning(f"Redis error, falling back to memory: {e}")

            # Fallback to memory cache
            if key in _memory_cache:
                if time.time() < _cache_timestamps.get(key, 0):
                    logger.debug(f"Memory cache HIT: {key}")
                    return _memory_cache[key]
                else:
                    # Expired
                    del _memory_cache[key]
                    del _cache_timestamps[key]

            # Cache miss - execute function
            logger.debug(f"Cache MISS: {key}")
            result = func(*args, **kwargs)

            # Store in Redis
            if redis_client:
                try:
                    redis_client.setex(key, ttl, json.dumps(result, default=str))
                except Exception as e:
                    logger.warning(f"Redis store error: {e}")

            # Store in memory as fallback
            _memory_cache[key] = result
            _cache_timestamps[key] = time.time() + ttl

            # Memory cache cleanup (simple LRU-ish)
            if len(_memory_cache) > 1000:
                oldest = min(_cache_timestamps, key=_cache_timestamps.get)
                del _memory_cache[oldest]
                del _cache_timestamps[oldest]

            return result

        def cache_clear():
            """Clear cache for this function"""
            pattern = f"{prefix}:{func.__name__}:*"
            if redis_client:
                try:
                    keys = redis_client.keys(pattern)
                    if keys:
                        redis_client.delete(*keys)
                except:
                    pass

            # Clear memory cache
            to_delete = [k for k in _memory_cache if k.startswith(f"{prefix}:{func.__name__}:")]
            for k in to_delete:
                del _memory_cache[k]
                del _cache_timestamps[k]

        wrapper.cache_clear = cache_clear
        return wrapper

    return decorator


class CacheManager:
    """
    Centralized cache management for TSUNAMI.

    Usage:
        cache = CacheManager(redis_url='redis://localhost:6379')

        @cache.cached(ttl=60)
        def my_function():
            ...
    """

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_client = None
        if redis_url:
            try:
                import redis
                self.redis_client = redis.from_url(redis_url)
                self.redis_client.ping()
                logger.info(f"CacheManager connected to Redis: {redis_url}")
            except Exception as e:
                logger.warning(f"Redis connection failed, using memory cache: {e}")

    def cached(self, ttl: int = 300, prefix: str = 'tsunami'):
        """Decorator for caching function results"""
        return redis_cache(ttl=ttl, prefix=prefix, redis_client=self.redis_client)

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if self.redis_client:
            try:
                value = self.redis_client.get(key)
                return json.loads(value) if value else None
            except:
                pass
        return _memory_cache.get(key)

    def set(self, key: str, value: Any, ttl: int = 300):
        """Set value in cache"""
        if self.redis_client:
            try:
                self.redis_client.setex(key, ttl, json.dumps(value, default=str))
                return
            except:
                pass
        _memory_cache[key] = value
        _cache_timestamps[key] = time.time() + ttl

    def delete(self, key: str):
        """Delete value from cache"""
        if self.redis_client:
            try:
                self.redis_client.delete(key)
            except:
                pass
        _memory_cache.pop(key, None)
        _cache_timestamps.pop(key, None)

    def clear_all(self):
        """Clear all cached values"""
        if self.redis_client:
            try:
                self.redis_client.flushdb()
            except:
                pass
        _memory_cache.clear()
        _cache_timestamps.clear()
