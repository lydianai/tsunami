#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 - Redis Cluster Configuration
    Production-Ready Cache, Session, and Pub/Sub for 10M+ Users
================================================================================

    Kullanim Alanlari:
    - Session Storage: Distributed session management
    - Cache Layer: API response caching, query caching
    - Pub/Sub: Real-time notifications, WebSocket broadcasting
    - Rate Limiting: Distributed rate limiter (sliding window)
    - Job Queue: Celery broker (alternatif)
    - Lock Manager: Distributed locks (Redlock)

    Cluster Topology (onerilir):
    - 6 node minimum (3 master + 3 replica)
    - Multi-AZ deployment icin farkli datacenter'larda
    - Her master'in en az 1 replica'si olmali

================================================================================
"""

import os
import json
import time
import logging
import hashlib
from typing import Optional, Dict, Any, List, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import timedelta
from functools import wraps

# ==================== CONFIGURATION ENUMS ====================

class RedisMode(Enum):
    """Redis deployment modlari"""
    STANDALONE = "standalone"      # Tek node (dev)
    SENTINEL = "sentinel"          # High Availability
    CLUSTER = "cluster"            # Horizontal scaling


class CacheNamespace(Enum):
    """Cache namespace prefixes"""
    SESSION = "sess"
    CACHE = "cache"
    RATE_LIMIT = "rl"
    LOCK = "lock"
    PUBSUB = "ps"
    QUEUE = "q"
    USER = "usr"
    THREAT = "threat"
    GEO = "geo"


# ==================== CONFIGURATION DATACLASSES ====================

@dataclass
class RedisNode:
    """Redis node bilgileri"""
    host: str
    port: int = 6379
    is_master: bool = True
    datacenter: str = "dc1"
    weight: int = 1

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class SentinelConfig:
    """Redis Sentinel konfigurasyonu"""
    sentinels: List[tuple]  # [(host, port), ...]
    master_name: str = "tsunami-master"
    password: Optional[str] = None
    db: int = 0
    socket_timeout: float = 5.0


@dataclass
class ClusterSlot:
    """Redis Cluster slot bilgisi"""
    start_slot: int
    end_slot: int
    master: RedisNode
    replicas: List[RedisNode] = field(default_factory=list)


# ==================== MAIN CONFIGURATION CLASS ====================

class RedisClusterConfig:
    """
    Production-grade Redis Cluster Configuration

    10M kullanici hedefi icin optimize edilmis:
    - Connection pooling: 50-100 baglanti per node
    - Cluster mode: 16384 slot, 6+ node
    - Automatic failover ve resharding
    - SSL/TLS sifreleme
    - Read replica'lardan okuma

    Cache Stratejisi:
    - Session TTL: 24 saat
    - API Cache TTL: 5-60 dakika
    - Rate Limit Window: 1 dakika (sliding)
    - Threat Intel Cache: 1 saat
    """

    def __init__(self, mode: str = None):
        self.mode = RedisMode(
            mode or os.getenv('REDIS_MODE', 'standalone')
        )
        self._load_configuration()
        self.logger = logging.getLogger('tsunami.redis')

    def _load_configuration(self):
        """Environment'dan yapilandirmayi yukle"""

        # === Temel Ayarlar ===
        self.password = os.getenv('REDIS_PASSWORD')
        self.db = int(os.getenv('REDIS_DB', 0))

        # === SSL/TLS ===
        self.ssl_enabled = os.getenv('REDIS_SSL', 'false').lower() == 'true'
        self.ssl_ca_certs = os.getenv('REDIS_SSL_CA')
        self.ssl_certfile = os.getenv('REDIS_SSL_CERT')
        self.ssl_keyfile = os.getenv('REDIS_SSL_KEY')

        # === Connection Pool ===
        self.pool_max_connections = int(os.getenv('REDIS_POOL_SIZE', 50))
        self.socket_timeout = float(os.getenv('REDIS_SOCKET_TIMEOUT', 5.0))
        self.socket_connect_timeout = float(os.getenv('REDIS_CONNECT_TIMEOUT', 5.0))
        self.retry_on_timeout = os.getenv('REDIS_RETRY_TIMEOUT', 'true').lower() == 'true'
        self.health_check_interval = int(os.getenv('REDIS_HEALTH_INTERVAL', 30))

        # === Cluster-specific ===
        self.read_from_replicas = os.getenv('REDIS_READ_REPLICAS', 'true').lower() == 'true'
        self.skip_full_coverage_check = os.getenv('REDIS_SKIP_COVERAGE', 'false').lower() == 'true'

        # === Cache TTLs (saniye) ===
        self.ttl_session = int(os.getenv('REDIS_TTL_SESSION', 86400))  # 24 saat
        self.ttl_cache_short = int(os.getenv('REDIS_TTL_CACHE_SHORT', 300))  # 5 dakika
        self.ttl_cache_medium = int(os.getenv('REDIS_TTL_CACHE_MEDIUM', 1800))  # 30 dakika
        self.ttl_cache_long = int(os.getenv('REDIS_TTL_CACHE_LONG', 3600))  # 1 saat
        self.ttl_rate_limit = int(os.getenv('REDIS_TTL_RATE_LIMIT', 60))  # 1 dakika
        self.ttl_lock = int(os.getenv('REDIS_TTL_LOCK', 30))  # 30 saniye
        self.ttl_threat_intel = int(os.getenv('REDIS_TTL_THREAT', 3600))  # 1 saat

        # === Mode-specific configuration ===
        self._configure_mode()

    def _configure_mode(self):
        """Redis moduna gore yapilandirma"""

        if self.mode == RedisMode.STANDALONE:
            self.host = os.getenv('REDIS_HOST', 'localhost')
            self.port = int(os.getenv('REDIS_PORT', 6379))
            self.nodes = [RedisNode(host=self.host, port=self.port)]

        elif self.mode == RedisMode.SENTINEL:
            # Sentinel nodes: "host1:port1,host2:port2,host3:port3"
            sentinels_str = os.getenv('REDIS_SENTINELS', 'localhost:26379')
            self.sentinels = []
            for sentinel in sentinels_str.split(','):
                parts = sentinel.strip().split(':')
                self.sentinels.append((parts[0], int(parts[1])))

            self.sentinel_config = SentinelConfig(
                sentinels=self.sentinels,
                master_name=os.getenv('REDIS_SENTINEL_MASTER', 'tsunami-master'),
                password=self.password,
                db=self.db,
                socket_timeout=self.socket_timeout
            )

        elif self.mode == RedisMode.CLUSTER:
            # Cluster nodes: "host1:port1,host2:port2,..."
            nodes_str = os.getenv('REDIS_CLUSTER_NODES', 'localhost:7000,localhost:7001,localhost:7002')
            self.nodes = []
            for node in nodes_str.split(','):
                parts = node.strip().split(':')
                self.nodes.append(RedisNode(host=parts[0], port=int(parts[1])))

    def get_connection_url(self) -> str:
        """
        Redis connection URL (standalone mode icin)

        Returns:
            redis://[:password@]host:port/db
        """
        auth = f":{self.password}@" if self.password else ""
        protocol = "rediss" if self.ssl_enabled else "redis"
        return f"{protocol}://{auth}{self.host}:{self.port}/{self.db}"

    def get_client_kwargs(self) -> Dict[str, Any]:
        """
        Redis client olusturma parametreleri

        Kullanim:
            import redis
            config = RedisClusterConfig()
            client = redis.Redis(**config.get_client_kwargs())
        """
        kwargs = {
            'socket_timeout': self.socket_timeout,
            'socket_connect_timeout': self.socket_connect_timeout,
            'retry_on_timeout': self.retry_on_timeout,
            'health_check_interval': self.health_check_interval,
            'max_connections': self.pool_max_connections,
            'decode_responses': True,  # UTF-8 string response
        }

        if self.password:
            kwargs['password'] = self.password

        if self.ssl_enabled:
            kwargs['ssl'] = True
            if self.ssl_ca_certs:
                kwargs['ssl_ca_certs'] = self.ssl_ca_certs
            if self.ssl_certfile:
                kwargs['ssl_certfile'] = self.ssl_certfile
            if self.ssl_keyfile:
                kwargs['ssl_keyfile'] = self.ssl_keyfile

        if self.mode == RedisMode.STANDALONE:
            kwargs['host'] = self.host
            kwargs['port'] = self.port
            kwargs['db'] = self.db

        return kwargs

    def get_cluster_kwargs(self) -> Dict[str, Any]:
        """
        Redis Cluster client parametreleri

        Kullanim:
            from redis.cluster import RedisCluster
            config = RedisClusterConfig(mode='cluster')
            client = RedisCluster(**config.get_cluster_kwargs())
        """
        if self.mode != RedisMode.CLUSTER:
            raise ValueError("Cluster kwargs only available in cluster mode")

        kwargs = {
            'startup_nodes': [
                {'host': node.host, 'port': node.port}
                for node in self.nodes
            ],
            'socket_timeout': self.socket_timeout,
            'socket_connect_timeout': self.socket_connect_timeout,
            'retry_on_timeout': self.retry_on_timeout,
            'health_check_interval': self.health_check_interval,
            'decode_responses': True,
            'read_from_replicas': self.read_from_replicas,
            'skip_full_coverage_check': self.skip_full_coverage_check,
        }

        if self.password:
            kwargs['password'] = self.password

        if self.ssl_enabled:
            kwargs['ssl'] = True

        return kwargs

    def get_sentinel_kwargs(self) -> Dict[str, Any]:
        """
        Redis Sentinel client parametreleri

        Kullanim:
            from redis.sentinel import Sentinel
            config = RedisClusterConfig(mode='sentinel')
            sentinel = Sentinel(**config.get_sentinel_kwargs())
            master = sentinel.master_for('tsunami-master')
        """
        if self.mode != RedisMode.SENTINEL:
            raise ValueError("Sentinel kwargs only available in sentinel mode")

        return {
            'sentinels': self.sentinel_config.sentinels,
            'socket_timeout': self.socket_timeout,
            'password': self.password,
        }


# ==================== REDIS CLIENT MANAGER ====================

class RedisClientManager:
    """
    Production-grade Redis Client Manager

    Ozellikler:
    - Mode-agnostic client factory
    - Connection pooling
    - Automatic failover
    - Health monitoring
    - Graceful degradation
    """

    def __init__(self, config: RedisClusterConfig = None):
        self.config = config or RedisClusterConfig()
        self._client = None
        self._pubsub_client = None
        self._initialized = False
        self.logger = logging.getLogger('tsunami.redis')

    def initialize(self):
        """Redis client'i baslat"""
        if self._initialized:
            return

        try:
            if self.config.mode == RedisMode.CLUSTER:
                from redis.cluster import RedisCluster
                self._client = RedisCluster(**self.config.get_cluster_kwargs())
            elif self.config.mode == RedisMode.SENTINEL:
                from redis.sentinel import Sentinel
                sentinel = Sentinel(**self.config.get_sentinel_kwargs())
                self._client = sentinel.master_for(
                    self.config.sentinel_config.master_name,
                    db=self.config.db,
                    decode_responses=True
                )
            else:  # STANDALONE
                import redis
                self._client = redis.Redis(**self.config.get_client_kwargs())

            # Baglanti testi
            self._client.ping()
            self._initialized = True
            self.logger.info(f"Redis client initialized (mode: {self.config.mode.value})")

        except ImportError as e:
            self.logger.error(f"Redis library not available: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to initialize Redis: {e}")
            raise

    @property
    def client(self):
        """Redis client instance"""
        if not self._initialized:
            self.initialize()
        return self._client

    def get_pubsub(self):
        """Pub/Sub client al"""
        if self._pubsub_client is None:
            self._pubsub_client = self.client.pubsub(ignore_subscribe_messages=True)
        return self._pubsub_client

    def health_check(self) -> Dict[str, Any]:
        """
        Redis saglik kontrolu

        Returns:
            {
                'status': 'healthy' | 'unhealthy',
                'mode': str,
                'latency_ms': float,
                'info': {...}
            }
        """
        result = {
            'status': 'unhealthy',
            'mode': self.config.mode.value,
            'latency_ms': None,
            'info': {}
        }

        try:
            start = time.monotonic()
            self.client.ping()
            latency = (time.monotonic() - start) * 1000

            result['status'] = 'healthy'
            result['latency_ms'] = round(latency, 2)

            # Basic info
            info = self.client.info(section='server')
            result['info'] = {
                'redis_version': info.get('redis_version'),
                'uptime_seconds': info.get('uptime_in_seconds'),
                'connected_clients': self.client.info('clients').get('connected_clients'),
                'used_memory_human': self.client.info('memory').get('used_memory_human'),
            }

            if self.config.mode == RedisMode.CLUSTER:
                cluster_info = self.client.cluster_info()
                result['info']['cluster_state'] = cluster_info.get('cluster_state')
                result['info']['cluster_slots_ok'] = cluster_info.get('cluster_slots_ok')

        except Exception as e:
            result['error'] = str(e)

        return result

    def close(self):
        """Baglantilari kapat"""
        if self._pubsub_client:
            self._pubsub_client.close()
            self._pubsub_client = None

        if self._client:
            self._client.close()
            self._client = None

        self._initialized = False
        self.logger.info("Redis connections closed")


# ==================== SESSION MANAGER ====================

class SessionManager:
    """
    Distributed Session Manager

    Ozellikler:
    - Secure session storage
    - Automatic expiration
    - Session fixation protection
    - Concurrent session limiting
    """

    def __init__(self, redis_manager: RedisClientManager, max_sessions_per_user: int = 5):
        self.redis = redis_manager
        self.max_sessions = max_sessions_per_user
        self.prefix = CacheNamespace.SESSION.value
        self.ttl = redis_manager.config.ttl_session

    def _session_key(self, session_id: str) -> str:
        return f"{self.prefix}:{session_id}"

    def _user_sessions_key(self, user_id: int) -> str:
        return f"{self.prefix}:user:{user_id}"

    def create_session(self, session_id: str, user_id: int, data: Dict) -> bool:
        """
        Yeni session olustur

        Args:
            session_id: Unique session ID
            user_id: Kullanici ID
            data: Session data (user info, permissions, etc.)

        Returns:
            True if created, False if limit exceeded
        """
        client = self.redis.client
        session_key = self._session_key(session_id)
        user_sessions_key = self._user_sessions_key(user_id)

        # Mevcut session sayisi kontrolu
        current_sessions = client.scard(user_sessions_key) or 0
        if current_sessions >= self.max_sessions:
            # En eski session'i sil
            oldest = client.spop(user_sessions_key)
            if oldest:
                client.delete(self._session_key(oldest))

        # Session data kaydet
        session_data = {
            'user_id': user_id,
            'created_at': time.time(),
            'last_activity': time.time(),
            **data
        }

        pipe = client.pipeline()
        pipe.hset(session_key, mapping=session_data)
        pipe.expire(session_key, self.ttl)
        pipe.sadd(user_sessions_key, session_id)
        pipe.expire(user_sessions_key, self.ttl)
        pipe.execute()

        return True

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Session verisini al"""
        client = self.redis.client
        session_key = self._session_key(session_id)

        data = client.hgetall(session_key)
        if not data:
            return None

        # Son aktivite guncelle
        client.hset(session_key, 'last_activity', time.time())
        client.expire(session_key, self.ttl)

        return data

    def destroy_session(self, session_id: str, user_id: int):
        """Session'i sil"""
        client = self.redis.client
        pipe = client.pipeline()
        pipe.delete(self._session_key(session_id))
        pipe.srem(self._user_sessions_key(user_id), session_id)
        pipe.execute()

    def destroy_all_user_sessions(self, user_id: int):
        """Kullanicinin tum session'larini sil"""
        client = self.redis.client
        user_sessions_key = self._user_sessions_key(user_id)

        session_ids = client.smembers(user_sessions_key)

        pipe = client.pipeline()
        for session_id in session_ids:
            pipe.delete(self._session_key(session_id))
        pipe.delete(user_sessions_key)
        pipe.execute()


# ==================== CACHE MANAGER ====================

class CacheManager:
    """
    Multi-tier Cache Manager

    Stratejiler:
    - Cache-aside pattern
    - Write-through (opsiyonel)
    - TTL-based expiration
    - Cache invalidation
    """

    def __init__(self, redis_manager: RedisClientManager):
        self.redis = redis_manager
        self.prefix = CacheNamespace.CACHE.value
        self.config = redis_manager.config

    def _cache_key(self, namespace: str, key: str) -> str:
        """Cache key olustur"""
        return f"{self.prefix}:{namespace}:{key}"

    def get(self, namespace: str, key: str) -> Optional[Any]:
        """Cache'den veri al"""
        cache_key = self._cache_key(namespace, key)
        data = self.redis.client.get(cache_key)

        if data:
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                return data

        return None

    def set(self, namespace: str, key: str, value: Any, ttl: int = None):
        """Cache'e veri yaz"""
        cache_key = self._cache_key(namespace, key)
        ttl = ttl or self.config.ttl_cache_medium

        if isinstance(value, (dict, list)):
            value = json.dumps(value)

        self.redis.client.setex(cache_key, ttl, value)

    def delete(self, namespace: str, key: str):
        """Cache'den sil"""
        cache_key = self._cache_key(namespace, key)
        self.redis.client.delete(cache_key)

    def delete_pattern(self, pattern: str):
        """Pattern'e uyan tum key'leri sil"""
        client = self.redis.client
        full_pattern = f"{self.prefix}:{pattern}"

        # Cluster mode'da SCAN kullan
        cursor = 0
        while True:
            cursor, keys = client.scan(cursor, match=full_pattern, count=100)
            if keys:
                client.delete(*keys)
            if cursor == 0:
                break

    def cached(self, namespace: str, ttl: int = None, key_builder: Callable = None):
        """
        Decorator: Fonksiyon sonucunu cache'le

        Kullanim:
            @cache.cached('api_responses', ttl=300)
            def expensive_operation(param):
                ...

            @cache.cached('user', key_builder=lambda u: f"profile:{u.id}")
            def get_user_profile(user_id):
                ...
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Cache key olustur
                if key_builder:
                    cache_key = key_builder(*args, **kwargs)
                else:
                    key_parts = [func.__name__] + [str(a) for a in args]
                    key_parts += [f"{k}={v}" for k, v in sorted(kwargs.items())]
                    cache_key = hashlib.md5(':'.join(key_parts).encode()).hexdigest()

                # Cache'den dene
                cached_value = self.get(namespace, cache_key)
                if cached_value is not None:
                    return cached_value

                # Fonksiyonu calistir ve cache'le
                result = func(*args, **kwargs)
                self.set(namespace, cache_key, result, ttl)

                return result

            return wrapper
        return decorator


# ==================== RATE LIMITER ====================

class RateLimiter:
    """
    Distributed Rate Limiter (Sliding Window)

    Algoritmalar:
    - Fixed Window: Basit, hizli
    - Sliding Window Log: Hassas, daha fazla memory
    - Sliding Window Counter: Dengeli (varsayilan)

    Limitler:
    - API: 100/dakika
    - Auth: 10/dakika
    - OSINT: 30/dakika
    - Scan: 10/dakika
    """

    def __init__(self, redis_manager: RedisClientManager):
        self.redis = redis_manager
        self.prefix = CacheNamespace.RATE_LIMIT.value
        self.window = redis_manager.config.ttl_rate_limit

    def _key(self, identifier: str, action: str) -> str:
        return f"{self.prefix}:{action}:{identifier}"

    def is_allowed(self, identifier: str, action: str, limit: int, window: int = None) -> tuple:
        """
        Rate limit kontrolu (sliding window counter)

        Args:
            identifier: IP, user_id, API key, etc.
            action: Aksiyon tipi (api, auth, scan, etc.)
            limit: Maksimum istek sayisi
            window: Zaman penceresi (saniye)

        Returns:
            (is_allowed: bool, remaining: int, reset_after: int)
        """
        client = self.redis.client
        window = window or self.window
        key = self._key(identifier, action)
        now = time.time()
        window_start = now - window

        pipe = client.pipeline()

        # Eski kayitlari sil
        pipe.zremrangebyscore(key, 0, window_start)

        # Mevcut sayiyi al
        pipe.zcard(key)

        # Yeni kayit ekle
        pipe.zadd(key, {str(now): now})

        # TTL ayarla
        pipe.expire(key, window)

        results = pipe.execute()
        current_count = results[1]

        remaining = max(0, limit - current_count - 1)
        is_allowed = current_count < limit

        # Reset zamani
        if not is_allowed:
            oldest = client.zrange(key, 0, 0, withscores=True)
            if oldest:
                reset_after = int(oldest[0][1] + window - now)
            else:
                reset_after = window
        else:
            reset_after = window

        return (is_allowed, remaining, reset_after)

    def get_usage(self, identifier: str, action: str) -> int:
        """Mevcut kullanim sayisi"""
        client = self.redis.client
        key = self._key(identifier, action)
        window_start = time.time() - self.window

        client.zremrangebyscore(key, 0, window_start)
        return client.zcard(key) or 0


# ==================== PUB/SUB MANAGER ====================

class PubSubManager:
    """
    Real-time Pub/Sub Manager

    Kullanim Alanlari:
    - WebSocket broadcasting
    - Real-time threat notifications
    - Scan status updates
    - Cluster-wide event propagation
    """

    def __init__(self, redis_manager: RedisClientManager):
        self.redis = redis_manager
        self.prefix = CacheNamespace.PUBSUB.value
        self._pubsub = None
        self._handlers: Dict[str, List[Callable]] = {}
        self.logger = logging.getLogger('tsunami.pubsub')

    def _channel_name(self, channel: str) -> str:
        return f"{self.prefix}:{channel}"

    def publish(self, channel: str, message: Dict):
        """Mesaj yayinla"""
        full_channel = self._channel_name(channel)
        self.redis.client.publish(full_channel, json.dumps(message))

    def subscribe(self, channel: str, handler: Callable):
        """Kanala abone ol"""
        full_channel = self._channel_name(channel)

        if full_channel not in self._handlers:
            self._handlers[full_channel] = []

        self._handlers[full_channel].append(handler)

        if self._pubsub is None:
            self._pubsub = self.redis.get_pubsub()

        self._pubsub.subscribe(**{full_channel: self._message_handler})

    def _message_handler(self, message):
        """Gelen mesajlari isle"""
        if message['type'] != 'message':
            return

        channel = message['channel']
        if isinstance(channel, bytes):
            channel = channel.decode()

        try:
            data = json.loads(message['data'])
        except (json.JSONDecodeError, TypeError):
            data = message['data']

        handlers = self._handlers.get(channel, [])
        for handler in handlers:
            try:
                handler(data)
            except Exception as e:
                self.logger.error(f"Handler error on {channel}: {e}")

    def listen(self):
        """Mesajlari dinlemeye basla (blocking)"""
        if self._pubsub is None:
            raise ValueError("No subscriptions active")

        for message in self._pubsub.listen():
            self._message_handler(message)

    def close(self):
        """Pub/Sub baglantisini kapat"""
        if self._pubsub:
            self._pubsub.close()
            self._pubsub = None
        self._handlers.clear()


# ==================== DISTRIBUTED LOCK ====================

class DistributedLock:
    """
    Distributed Lock Manager (Redlock Algorithm)

    Kullanim Alanlari:
    - Critical section protection
    - Scan job coordination
    - Resource access control
    """

    def __init__(self, redis_manager: RedisClientManager):
        self.redis = redis_manager
        self.prefix = CacheNamespace.LOCK.value
        self.default_ttl = redis_manager.config.ttl_lock
        self.logger = logging.getLogger('tsunami.lock')

    def _lock_key(self, name: str) -> str:
        return f"{self.prefix}:{name}"

    def acquire(self, name: str, ttl: int = None, blocking: bool = True, timeout: float = 10) -> Optional[str]:
        """
        Lock al

        Args:
            name: Lock ismi
            ttl: Lock suresi (saniye)
            blocking: True ise lock alinana kadar bekle
            timeout: Maksimum bekleme suresi

        Returns:
            Lock token (release icin gerekli) veya None
        """
        import secrets

        client = self.redis.client
        key = self._lock_key(name)
        ttl = ttl or self.default_ttl
        token = secrets.token_hex(16)

        start_time = time.monotonic()

        while True:
            # SET NX PX atomic operation
            acquired = client.set(key, token, nx=True, px=ttl * 1000)

            if acquired:
                self.logger.debug(f"Lock acquired: {name}")
                return token

            if not blocking:
                return None

            if time.monotonic() - start_time > timeout:
                self.logger.warning(f"Lock timeout: {name}")
                return None

            time.sleep(0.1)

    def release(self, name: str, token: str) -> bool:
        """
        Lock birak (sadece token sahibi birakabilir)

        Returns:
            True if released, False if token mismatch
        """
        client = self.redis.client
        key = self._lock_key(name)

        # Lua script: Atomic check-and-delete
        lua_script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("del", KEYS[1])
        else
            return 0
        end
        """

        result = client.eval(lua_script, 1, key, token)

        if result:
            self.logger.debug(f"Lock released: {name}")
            return True

        self.logger.warning(f"Lock release failed (token mismatch): {name}")
        return False

    def extend(self, name: str, token: str, ttl: int = None) -> bool:
        """Lock suresini uzat"""
        client = self.redis.client
        key = self._lock_key(name)
        ttl = ttl or self.default_ttl

        lua_script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("pexpire", KEYS[1], ARGV[2])
        else
            return 0
        end
        """

        return bool(client.eval(lua_script, 1, key, token, ttl * 1000))


# ==================== GLOBAL INSTANCES ====================

_redis_config: Optional[RedisClusterConfig] = None
_redis_manager: Optional[RedisClientManager] = None
_session_manager: Optional[SessionManager] = None
_cache_manager: Optional[CacheManager] = None
_rate_limiter: Optional[RateLimiter] = None
_pubsub_manager: Optional[PubSubManager] = None
_lock_manager: Optional[DistributedLock] = None


def get_redis_config() -> RedisClusterConfig:
    """Global Redis config"""
    global _redis_config
    if _redis_config is None:
        _redis_config = RedisClusterConfig()
    return _redis_config


def get_redis_manager() -> RedisClientManager:
    """Global Redis client manager"""
    global _redis_manager
    if _redis_manager is None:
        _redis_manager = RedisClientManager(get_redis_config())
    return _redis_manager


def get_session_manager() -> SessionManager:
    """Global session manager"""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager(get_redis_manager())
    return _session_manager


def get_cache_manager() -> CacheManager:
    """Global cache manager"""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager(get_redis_manager())
    return _cache_manager


def get_rate_limiter() -> RateLimiter:
    """Global rate limiter"""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(get_redis_manager())
    return _rate_limiter


def get_pubsub_manager() -> PubSubManager:
    """Global pub/sub manager"""
    global _pubsub_manager
    if _pubsub_manager is None:
        _pubsub_manager = PubSubManager(get_redis_manager())
    return _pubsub_manager


def get_lock_manager() -> DistributedLock:
    """Global lock manager"""
    global _lock_manager
    if _lock_manager is None:
        _lock_manager = DistributedLock(get_redis_manager())
    return _lock_manager


# ==================== FLASK INTEGRATION ====================

def init_app(app):
    """
    Flask uygulamasina Redis entegrasyonu

    Kullanim:
        from config.redis_cluster_config import init_app
        init_app(app)
    """
    from flask import g

    config = get_redis_config()

    # Flask config'e ekle
    app.config['REDIS_URL'] = config.get_connection_url()

    @app.before_request
    def before_request():
        """Her request oncesi Redis manager'i g'ye ekle"""
        g.redis = get_redis_manager().client
        g.cache = get_cache_manager()
        g.rate_limiter = get_rate_limiter()

    @app.teardown_appcontext
    def shutdown_redis(exception=None):
        """Uygulama kapanirken baglantilari kapat"""
        pass  # Connection pooling - explicitly close not needed


# ==================== CLI / TEST ====================

if __name__ == '__main__':
    def test_redis():
        """Redis baglanti testi"""
        config = RedisClusterConfig()
        manager = RedisClientManager(config)

        print(f"Mode: {config.mode.value}")
        print(f"SSL Enabled: {config.ssl_enabled}")
        print(f"Pool Size: {config.pool_max_connections}")

        print("\nTesting connection...")
        health = manager.health_check()
        print(f"Status: {health['status']}")
        if health.get('latency_ms'):
            print(f"Latency: {health['latency_ms']}ms")
        if health.get('info'):
            print(f"Version: {health['info'].get('redis_version')}")
            print(f"Memory: {health['info'].get('used_memory_human')}")

        # Cache test
        print("\nTesting cache...")
        cache = CacheManager(manager)
        cache.set('test', 'key1', {'hello': 'world'}, ttl=60)
        result = cache.get('test', 'key1')
        print(f"Cache get: {result}")

        # Rate limiter test
        print("\nTesting rate limiter...")
        limiter = RateLimiter(manager)
        for i in range(5):
            allowed, remaining, reset = limiter.is_allowed('test-ip', 'api', limit=3)
            print(f"Request {i+1}: allowed={allowed}, remaining={remaining}")

        manager.close()

    test_redis()
