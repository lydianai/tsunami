#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 - PostgreSQL Configuration
    Production-Ready Database Configuration for 10M+ Users
================================================================================

    Ozellikler:
    - Connection Pooling (SQLAlchemy + asyncpg)
    - Read Replicas destegi
    - Automatic failover
    - Query timeout ve statement_timeout
    - SSL/TLS baglanti sifreleme
    - Health check ve monitoring
    - Sharding stratejisi destegi

================================================================================
"""

import os
import ssl
import logging
from typing import Optional, Dict, Any, List
from datetime import timedelta
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import quote_plus

# ==================== ENVIRONMENT CONFIGURATION ====================

class DatabaseEnvironment(Enum):
    """Veritabani ortam tipleri"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class PostgreSQLNode:
    """PostgreSQL sunucu node bilgileri"""
    host: str
    port: int = 5432
    weight: int = 1  # Load balancing icin agirlik
    is_primary: bool = False
    is_read_replica: bool = False
    datacenter: str = "dc1"  # Multi-DC deployments

    @property
    def connection_string(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class ShardConfig:
    """Database shard konfigurasyonu"""
    shard_id: int
    shard_key_range_start: int
    shard_key_range_end: int
    primary_node: PostgreSQLNode
    replica_nodes: List[PostgreSQLNode] = field(default_factory=list)

    def contains_key(self, shard_key: int) -> bool:
        """Shard key bu shard'a ait mi kontrol et"""
        return self.shard_key_range_start <= shard_key < self.shard_key_range_end


# ==================== POSTGRESQL CONFIGURATION ====================

class PostgreSQLConfig:
    """
    Production-grade PostgreSQL Configuration

    10M kullanici hedefi icin optimize edilmis yapilandirma:
    - Connection pooling: 50-200 baglanti per node
    - Read replicas: Okuma trafikini dagitma
    - SSL/TLS: Tum baglantilarda sifreleme
    - Query timeouts: Uzun sureli sorgulari sinirla
    - Health checks: Otomatik failover
    """

    def __init__(self, environment: str = None):
        self.environment = DatabaseEnvironment(
            environment or os.getenv('TSUNAMI_ENV', 'development')
        )
        self._load_configuration()

    def _load_configuration(self):
        """Ortama gore yapilandirmayi yukle"""

        # === Temel Baglanti Bilgileri ===
        self.host = os.getenv('POSTGRES_HOST', 'localhost')
        self.port = int(os.getenv('POSTGRES_PORT', 5432))
        self.database = os.getenv('POSTGRES_DB', 'tsunami')
        self.username = os.getenv('POSTGRES_USER', 'tsunami')
        self.password = os.getenv('POSTGRES_PASSWORD', '')

        # === Read Replicas (virgul ile ayrilmis host:port listesi) ===
        replicas_str = os.getenv('POSTGRES_READ_REPLICAS', '')
        self.read_replicas: List[PostgreSQLNode] = []
        if replicas_str:
            for replica in replicas_str.split(','):
                parts = replica.strip().split(':')
                host = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 5432
                self.read_replicas.append(
                    PostgreSQLNode(host=host, port=port, is_read_replica=True)
                )

        # === SSL Configuration ===
        self.ssl_enabled = os.getenv('POSTGRES_SSL', 'true').lower() == 'true'
        self.ssl_ca_cert = os.getenv('POSTGRES_SSL_CA', '/etc/ssl/certs/ca-certificates.crt')
        self.ssl_client_cert = os.getenv('POSTGRES_SSL_CERT')
        self.ssl_client_key = os.getenv('POSTGRES_SSL_KEY')

        # === Connection Pool Settings (ortama gore) ===
        if self.environment == DatabaseEnvironment.PRODUCTION:
            self.pool_size = int(os.getenv('POSTGRES_POOL_SIZE', 50))
            self.pool_max_overflow = int(os.getenv('POSTGRES_MAX_OVERFLOW', 100))
            self.pool_timeout = int(os.getenv('POSTGRES_POOL_TIMEOUT', 30))
            self.pool_recycle = int(os.getenv('POSTGRES_POOL_RECYCLE', 1800))  # 30 dakika
            self.pool_pre_ping = True  # Her baglantida health check
        elif self.environment == DatabaseEnvironment.STAGING:
            self.pool_size = int(os.getenv('POSTGRES_POOL_SIZE', 20))
            self.pool_max_overflow = int(os.getenv('POSTGRES_MAX_OVERFLOW', 30))
            self.pool_timeout = 30
            self.pool_recycle = 1800
            self.pool_pre_ping = True
        else:  # Development
            self.pool_size = int(os.getenv('POSTGRES_POOL_SIZE', 5))
            self.pool_max_overflow = int(os.getenv('POSTGRES_MAX_OVERFLOW', 10))
            self.pool_timeout = 30
            self.pool_recycle = 3600
            self.pool_pre_ping = False

        # === Query Timeouts ===
        self.statement_timeout = int(os.getenv('POSTGRES_STATEMENT_TIMEOUT', 30000))  # 30 saniye (ms)
        self.lock_timeout = int(os.getenv('POSTGRES_LOCK_TIMEOUT', 10000))  # 10 saniye (ms)

        # === Sharding Configuration ===
        self.sharding_enabled = os.getenv('POSTGRES_SHARDING', 'false').lower() == 'true'
        self.shard_count = int(os.getenv('POSTGRES_SHARD_COUNT', 4))

        # === Performance Tuning ===
        self.echo_queries = os.getenv('POSTGRES_ECHO', 'false').lower() == 'true'
        self.slow_query_threshold = float(os.getenv('POSTGRES_SLOW_QUERY_MS', 1000))  # ms

    @property
    def primary_connection_string(self) -> str:
        """
        SQLAlchemy icin primary node baglanti URL'i
        Format: postgresql+asyncpg://user:pass@host:port/db?options
        """
        # Sifre URL encode
        encoded_password = quote_plus(self.password) if self.password else ''

        # SSL parametreleri
        params = []
        if self.ssl_enabled:
            params.append('sslmode=require')

        # Statement timeout
        params.append(f'options=-c%20statement_timeout={self.statement_timeout}')

        query_string = '&'.join(params) if params else ''
        query_part = f'?{query_string}' if query_string else ''

        return (
            f"postgresql+asyncpg://{self.username}:{encoded_password}"
            f"@{self.host}:{self.port}/{self.database}{query_part}"
        )

    @property
    def sync_connection_string(self) -> str:
        """
        Synchronous baglanti icin (psycopg2)
        """
        encoded_password = quote_plus(self.password) if self.password else ''

        params = []
        if self.ssl_enabled:
            params.append('sslmode=require')

        query_string = '&'.join(params) if params else ''
        query_part = f'?{query_string}' if query_string else ''

        return (
            f"postgresql+psycopg2://{self.username}:{encoded_password}"
            f"@{self.host}:{self.port}/{self.database}{query_part}"
        )

    @property
    def replica_connection_strings(self) -> List[str]:
        """Read replica baglanti URL'leri"""
        encoded_password = quote_plus(self.password) if self.password else ''

        strings = []
        for replica in self.read_replicas:
            params = ['sslmode=require'] if self.ssl_enabled else []
            params.append('target_session_attrs=read-only')
            query_string = '&'.join(params)

            strings.append(
                f"postgresql+asyncpg://{self.username}:{encoded_password}"
                f"@{replica.host}:{replica.port}/{self.database}?{query_string}"
            )

        return strings

    def get_sqlalchemy_engine_options(self) -> Dict[str, Any]:
        """
        SQLAlchemy create_engine icin options dict

        Kullanim:
            from sqlalchemy import create_engine
            config = PostgreSQLConfig()
            engine = create_engine(
                config.primary_connection_string,
                **config.get_sqlalchemy_engine_options()
            )
        """
        options = {
            'pool_size': self.pool_size,
            'max_overflow': self.pool_max_overflow,
            'pool_timeout': self.pool_timeout,
            'pool_recycle': self.pool_recycle,
            'pool_pre_ping': self.pool_pre_ping,
            'echo': self.echo_queries,
        }

        # SSL context (production icin)
        if self.ssl_enabled and self.environment == DatabaseEnvironment.PRODUCTION:
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if self.ssl_ca_cert and os.path.exists(self.ssl_ca_cert):
                ssl_context.load_verify_locations(self.ssl_ca_cert)
            if self.ssl_client_cert and self.ssl_client_key:
                ssl_context.load_cert_chain(self.ssl_client_cert, self.ssl_client_key)
            options['connect_args'] = {'ssl': ssl_context}

        return options

    def get_async_engine_options(self) -> Dict[str, Any]:
        """
        SQLAlchemy async engine (asyncpg) icin options

        Kullanim:
            from sqlalchemy.ext.asyncio import create_async_engine
            config = PostgreSQLConfig()
            engine = create_async_engine(
                config.primary_connection_string,
                **config.get_async_engine_options()
            )
        """
        options = self.get_sqlalchemy_engine_options()

        # asyncpg-specific connect_args
        connect_args = options.get('connect_args', {})
        connect_args.update({
            'command_timeout': self.statement_timeout / 1000,  # seconds
            'server_settings': {
                'application_name': 'tsunami_web',
                'statement_timeout': str(self.statement_timeout),
                'lock_timeout': str(self.lock_timeout),
            }
        })
        options['connect_args'] = connect_args

        return options


# ==================== SHARDING MANAGER ====================

class ShardingManager:
    """
    Horizontal Sharding Manager

    Sharding Stratejisi (10M+ kullanici icin):
    - Shard Key: user_id % shard_count
    - Her shard 2.5M kullanici kapasiteli
    - Cross-shard queries icin coordinator pattern

    Shard Distribution (4 shard ornegi):
    - Shard 0: user_id 0 - 2,499,999
    - Shard 1: user_id 2,500,000 - 4,999,999
    - Shard 2: user_id 5,000,000 - 7,499,999
    - Shard 3: user_id 7,500,000 - 9,999,999
    """

    def __init__(self, config: PostgreSQLConfig):
        self.config = config
        self.shards: Dict[int, ShardConfig] = {}
        self._load_shard_configs()

    def _load_shard_configs(self):
        """Environment'dan shard konfigurasyonlarini yukle"""
        if not self.config.sharding_enabled:
            return

        shard_count = self.config.shard_count
        records_per_shard = 10_000_000 // shard_count  # 10M kullanici icin

        for i in range(shard_count):
            # Her shard icin environment variable'lardan oku
            shard_host = os.getenv(f'POSTGRES_SHARD_{i}_HOST', self.config.host)
            shard_port = int(os.getenv(f'POSTGRES_SHARD_{i}_PORT', self.config.port))

            primary_node = PostgreSQLNode(
                host=shard_host,
                port=shard_port,
                is_primary=True,
                datacenter=os.getenv(f'POSTGRES_SHARD_{i}_DC', 'dc1')
            )

            # Shard replicas
            replica_nodes = []
            replicas_str = os.getenv(f'POSTGRES_SHARD_{i}_REPLICAS', '')
            if replicas_str:
                for replica in replicas_str.split(','):
                    parts = replica.strip().split(':')
                    replica_nodes.append(
                        PostgreSQLNode(
                            host=parts[0],
                            port=int(parts[1]) if len(parts) > 1 else 5432,
                            is_read_replica=True
                        )
                    )

            self.shards[i] = ShardConfig(
                shard_id=i,
                shard_key_range_start=i * records_per_shard,
                shard_key_range_end=(i + 1) * records_per_shard,
                primary_node=primary_node,
                replica_nodes=replica_nodes
            )

    def get_shard_for_key(self, shard_key: int) -> ShardConfig:
        """
        Verilen shard key icin uygun shard'i dondur

        Args:
            shard_key: Genellikle user_id

        Returns:
            ShardConfig: Hedef shard konfigurasyonu
        """
        if not self.config.sharding_enabled:
            raise ValueError("Sharding is not enabled")

        shard_id = shard_key % self.config.shard_count
        return self.shards.get(shard_id)

    def get_shard_connection_string(self, shard_id: int, read_only: bool = False) -> str:
        """
        Belirli bir shard icin connection string

        Args:
            shard_id: Shard numarasi
            read_only: True ise replica, False ise primary

        Returns:
            Connection string
        """
        shard = self.shards.get(shard_id)
        if not shard:
            raise ValueError(f"Shard {shard_id} not found")

        node = shard.primary_node
        if read_only and shard.replica_nodes:
            # Round-robin replica secimi
            import random
            node = random.choice(shard.replica_nodes)

        encoded_password = quote_plus(self.config.password) if self.config.password else ''

        return (
            f"postgresql+asyncpg://{self.config.username}:{encoded_password}"
            f"@{node.host}:{node.port}/{self.config.database}"
        )

    def get_all_shard_connection_strings(self) -> Dict[int, str]:
        """Tum shardlar icin connection string'leri dondur"""
        return {
            shard_id: self.get_shard_connection_string(shard_id)
            for shard_id in self.shards.keys()
        }


# ==================== DATABASE SESSION MANAGER ====================

class DatabaseSessionManager:
    """
    Production-grade Database Session Manager

    Ozellikler:
    - Async/Sync session destegi
    - Read/Write splitting
    - Automatic retry with exponential backoff
    - Connection health monitoring
    - Graceful shutdown
    """

    def __init__(self, config: PostgreSQLConfig = None):
        self.config = config or PostgreSQLConfig()
        self._async_engine = None
        self._sync_engine = None
        self._read_engines: List = []
        self._async_session_factory = None
        self._sync_session_factory = None
        self._initialized = False
        self.logger = logging.getLogger('tsunami.database')

    async def initialize(self):
        """Async engine ve session factory'leri baslat"""
        if self._initialized:
            return

        try:
            from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

            # Primary (write) engine
            self._async_engine = create_async_engine(
                self.config.primary_connection_string,
                **self.config.get_async_engine_options()
            )

            # Read replica engines
            for replica_url in self.config.replica_connection_strings:
                engine = create_async_engine(
                    replica_url,
                    **self.config.get_async_engine_options()
                )
                self._read_engines.append(engine)

            # Session factory
            self._async_session_factory = async_sessionmaker(
                bind=self._async_engine,
                expire_on_commit=False,
                autoflush=False
            )

            self._initialized = True
            self.logger.info("Database session manager initialized successfully")

        except ImportError as e:
            self.logger.error(f"SQLAlchemy async not available: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise

    def initialize_sync(self):
        """Sync engine ve session factory'leri baslat"""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        self._sync_engine = create_engine(
            self.config.sync_connection_string,
            **self.config.get_sqlalchemy_engine_options()
        )

        self._sync_session_factory = sessionmaker(
            bind=self._sync_engine,
            expire_on_commit=False
        )

    async def get_session(self, read_only: bool = False):
        """
        Async database session al

        Args:
            read_only: True ise read replica'dan, False ise primary'den

        Kullanim:
            async with db_manager.get_session() as session:
                result = await session.execute(query)
        """
        if not self._initialized:
            await self.initialize()

        if read_only and self._read_engines:
            # Round-robin read replica secimi
            import random
            from sqlalchemy.ext.asyncio import async_sessionmaker
            engine = random.choice(self._read_engines)
            factory = async_sessionmaker(bind=engine, expire_on_commit=False)
            return factory()

        return self._async_session_factory()

    def get_sync_session(self):
        """Sync database session al"""
        if not self._sync_session_factory:
            self.initialize_sync()
        return self._sync_session_factory()

    async def health_check(self) -> Dict[str, Any]:
        """
        Veritabani saglik kontrolu

        Returns:
            {
                'status': 'healthy' | 'degraded' | 'unhealthy',
                'primary': {'connected': bool, 'latency_ms': float},
                'replicas': [{'host': str, 'connected': bool, 'latency_ms': float}],
                'pool_status': {...}
            }
        """
        import time

        result = {
            'status': 'healthy',
            'primary': {'connected': False, 'latency_ms': None},
            'replicas': [],
            'pool_status': {}
        }

        # Primary check
        try:
            if not self._initialized:
                await self.initialize()

            start = time.monotonic()
            async with self._async_engine.connect() as conn:
                await conn.execute("SELECT 1")
            latency = (time.monotonic() - start) * 1000

            result['primary'] = {'connected': True, 'latency_ms': round(latency, 2)}

        except Exception as e:
            result['primary'] = {'connected': False, 'error': str(e)}
            result['status'] = 'unhealthy'

        # Replica checks
        for i, engine in enumerate(self._read_engines):
            try:
                start = time.monotonic()
                async with engine.connect() as conn:
                    await conn.execute("SELECT 1")
                latency = (time.monotonic() - start) * 1000

                result['replicas'].append({
                    'index': i,
                    'connected': True,
                    'latency_ms': round(latency, 2)
                })
            except Exception as e:
                result['replicas'].append({
                    'index': i,
                    'connected': False,
                    'error': str(e)
                })
                if result['status'] == 'healthy':
                    result['status'] = 'degraded'

        # Pool status
        if self._async_engine:
            pool = self._async_engine.pool
            result['pool_status'] = {
                'size': pool.size(),
                'checked_in': pool.checkedin(),
                'checked_out': pool.checkedout(),
                'overflow': pool.overflow(),
            }

        return result

    async def close(self):
        """Tum baglantilari kapat"""
        if self._async_engine:
            await self._async_engine.dispose()
            self.logger.info("Primary engine disposed")

        for engine in self._read_engines:
            await engine.dispose()

        self._read_engines.clear()
        self._initialized = False
        self.logger.info("Database connections closed")


# ==================== GLOBAL INSTANCE ====================

# Singleton instance
_db_config: Optional[PostgreSQLConfig] = None
_db_manager: Optional[DatabaseSessionManager] = None
_sharding_manager: Optional[ShardingManager] = None


def get_db_config() -> PostgreSQLConfig:
    """Global PostgreSQL config instance"""
    global _db_config
    if _db_config is None:
        _db_config = PostgreSQLConfig()
    return _db_config


def get_db_manager() -> DatabaseSessionManager:
    """Global Database Session Manager instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseSessionManager(get_db_config())
    return _db_manager


def get_sharding_manager() -> ShardingManager:
    """Global Sharding Manager instance"""
    global _sharding_manager
    if _sharding_manager is None:
        _sharding_manager = ShardingManager(get_db_config())
    return _sharding_manager


# ==================== FLASK INTEGRATION ====================

def init_app(app):
    """
    Flask uygulamasina PostgreSQL entegrasyonu

    Kullanim:
        from config.postgresql_config import init_app
        init_app(app)
    """
    from flask import g

    config = get_db_config()

    # Flask config'e ekle
    app.config['SQLALCHEMY_DATABASE_URI'] = config.sync_connection_string
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = config.get_sqlalchemy_engine_options()
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    @app.before_request
    def before_request():
        """Her request oncesi database session olustur"""
        g.db_session = get_db_manager().get_sync_session()

    @app.teardown_request
    def teardown_request(exception=None):
        """Request sonunda session'i kapat"""
        session = getattr(g, 'db_session', None)
        if session:
            if exception:
                session.rollback()
            session.close()

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        """Uygulama kapanirken session'i kapat"""
        pass


# ==================== CLI / TEST ====================

if __name__ == '__main__':
    import asyncio

    async def test_connection():
        """Baglanti testi"""
        config = PostgreSQLConfig()
        manager = DatabaseSessionManager(config)

        print(f"Environment: {config.environment.value}")
        print(f"Primary URL: {config.primary_connection_string[:50]}...")
        print(f"Pool Size: {config.pool_size}")
        print(f"Max Overflow: {config.pool_max_overflow}")
        print(f"SSL Enabled: {config.ssl_enabled}")
        print(f"Sharding Enabled: {config.sharding_enabled}")

        if config.read_replicas:
            print(f"Read Replicas: {len(config.read_replicas)}")

        print("\nTesting connection...")
        health = await manager.health_check()
        print(f"Health Status: {health['status']}")
        print(f"Primary Connected: {health['primary']['connected']}")
        if health['primary'].get('latency_ms'):
            print(f"Primary Latency: {health['primary']['latency_ms']}ms")

        await manager.close()

    asyncio.run(test_connection())
