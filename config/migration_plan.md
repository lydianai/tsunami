# TSUNAMI v5.0 - PostgreSQL + Redis Cluster Migration Plan

## Executive Summary

Bu dokuman, TSUNAMI v5.0 icin SQLite'dan PostgreSQL'e gecis ve Redis Cluster entegrasyonunu adim adim aciklar. Hedef: **10 milyon kullanici** destegi ile production-grade altyapi.

---

## Mevcut Durum Analizi

### Veritabani Yapisi (SQLite)

```
dalga_v2.db / tsunami.db
├── kullanicilar         (users)
├── wifi_aglar           (wifi networks)
├── bluetooth_cihazlar   (bluetooth devices)
├── baz_istasyonlari     (cell towers)
├── iot_cihazlar         (IoT devices)
├── zafiyetler           (vulnerabilities)
├── alarmlar             (alerts)
├── tarama_gecmisi       (scan history)
├── api_anahtarlari      (API keys - encrypted)
├── oturum_kayitlari     (session logs)
├── pentest_projeler     (pentest projects)
├── pentest_bulgular     (pentest findings)
└── pentest_gorevler     (pentest tasks)
```

### Mevcut Stack
- **Backend**: Flask 3.0.3 + Flask-SocketIO
- **Database**: SQLite (tek dosya)
- **Session**: Flask session (server-side)
- **Cache**: Yok (in-memory)
- **Queue**: Yok (Celery planli)

### Hedef Stack
- **Backend**: Flask 3.0.3 + Flask-SocketIO + Gunicorn
- **Database**: PostgreSQL 16+ (Cluster)
- **Session**: Redis (distributed)
- **Cache**: Redis (multi-tier)
- **Queue**: Celery + Redis (broker)
- **Pub/Sub**: Redis (real-time)

---

## Migration Stratejisi

### Faz 1: Hazirlik (1 Hafta)

#### 1.1 Altyapi Kurulumu

```bash
# PostgreSQL 16 kurulumu (Ubuntu/Debian)
sudo apt update
sudo apt install postgresql-16 postgresql-contrib-16

# Redis 7.x kurulumu
sudo apt install redis-server

# Python bagimliliklari
pip install psycopg2-binary asyncpg sqlalchemy[asyncio] redis

# Production icin
pip install psycopg2 asyncpg[sa]
```

#### 1.2 PostgreSQL Cluster Yapisi

**Development (tek node):**
```
postgres:5432 (primary)
```

**Production (6 node cluster):**
```
DC1:
├── pg-master-1:5432      (primary, shard 0-1)
├── pg-replica-1a:5432    (sync replica)
└── pg-replica-1b:5432    (async replica)

DC2:
├── pg-master-2:5432      (primary, shard 2-3)
├── pg-replica-2a:5432    (sync replica)
└── pg-replica-2b:5432    (async replica)
```

#### 1.3 Redis Cluster Yapisi

**Development:**
```
redis:6379 (standalone)
```

**Production (6 node cluster):**
```
├── redis-1:7000 (master, slots 0-5460)
├── redis-2:7001 (master, slots 5461-10922)
├── redis-3:7002 (master, slots 10923-16383)
├── redis-4:7003 (replica of redis-1)
├── redis-5:7004 (replica of redis-2)
└── redis-6:7005 (replica of redis-3)
```

---

### Faz 2: Schema Migration (2-3 Gun)

#### 2.1 PostgreSQL Schema Olusturma

```sql
-- /home/lydian/Desktop/TSUNAMI/migrations/001_initial_schema.sql

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";       -- Full-text search
CREATE EXTENSION IF NOT EXISTS "postgis";        -- Geospatial (opsiyonel)

-- ==================== USERS ====================
CREATE TABLE kullanicilar (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    kullanici_adi VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    sifre_hash VARCHAR(255) NOT NULL,
    rol VARCHAR(20) DEFAULT 'user' CHECK (rol IN ('admin', 'analyst', 'user', 'readonly')),
    olusturma TIMESTAMPTZ DEFAULT NOW(),
    son_giris TIMESTAMPTZ,
    aktif BOOLEAN DEFAULT TRUE,
    totp_secret VARCHAR(32),
    totp_enabled BOOLEAN DEFAULT FALSE,
    failed_login_count INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,

    -- Audit
    created_by BIGINT REFERENCES kullanicilar(id),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexler
CREATE INDEX idx_kullanicilar_kullanici_adi ON kullanicilar(kullanici_adi);
CREATE INDEX idx_kullanicilar_email ON kullanicilar(email) WHERE email IS NOT NULL;
CREATE INDEX idx_kullanicilar_aktif ON kullanicilar(aktif) WHERE aktif = TRUE;

-- ==================== WIFI NETWORKS ====================
CREATE TABLE wifi_aglar (
    id BIGSERIAL PRIMARY KEY,
    bssid MACADDR NOT NULL,
    ssid VARCHAR(64),
    kanal INTEGER CHECK (kanal BETWEEN 1 AND 196),
    frekans INTEGER,
    sinyal_dbm INTEGER,
    sinyal_yuzde INTEGER CHECK (sinyal_yuzde BETWEEN 0 AND 100),
    sifreleme VARCHAR(50),
    wps BOOLEAN DEFAULT FALSE,
    gizli BOOLEAN DEFAULT FALSE,
    satici VARCHAR(100),
    ilk_gorulme TIMESTAMPTZ DEFAULT NOW(),
    son_gorulme TIMESTAMPTZ DEFAULT NOW(),
    konum GEOGRAPHY(POINT, 4326),  -- PostGIS point
    enlem DECIMAL(10, 8),
    boylam DECIMAL(11, 8),
    istemci_sayisi INTEGER DEFAULT 0,
    veri_hizi VARCHAR(20),
    notlar TEXT,

    -- Sharding key (user_id veya region_id)
    owner_id BIGINT REFERENCES kullanicilar(id),
    region_code VARCHAR(10)
);

-- Indexler
CREATE UNIQUE INDEX idx_wifi_bssid ON wifi_aglar(bssid);
CREATE INDEX idx_wifi_ssid ON wifi_aglar USING gin(ssid gin_trgm_ops);
CREATE INDEX idx_wifi_son_gorulme ON wifi_aglar(son_gorulme DESC);
CREATE INDEX idx_wifi_konum ON wifi_aglar USING GIST(konum);
CREATE INDEX idx_wifi_owner ON wifi_aglar(owner_id);

-- ==================== BLUETOOTH DEVICES ====================
CREATE TABLE bluetooth_cihazlar (
    id BIGSERIAL PRIMARY KEY,
    mac MACADDR NOT NULL,
    ad VARCHAR(100),
    sinif VARCHAR(50),
    ble BOOLEAN DEFAULT FALSE,
    satici VARCHAR(100),
    rssi INTEGER,
    ilk_gorulme TIMESTAMPTZ DEFAULT NOW(),
    son_gorulme TIMESTAMPTZ DEFAULT NOW(),
    konum GEOGRAPHY(POINT, 4326),
    enlem DECIMAL(10, 8),
    boylam DECIMAL(11, 8),
    notlar TEXT,
    owner_id BIGINT REFERENCES kullanicilar(id)
);

CREATE UNIQUE INDEX idx_bt_mac ON bluetooth_cihazlar(mac);
CREATE INDEX idx_bt_son_gorulme ON bluetooth_cihazlar(son_gorulme DESC);

-- ==================== CELL TOWERS ====================
CREATE TABLE baz_istasyonlari (
    id BIGSERIAL PRIMARY KEY,
    mcc INTEGER NOT NULL,          -- Mobile Country Code (286 = Turkey)
    mnc INTEGER NOT NULL,          -- Mobile Network Code
    lac INTEGER NOT NULL,          -- Location Area Code
    cid INTEGER NOT NULL,          -- Cell ID
    sinyal INTEGER,
    teknoloji VARCHAR(20) CHECK (teknoloji IN ('GSM', 'UMTS', 'LTE', '5G')),
    operator VARCHAR(50),
    konum GEOGRAPHY(POINT, 4326),
    enlem DECIMAL(10, 8),
    boylam DECIMAL(11, 8),
    ilk_gorulme TIMESTAMPTZ DEFAULT NOW(),
    son_gorulme TIMESTAMPTZ DEFAULT NOW(),
    notlar TEXT,

    UNIQUE(mcc, mnc, lac, cid)
);

CREATE INDEX idx_baz_konum ON baz_istasyonlari USING GIST(konum);
CREATE INDEX idx_baz_operator ON baz_istasyonlari(operator);

-- ==================== IOT DEVICES ====================
CREATE TABLE iot_cihazlar (
    id BIGSERIAL PRIMARY KEY,
    ip INET,
    mac MACADDR,
    hostname VARCHAR(255),
    port INTEGER CHECK (port BETWEEN 1 AND 65535),
    protokol VARCHAR(20),
    cihaz_tipi VARCHAR(50),
    uretici VARCHAR(100),
    model VARCHAR(100),
    firmware VARCHAR(50),
    zafiyet_sayisi INTEGER DEFAULT 0,
    ilk_gorulme TIMESTAMPTZ DEFAULT NOW(),
    son_gorulme TIMESTAMPTZ DEFAULT NOW(),
    konum GEOGRAPHY(POINT, 4326),
    enlem DECIMAL(10, 8),
    boylam DECIMAL(11, 8),
    notlar TEXT,
    shodan_data JSONB,  -- Shodan API response
    owner_id BIGINT REFERENCES kullanicilar(id)
);

CREATE INDEX idx_iot_ip ON iot_cihazlar(ip);
CREATE INDEX idx_iot_cihaz_tipi ON iot_cihazlar(cihaz_tipi);
CREATE INDEX idx_iot_shodan ON iot_cihazlar USING GIN(shodan_data);

-- ==================== VULNERABILITIES ====================
CREATE TABLE zafiyetler (
    id BIGSERIAL PRIMARY KEY,
    cihaz_id BIGINT,
    cihaz_tipi VARCHAR(50) NOT NULL,  -- 'wifi', 'bluetooth', 'iot', etc.
    cve VARCHAR(20),
    aciklama TEXT,
    ciddiyet VARCHAR(10) CHECK (ciddiyet IN ('critical', 'high', 'medium', 'low', 'info')),
    cvss_puan DECIMAL(3, 1) CHECK (cvss_puan BETWEEN 0 AND 10),
    kesfedilme TIMESTAMPTZ DEFAULT NOW(),
    durum VARCHAR(20) DEFAULT 'open' CHECK (durum IN ('open', 'confirmed', 'mitigated', 'false_positive')),
    notlar TEXT,
    references JSONB,  -- CVE references, PoC links
    owner_id BIGINT REFERENCES kullanicilar(id)
);

CREATE INDEX idx_zafiyet_cve ON zafiyetler(cve) WHERE cve IS NOT NULL;
CREATE INDEX idx_zafiyet_ciddiyet ON zafiyetler(ciddiyet);
CREATE INDEX idx_zafiyet_cihaz ON zafiyetler(cihaz_tipi, cihaz_id);

-- ==================== ALERTS ====================
CREATE TABLE alarmlar (
    id BIGSERIAL PRIMARY KEY,
    tip VARCHAR(50) NOT NULL,
    seviye VARCHAR(20) NOT NULL CHECK (seviye IN ('critical', 'high', 'medium', 'low', 'info')),
    mesaj TEXT NOT NULL,
    kaynak VARCHAR(100),
    tarih TIMESTAMPTZ DEFAULT NOW(),
    okundu BOOLEAN DEFAULT FALSE,
    okunma_tarihi TIMESTAMPTZ,
    okuyan_id BIGINT REFERENCES kullanicilar(id),
    notlar TEXT,
    metadata JSONB,

    -- Partitioning key
    created_date DATE DEFAULT CURRENT_DATE
) PARTITION BY RANGE (created_date);

-- Monthly partitions
CREATE TABLE alarmlar_2025_01 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE alarmlar_2025_02 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
-- ... aylik partition'lar olustur

CREATE INDEX idx_alarm_tarih ON alarmlar(tarih DESC);
CREATE INDEX idx_alarm_okunmadi ON alarmlar(okundu) WHERE okundu = FALSE;

-- ==================== SCAN HISTORY ====================
CREATE TABLE tarama_gecmisi (
    id BIGSERIAL PRIMARY KEY,
    tarama_tipi VARCHAR(50) NOT NULL,
    baslangic TIMESTAMPTZ DEFAULT NOW(),
    bitis TIMESTAMPTZ,
    bulunan_sayisi INTEGER DEFAULT 0,
    durum VARCHAR(20) DEFAULT 'running' CHECK (durum IN ('running', 'completed', 'failed', 'cancelled')),
    hata_mesaji TEXT,
    notlar TEXT,
    parametreler JSONB,
    sonuclar JSONB,
    kullanici_id BIGINT REFERENCES kullanicilar(id)
);

CREATE INDEX idx_tarama_tarih ON tarama_gecmisi(baslangic DESC);
CREATE INDEX idx_tarama_kullanici ON tarama_gecmisi(kullanici_id);

-- ==================== API KEYS (ENCRYPTED) ====================
CREATE TABLE api_anahtarlari (
    id BIGSERIAL PRIMARY KEY,
    servis VARCHAR(50) NOT NULL,
    anahtar_sifreli BYTEA NOT NULL,
    iv BYTEA NOT NULL,
    ekleme TIMESTAMPTZ DEFAULT NOW(),
    guncelleme TIMESTAMPTZ DEFAULT NOW(),
    aktif BOOLEAN DEFAULT TRUE,
    kullanici_id BIGINT REFERENCES kullanicilar(id),

    UNIQUE(servis, kullanici_id)
);

-- ==================== SESSION LOGS ====================
CREATE TABLE oturum_kayitlari (
    id BIGSERIAL PRIMARY KEY,
    kullanici_id BIGINT REFERENCES kullanicilar(id),
    session_id VARCHAR(64) NOT NULL,
    ip INET,
    user_agent TEXT,
    giris TIMESTAMPTZ DEFAULT NOW(),
    cikis TIMESTAMPTZ,
    basarili BOOLEAN DEFAULT TRUE,
    cikis_nedeni VARCHAR(50),  -- 'logout', 'timeout', 'forced', etc.

    -- Partitioning
    created_date DATE DEFAULT CURRENT_DATE
) PARTITION BY RANGE (created_date);

-- ==================== PENTEST TABLES ====================
CREATE TABLE pentest_projeler (
    id BIGSERIAL PRIMARY KEY,
    ad VARCHAR(200) NOT NULL,
    aciklama TEXT,
    hedef JSONB,  -- Multiple targets as JSON
    baslangic TIMESTAMPTZ DEFAULT NOW(),
    bitis TIMESTAMPTZ,
    durum VARCHAR(20) DEFAULT 'planning' CHECK (durum IN ('planning', 'active', 'paused', 'completed', 'archived')),
    olusturan BIGINT REFERENCES kullanicilar(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE pentest_bulgular (
    id BIGSERIAL PRIMARY KEY,
    proje_id BIGINT REFERENCES pentest_projeler(id) ON DELETE CASCADE,
    baslik VARCHAR(300) NOT NULL,
    aciklama TEXT,
    ciddiyet VARCHAR(10) CHECK (ciddiyet IN ('critical', 'high', 'medium', 'low', 'info')),
    kanit JSONB,  -- Screenshots, logs, etc.
    tarih TIMESTAMPTZ DEFAULT NOW(),
    durum VARCHAR(20) DEFAULT 'new' CHECK (durum IN ('new', 'confirmed', 'fixed', 'wontfix', 'duplicate'))
);

CREATE TABLE pentest_gorevler (
    id BIGSERIAL PRIMARY KEY,
    proje_id BIGINT REFERENCES pentest_projeler(id) ON DELETE CASCADE,
    baslik VARCHAR(300) NOT NULL,
    aciklama TEXT,
    atanan BIGINT REFERENCES kullanicilar(id),
    tarih TIMESTAMPTZ DEFAULT NOW(),
    son_tarih TIMESTAMPTZ,
    durum VARCHAR(20) DEFAULT 'todo' CHECK (durum IN ('todo', 'in_progress', 'done', 'blocked'))
);

-- ==================== THREAT INTELLIGENCE ====================
CREATE TABLE threat_indicators (
    id BIGSERIAL PRIMARY KEY,
    indicator_type VARCHAR(30) NOT NULL,  -- 'ip', 'domain', 'hash', 'email', etc.
    value VARCHAR(500) NOT NULL,
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    source VARCHAR(100),
    tags TEXT[],
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB,

    UNIQUE(indicator_type, value)
);

CREATE INDEX idx_threat_type_value ON threat_indicators(indicator_type, value);
CREATE INDEX idx_threat_tags ON threat_indicators USING GIN(tags);

-- ==================== AUDIT LOG ====================
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    user_id BIGINT REFERENCES kullanicilar(id),
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id BIGINT,
    ip_address INET,
    user_agent TEXT,
    old_values JSONB,
    new_values JSONB,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,

    -- Partitioning
    created_date DATE DEFAULT CURRENT_DATE
) PARTITION BY RANGE (created_date);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_action ON audit_log(action);
```

#### 2.2 Migration Script

```python
#!/usr/bin/env python3
# /home/lydian/Desktop/TSUNAMI/scripts/migrate_sqlite_to_postgresql.py
"""
SQLite -> PostgreSQL Migration Script
"""

import sqlite3
import psycopg2
from psycopg2.extras import execute_batch
import os
from datetime import datetime

# Configuration
SQLITE_DB = os.path.expanduser('~/.dalga/dalga_v2.db')
POSTGRES_DSN = os.getenv('POSTGRES_DSN', 'postgresql://tsunami:password@localhost:5432/tsunami')

# Table mapping (sqlite -> postgres)
TABLE_MAPPING = {
    'kullanicilar': {
        'columns': ['id', 'kullanici_adi', 'sifre_hash', 'rol', 'olusturma', 'son_giris', 'aktif'],
        'transforms': {
            'aktif': lambda x: bool(x) if x is not None else True
        }
    },
    'wifi_aglar': {
        'columns': ['id', 'bssid', 'ssid', 'kanal', 'frekans', 'sinyal_dbm', 'sinyal_yuzde',
                   'sifreleme', 'wps', 'gizli', 'satici', 'ilk_gorulme', 'son_gorulme',
                   'enlem', 'boylam', 'istemci_sayisi', 'veri_hizi', 'notlar'],
        'transforms': {
            'wps': lambda x: bool(x),
            'gizli': lambda x: bool(x)
        }
    },
    'bluetooth_cihazlar': {
        'columns': ['id', 'mac', 'ad', 'sinif', 'ble', 'satici', 'rssi',
                   'ilk_gorulme', 'son_gorulme', 'enlem', 'boylam', 'notlar'],
        'transforms': {
            'ble': lambda x: bool(x)
        }
    },
    'baz_istasyonlari': {
        'columns': ['id', 'mcc', 'mnc', 'lac', 'cid', 'sinyal', 'teknoloji',
                   'operator', 'enlem', 'boylam', 'ilk_gorulme', 'son_gorulme', 'notlar']
    },
    'iot_cihazlar': {
        'columns': ['id', 'ip', 'mac', 'hostname', 'port', 'protokol', 'cihaz_tipi',
                   'uretici', 'model', 'firmware', 'zafiyet_sayisi',
                   'ilk_gorulme', 'son_gorulme', 'enlem', 'boylam', 'notlar']
    },
    'zafiyetler': {
        'columns': ['id', 'cihaz_id', 'cihaz_tipi', 'cve', 'aciklama', 'ciddiyet',
                   'puan', 'kesfedilme', 'durum', 'notlar'],
        'pg_columns': ['id', 'cihaz_id', 'cihaz_tipi', 'cve', 'aciklama', 'ciddiyet',
                      'cvss_puan', 'kesfedilme', 'durum', 'notlar']
    },
    'alarmlar': {
        'columns': ['id', 'tip', 'seviye', 'mesaj', 'kaynak', 'tarih', 'okundu', 'notlar'],
        'transforms': {
            'okundu': lambda x: bool(x)
        }
    },
    'tarama_gecmisi': {
        'columns': ['id', 'tarama_tipi', 'baslangic', 'bitis', 'bulunan_sayisi', 'durum', 'notlar']
    },
    'api_anahtarlari': {
        'columns': ['id', 'servis', 'anahtar_sifreli', 'iv', 'ekleme']
    },
    'oturum_kayitlari': {
        'columns': ['id', 'kullanici_id', 'ip', 'giris', 'cikis', 'basarili'],
        'transforms': {
            'basarili': lambda x: bool(x) if x is not None else True
        }
    },
    'pentest_projeler': {
        'columns': ['id', 'ad', 'aciklama', 'hedef', 'baslangic', 'bitis', 'durum', 'olusturan']
    },
    'pentest_bulgular': {
        'columns': ['id', 'proje_id', 'baslik', 'aciklama', 'ciddiyet', 'kanit', 'tarih', 'durum']
    },
    'pentest_gorevler': {
        'columns': ['id', 'proje_id', 'baslik', 'aciklama', 'atanan', 'tarih', 'son_tarih', 'durum']
    }
}


def migrate_table(sqlite_conn, pg_conn, table_name, config):
    """Tek tabloyu migrate et"""
    print(f"Migrating {table_name}...")

    sqlite_cur = sqlite_conn.cursor()
    pg_cur = pg_conn.cursor()

    columns = config['columns']
    pg_columns = config.get('pg_columns', columns)
    transforms = config.get('transforms', {})

    # SQLite'dan veri cek
    sqlite_cur.execute(f"SELECT {','.join(columns)} FROM {table_name}")
    rows = sqlite_cur.fetchall()

    if not rows:
        print(f"  No data in {table_name}")
        return 0

    # Transform uygula
    transformed_rows = []
    for row in rows:
        new_row = list(row)
        for i, col in enumerate(columns):
            if col in transforms:
                new_row[i] = transforms[col](row[i])
        transformed_rows.append(tuple(new_row))

    # PostgreSQL'e yaz
    placeholders = ','.join(['%s'] * len(pg_columns))
    insert_sql = f"""
        INSERT INTO {table_name} ({','.join(pg_columns)})
        VALUES ({placeholders})
        ON CONFLICT DO NOTHING
    """

    execute_batch(pg_cur, insert_sql, transformed_rows, page_size=1000)
    pg_conn.commit()

    # Sequence guncelle
    if 'id' in pg_columns:
        pg_cur.execute(f"""
            SELECT setval(pg_get_serial_sequence('{table_name}', 'id'),
                         COALESCE((SELECT MAX(id) FROM {table_name}), 1))
        """)
        pg_conn.commit()

    print(f"  Migrated {len(transformed_rows)} rows")
    return len(transformed_rows)


def main():
    """Ana migration fonksiyonu"""
    print("=" * 60)
    print("TSUNAMI SQLite -> PostgreSQL Migration")
    print("=" * 60)
    print(f"Source: {SQLITE_DB}")
    print(f"Target: {POSTGRES_DSN.split('@')[1]}")  # Hide password
    print()

    # Baglantilar
    sqlite_conn = sqlite3.connect(SQLITE_DB)
    pg_conn = psycopg2.connect(POSTGRES_DSN)

    total_rows = 0

    try:
        for table_name, config in TABLE_MAPPING.items():
            try:
                count = migrate_table(sqlite_conn, pg_conn, table_name, config)
                total_rows += count
            except Exception as e:
                print(f"  ERROR: {e}")
                pg_conn.rollback()

        print()
        print("=" * 60)
        print(f"Migration complete! Total rows: {total_rows}")
        print("=" * 60)

    finally:
        sqlite_conn.close()
        pg_conn.close()


if __name__ == '__main__':
    main()
```

---

### Faz 3: Uygulama Entegrasyonu (3-5 Gun)

#### 3.1 SQLAlchemy Models

```python
# /home/lydian/Desktop/TSUNAMI/models/base.py

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from config.postgresql_config import get_db_config

Base = declarative_base()

# Sync engine (legacy compatibility)
config = get_db_config()
sync_engine = create_engine(config.sync_connection_string, **config.get_sqlalchemy_engine_options())
SyncSession = sessionmaker(bind=sync_engine)

# Async engine
async_engine = create_async_engine(config.primary_connection_string, **config.get_async_engine_options())
AsyncSessionLocal = sessionmaker(bind=async_engine, class_=AsyncSession, expire_on_commit=False)
```

```python
# /home/lydian/Desktop/TSUNAMI/models/user.py

from sqlalchemy import Column, BigInteger, String, Boolean, DateTime, Integer
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.sql import func
import uuid

from .base import Base

class User(Base):
    __tablename__ = 'kullanicilar'

    id = Column(BigInteger, primary_key=True)
    uuid = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)
    kullanici_adi = Column(String(50), unique=True, nullable=False)
    email = Column(String(255), unique=True)
    sifre_hash = Column(String(255), nullable=False)
    rol = Column(String(20), default='user')
    olusturma = Column(DateTime(timezone=True), server_default=func.now())
    son_giris = Column(DateTime(timezone=True))
    aktif = Column(Boolean, default=True)
    totp_secret = Column(String(32))
    totp_enabled = Column(Boolean, default=False)
    failed_login_count = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))
```

#### 3.2 Flask Entegrasyonu

```python
# /home/lydian/Desktop/TSUNAMI/dalga_web.py (guncelleme)

# Mevcut SQLite import'larini kaldir
# import sqlite3  # KALDIR

# Yeni imports
from config.postgresql_config import init_app as init_postgresql, get_db_manager
from config.redis_cluster_config import init_app as init_redis, get_cache_manager, get_rate_limiter

# Flask app olusturulduktan sonra:
app = Flask(__name__, ...)

# Database initialization
init_postgresql(app)
init_redis(app)

# Session configuration (Redis-backed)
from flask_session import Session
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = get_redis_manager().client
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
Session(app)
```

#### 3.3 Rate Limiting Middleware

```python
# /home/lydian/Desktop/TSUNAMI/middleware/rate_limiting.py

from functools import wraps
from flask import request, jsonify, g
from config.redis_cluster_config import get_rate_limiter

RATE_LIMITS = {
    'default': (100, 60),      # 100 requests per minute
    'auth': (10, 60),          # 10 requests per minute
    'osint': (30, 60),         # 30 requests per minute
    'scan': (10, 60),          # 10 requests per minute
    'export': (5, 60),         # 5 requests per minute
}

def rate_limit(action: str = 'default'):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            limiter = get_rate_limiter()
            limit, window = RATE_LIMITS.get(action, RATE_LIMITS['default'])

            # Identifier: IP or user_id
            identifier = request.remote_addr
            if hasattr(g, 'user') and g.user:
                identifier = f"user:{g.user.id}"

            allowed, remaining, reset = limiter.is_allowed(identifier, action, limit, window)

            # Headers
            response_headers = {
                'X-RateLimit-Limit': str(limit),
                'X-RateLimit-Remaining': str(remaining),
                'X-RateLimit-Reset': str(reset),
            }

            if not allowed:
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': reset
                })
                response.status_code = 429
                for key, value in response_headers.items():
                    response.headers[key] = value
                return response

            # Normal response
            response = f(*args, **kwargs)
            if hasattr(response, 'headers'):
                for key, value in response_headers.items():
                    response.headers[key] = value

            return response
        return wrapped
    return decorator
```

---

### Faz 4: Redis Entegrasyonu (2-3 Gun)

#### 4.1 Session Migration

```python
# Mevcut Flask session yerine Redis-backed session

# requirements.txt'e ekle:
# flask-session[redis]

# app.py
from flask_session import Session
from config.redis_cluster_config import get_redis_manager

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = get_redis_manager().client
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'tsunami:sess:'
Session(app)
```

#### 4.2 Cache Layer Implementasyonu

```python
# Ornek: API response caching

from config.redis_cluster_config import get_cache_manager

cache = get_cache_manager()

@app.route('/api/threats')
@cache.cached('api', ttl=300, key_builder=lambda: f"threats:{request.args.get('page', 1)}")
def get_threats():
    # Expensive database query
    return jsonify(fetch_threats())
```

#### 4.3 Real-time Notifications (Pub/Sub)

```python
# /home/lydian/Desktop/TSUNAMI/services/notifications.py

from config.redis_cluster_config import get_pubsub_manager

pubsub = get_pubsub_manager()

# Yayinla
def notify_threat_detected(threat_data):
    pubsub.publish('threats', {
        'type': 'new_threat',
        'data': threat_data,
        'timestamp': time.time()
    })

# Dinle (SocketIO ile)
@socketio.on('connect')
def handle_connect():
    def on_threat(data):
        emit('threat_alert', data)

    pubsub.subscribe('threats', on_threat)
```

---

### Faz 5: Sharding Stratejisi (Opsiyonel - 10M+ icin)

#### 5.1 Sharding Key Secimi

**Onerilen Sharding Keys:**

| Tablo | Shard Key | Strateji |
|-------|-----------|----------|
| kullanicilar | user_id % 4 | Hash-based |
| wifi_aglar | region_code | Range-based |
| threat_indicators | indicator_type | List-based |
| audit_log | created_date | Time-based (partition) |

#### 5.2 Application-Level Routing

```python
from config.postgresql_config import get_sharding_manager

sharding = get_sharding_manager()

async def get_user(user_id: int):
    shard = sharding.get_shard_for_key(user_id)
    conn_str = sharding.get_shard_connection_string(shard.shard_id)

    async with create_async_engine(conn_str).connect() as conn:
        result = await conn.execute(
            "SELECT * FROM kullanicilar WHERE id = %s",
            (user_id,)
        )
        return result.fetchone()
```

---

### Faz 6: Test ve Dogrulama (3-5 Gun)

#### 6.1 Migration Validation Checklist

```bash
# Row count comparison
psql -c "SELECT 'kullanicilar', COUNT(*) FROM kullanicilar UNION ALL
         SELECT 'wifi_aglar', COUNT(*) FROM wifi_aglar UNION ALL
         SELECT 'bluetooth_cihazlar', COUNT(*) FROM bluetooth_cihazlar;"

# Data integrity check
psql -c "SELECT id, kullanici_adi FROM kullanicilar ORDER BY id LIMIT 10;"
```

#### 6.2 Performance Benchmark

```python
# /home/lydian/Desktop/TSUNAMI/scripts/benchmark.py

import time
import asyncio
from config.postgresql_config import get_db_manager
from config.redis_cluster_config import get_cache_manager

async def benchmark_queries():
    db = get_db_manager()
    await db.initialize()

    # Simple query
    start = time.monotonic()
    async with await db.get_session() as session:
        for _ in range(100):
            await session.execute("SELECT 1")
    print(f"100 simple queries: {(time.monotonic() - start) * 1000:.2f}ms")

    # Complex query with index
    start = time.monotonic()
    async with await db.get_session() as session:
        for _ in range(100):
            await session.execute(
                "SELECT * FROM wifi_aglar WHERE ssid LIKE '%test%' LIMIT 10"
            )
    print(f"100 LIKE queries: {(time.monotonic() - start) * 1000:.2f}ms")

asyncio.run(benchmark_queries())
```

#### 6.3 Load Test

```bash
# locust ile load test
pip install locust

# locustfile.py
from locust import HttpUser, task, between

class TsunamiUser(HttpUser):
    wait_time = between(1, 3)

    @task(3)
    def dashboard(self):
        self.client.get("/")

    @task(2)
    def api_threats(self):
        self.client.get("/api/threats")

    @task(1)
    def api_scan(self):
        self.client.post("/api/scan/wifi")

# Calistir
locust -f locustfile.py --host=http://localhost:8080
```

---

### Faz 7: Production Deployment (1-2 Gun)

#### 7.1 Docker Compose (Production)

```yaml
# docker-compose.prod.yml

version: '3.8'

services:
  # PostgreSQL Primary
  postgres-primary:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: tsunami
      POSTGRES_USER: tsunami
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    command:
      - "postgres"
      - "-c"
      - "max_connections=500"
      - "-c"
      - "shared_buffers=2GB"
      - "-c"
      - "effective_cache_size=6GB"
      - "-c"
      - "wal_level=replica"
      - "-c"
      - "max_wal_senders=3"
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G

  # PostgreSQL Replica
  postgres-replica:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    command:
      - "postgres"
      - "-c"
      - "hot_standby=on"
    depends_on:
      - postgres-primary

  # Redis Cluster (simplified - use Redis Cluster in production)
  redis-1:
    image: redis:7-alpine
    command: redis-server --appendonly yes --maxmemory 2gb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data_1:/data

  redis-2:
    image: redis:7-alpine
    command: redis-server --appendonly yes --maxmemory 2gb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data_2:/data

  redis-3:
    image: redis:7-alpine
    command: redis-server --appendonly yes --maxmemory 2gb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data_3:/data

  # Application
  tsunami-web:
    build: .
    environment:
      TSUNAMI_ENV: production
      POSTGRES_HOST: postgres-primary
      POSTGRES_READ_REPLICAS: postgres-replica:5432
      REDIS_MODE: cluster
      REDIS_CLUSTER_NODES: redis-1:6379,redis-2:6379,redis-3:6379
    depends_on:
      - postgres-primary
      - redis-1
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 4G

  # Celery Worker
  celery-worker:
    build: .
    command: celery -A celery_worker worker -l INFO -c 4
    environment:
      CELERY_BROKER_URL: redis://redis-1:6379/0
    depends_on:
      - redis-1
    deploy:
      replicas: 2

volumes:
  postgres_data:
  redis_data_1:
  redis_data_2:
  redis_data_3:
```

#### 7.2 Environment Variables (.env.production)

```bash
# PostgreSQL
POSTGRES_HOST=postgres-primary.internal
POSTGRES_PORT=5432
POSTGRES_DB=tsunami
POSTGRES_USER=tsunami
POSTGRES_PASSWORD=<secure-password>
POSTGRES_SSL=true
POSTGRES_READ_REPLICAS=postgres-replica-1:5432,postgres-replica-2:5432

# PostgreSQL Pool
POSTGRES_POOL_SIZE=50
POSTGRES_MAX_OVERFLOW=100
POSTGRES_STATEMENT_TIMEOUT=30000

# Redis
REDIS_MODE=cluster
REDIS_CLUSTER_NODES=redis-1:7000,redis-2:7001,redis-3:7002,redis-4:7003,redis-5:7004,redis-6:7005
REDIS_PASSWORD=<secure-password>
REDIS_SSL=true

# Redis TTLs
REDIS_TTL_SESSION=86400
REDIS_TTL_CACHE_SHORT=300
REDIS_TTL_CACHE_MEDIUM=1800
REDIS_TTL_CACHE_LONG=3600

# Sharding (optional)
POSTGRES_SHARDING=false
POSTGRES_SHARD_COUNT=4
```

---

## Rollback Plani

### Kritik Senaryolar

1. **Migration basarisiz olursa:**
   - SQLite backup'tan restore
   - `cp ~/.dalga/dalga_v2.db.backup ~/.dalga/dalga_v2.db`

2. **PostgreSQL performans sorunu:**
   - Environment variable ile SQLite'a geri don
   - `DATABASE_URL=sqlite:///tsunami.db`

3. **Redis cluster cokerse:**
   - Flask default session'a fallback
   - In-memory cache kullan

### Backup Stratejisi

```bash
# Migration oncesi backup
cp ~/.dalga/dalga_v2.db ~/.dalga/dalga_v2.db.backup.$(date +%Y%m%d)

# PostgreSQL backup (gunluk)
pg_dump -Fc tsunami > /backup/tsunami_$(date +%Y%m%d).dump

# Redis backup (AOF)
redis-cli BGREWRITEAOF
```

---

## Monitoring ve Alerting

### Prometheus Metrics

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'postgresql'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: 'tsunami'
    static_configs:
      - targets: ['tsunami-web:9090']
```

### Grafana Dashboards

- PostgreSQL Performance
- Redis Cluster Health
- Application Metrics
- Rate Limiting Stats

### Alert Rules

```yaml
groups:
  - name: tsunami-database
    rules:
      - alert: PostgreSQLConnectionsHigh
        expr: pg_stat_activity_count > 400
        for: 5m
        labels:
          severity: warning

      - alert: RedisMemoryHigh
        expr: redis_memory_used_bytes / redis_memory_max_bytes > 0.9
        for: 5m
        labels:
          severity: critical
```

---

## Zaman Cizelgesi Ozeti

| Faz | Sure | Aciklama |
|-----|------|----------|
| Faz 1 | 1 hafta | Altyapi kurulumu |
| Faz 2 | 2-3 gun | Schema migration |
| Faz 3 | 3-5 gun | Uygulama entegrasyonu |
| Faz 4 | 2-3 gun | Redis entegrasyonu |
| Faz 5 | Opsiyonel | Sharding (10M+ icin) |
| Faz 6 | 3-5 gun | Test ve dogrulama |
| Faz 7 | 1-2 gun | Production deployment |

**Toplam: 2-3 hafta (sharding haric)**

---

## Kaynaklar

- [PostgreSQL 16 Documentation](https://www.postgresql.org/docs/16/)
- [Redis Cluster Tutorial](https://redis.io/docs/management/scaling/)
- [SQLAlchemy Async](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html)
- [Flask-Session with Redis](https://flask-session.readthedocs.io/)

---

*TSUNAMI v5.0 - Siber Komuta ve Istihbarat Platformu*
*Migration Plan v1.0 - 2025-02-04*
