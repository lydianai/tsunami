-- ================================================================================
--     TSUNAMI v5.0 - PostgreSQL Initial Schema
--     Production-Ready Database Schema for 10M+ Users
-- ================================================================================
--
-- Execution:
--   psql -U tsunami -d tsunami -f 001_initial_schema.sql
--
-- ================================================================================

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";        -- Full-text search / fuzzy matching
CREATE EXTENSION IF NOT EXISTS "btree_gin";      -- GIN index support
-- CREATE EXTENSION IF NOT EXISTS "postgis";     -- Geospatial (uncomment if needed)

-- ==================== USERS ====================
CREATE TABLE IF NOT EXISTS kullanicilar (
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

    -- Audit fields
    created_by BIGINT REFERENCES kullanicilar(id),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE kullanicilar IS 'TSUNAMI kullanici hesaplari';
COMMENT ON COLUMN kullanicilar.rol IS 'Kullanici rolu: admin, analyst, user, readonly';
COMMENT ON COLUMN kullanicilar.totp_secret IS '2FA TOTP secret key (encrypted)';

-- Indexes
CREATE INDEX IF NOT EXISTS idx_kullanicilar_kullanici_adi ON kullanicilar(kullanici_adi);
CREATE INDEX IF NOT EXISTS idx_kullanicilar_email ON kullanicilar(email) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_kullanicilar_aktif ON kullanicilar(aktif) WHERE aktif = TRUE;
CREATE INDEX IF NOT EXISTS idx_kullanicilar_rol ON kullanicilar(rol);

-- ==================== WIFI NETWORKS ====================
CREATE TABLE IF NOT EXISTS wifi_aglar (
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
    enlem DECIMAL(10, 8),
    boylam DECIMAL(11, 8),
    istemci_sayisi INTEGER DEFAULT 0,
    veri_hizi VARCHAR(20),
    notlar TEXT,

    -- Sharding/ownership
    owner_id BIGINT REFERENCES kullanicilar(id),
    region_code VARCHAR(10)
);

COMMENT ON TABLE wifi_aglar IS 'Tespit edilen WiFi aglari';
COMMENT ON COLUMN wifi_aglar.bssid IS 'Access Point MAC adresi';
COMMENT ON COLUMN wifi_aglar.sifreleme IS 'WPA2, WPA3, WEP, Open, etc.';

-- Indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_wifi_bssid ON wifi_aglar(bssid);
CREATE INDEX IF NOT EXISTS idx_wifi_ssid ON wifi_aglar USING gin(ssid gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_wifi_son_gorulme ON wifi_aglar(son_gorulme DESC);
CREATE INDEX IF NOT EXISTS idx_wifi_konum ON wifi_aglar(enlem, boylam) WHERE enlem IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_wifi_owner ON wifi_aglar(owner_id);
CREATE INDEX IF NOT EXISTS idx_wifi_region ON wifi_aglar(region_code) WHERE region_code IS NOT NULL;

-- ==================== BLUETOOTH DEVICES ====================
CREATE TABLE IF NOT EXISTS bluetooth_cihazlar (
    id BIGSERIAL PRIMARY KEY,
    mac MACADDR NOT NULL,
    ad VARCHAR(100),
    sinif VARCHAR(50),
    ble BOOLEAN DEFAULT FALSE,
    satici VARCHAR(100),
    rssi INTEGER,
    ilk_gorulme TIMESTAMPTZ DEFAULT NOW(),
    son_gorulme TIMESTAMPTZ DEFAULT NOW(),
    enlem DECIMAL(10, 8),
    boylam DECIMAL(11, 8),
    notlar TEXT,
    owner_id BIGINT REFERENCES kullanicilar(id)
);

COMMENT ON TABLE bluetooth_cihazlar IS 'Tespit edilen Bluetooth cihazlari';
COMMENT ON COLUMN bluetooth_cihazlar.ble IS 'Bluetooth Low Energy destegi';

CREATE UNIQUE INDEX IF NOT EXISTS idx_bt_mac ON bluetooth_cihazlar(mac);
CREATE INDEX IF NOT EXISTS idx_bt_son_gorulme ON bluetooth_cihazlar(son_gorulme DESC);
CREATE INDEX IF NOT EXISTS idx_bt_ad ON bluetooth_cihazlar USING gin(ad gin_trgm_ops) WHERE ad IS NOT NULL;

-- ==================== CELL TOWERS ====================
CREATE TABLE IF NOT EXISTS baz_istasyonlari (
    id BIGSERIAL PRIMARY KEY,
    mcc INTEGER NOT NULL,              -- Mobile Country Code (286 = Turkey)
    mnc INTEGER NOT NULL,              -- Mobile Network Code
    lac INTEGER NOT NULL,              -- Location Area Code
    cid INTEGER NOT NULL,              -- Cell ID
    sinyal INTEGER,
    teknoloji VARCHAR(20) CHECK (teknoloji IN ('GSM', 'UMTS', 'LTE', '5G', 'NR')),
    operator VARCHAR(50),
    enlem DECIMAL(10, 8),
    boylam DECIMAL(11, 8),
    ilk_gorulme TIMESTAMPTZ DEFAULT NOW(),
    son_gorulme TIMESTAMPTZ DEFAULT NOW(),
    notlar TEXT,

    UNIQUE(mcc, mnc, lac, cid)
);

COMMENT ON TABLE baz_istasyonlari IS 'Mobil baz istasyonu bilgileri';
COMMENT ON COLUMN baz_istasyonlari.mcc IS 'Mobile Country Code (286 = Turkiye)';
COMMENT ON COLUMN baz_istasyonlari.mnc IS 'Mobile Network Code (01=Turkcell, 02=Vodafone, 03=TurkTelekom)';

CREATE INDEX IF NOT EXISTS idx_baz_konum ON baz_istasyonlari(enlem, boylam) WHERE enlem IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_baz_operator ON baz_istasyonlari(operator);
CREATE INDEX IF NOT EXISTS idx_baz_mcc_mnc ON baz_istasyonlari(mcc, mnc);

-- ==================== IOT DEVICES ====================
CREATE TABLE IF NOT EXISTS iot_cihazlar (
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
    enlem DECIMAL(10, 8),
    boylam DECIMAL(11, 8),
    notlar TEXT,
    shodan_data JSONB,                 -- Shodan API response
    censys_data JSONB,                 -- Censys data
    owner_id BIGINT REFERENCES kullanicilar(id)
);

COMMENT ON TABLE iot_cihazlar IS 'IoT cihazlari (Shodan, Censys, manuel tarama)';

CREATE INDEX IF NOT EXISTS idx_iot_ip ON iot_cihazlar(ip);
CREATE INDEX IF NOT EXISTS idx_iot_cihaz_tipi ON iot_cihazlar(cihaz_tipi);
CREATE INDEX IF NOT EXISTS idx_iot_shodan ON iot_cihazlar USING GIN(shodan_data);
CREATE INDEX IF NOT EXISTS idx_iot_zafiyet ON iot_cihazlar(zafiyet_sayisi DESC) WHERE zafiyet_sayisi > 0;

-- ==================== VULNERABILITIES ====================
CREATE TABLE IF NOT EXISTS zafiyetler (
    id BIGSERIAL PRIMARY KEY,
    cihaz_id BIGINT,
    cihaz_tipi VARCHAR(50) NOT NULL,   -- 'wifi', 'bluetooth', 'iot', 'web', etc.
    cve VARCHAR(20),
    aciklama TEXT,
    ciddiyet VARCHAR(10) CHECK (ciddiyet IN ('critical', 'high', 'medium', 'low', 'info')),
    cvss_puan DECIMAL(3, 1) CHECK (cvss_puan BETWEEN 0 AND 10),
    kesfedilme TIMESTAMPTZ DEFAULT NOW(),
    durum VARCHAR(20) DEFAULT 'open' CHECK (durum IN ('open', 'confirmed', 'mitigated', 'false_positive', 'accepted')),
    notlar TEXT,
    references_data JSONB,             -- CVE references, PoC links
    remediation TEXT,                  -- Fix recommendations
    owner_id BIGINT REFERENCES kullanicilar(id)
);

COMMENT ON TABLE zafiyetler IS 'Tespit edilen guvenlik aciklari';

CREATE INDEX IF NOT EXISTS idx_zafiyet_cve ON zafiyetler(cve) WHERE cve IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_zafiyet_ciddiyet ON zafiyetler(ciddiyet);
CREATE INDEX IF NOT EXISTS idx_zafiyet_cihaz ON zafiyetler(cihaz_tipi, cihaz_id);
CREATE INDEX IF NOT EXISTS idx_zafiyet_durum ON zafiyetler(durum) WHERE durum = 'open';

-- ==================== ALERTS (PARTITIONED) ====================
CREATE TABLE IF NOT EXISTS alarmlar (
    id BIGSERIAL,
    tip VARCHAR(50) NOT NULL,
    seviye VARCHAR(20) NOT NULL CHECK (seviye IN ('critical', 'high', 'medium', 'low', 'info')),
    mesaj TEXT NOT NULL,
    kaynak VARCHAR(100),
    tarih TIMESTAMPTZ DEFAULT NOW(),
    okundu BOOLEAN DEFAULT FALSE,
    okunma_tarihi TIMESTAMPTZ,
    okuyan_id BIGINT,
    notlar TEXT,
    metadata JSONB,

    -- Partitioning key
    created_date DATE DEFAULT CURRENT_DATE,
    PRIMARY KEY (id, created_date)
) PARTITION BY RANGE (created_date);

COMMENT ON TABLE alarmlar IS 'Sistem alarmlari ve bildirimler';

-- Create partitions for 2025
CREATE TABLE IF NOT EXISTS alarmlar_2025_01 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE IF NOT EXISTS alarmlar_2025_02 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE IF NOT EXISTS alarmlar_2025_03 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE IF NOT EXISTS alarmlar_2025_04 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');
CREATE TABLE IF NOT EXISTS alarmlar_2025_05 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-05-01') TO ('2025-06-01');
CREATE TABLE IF NOT EXISTS alarmlar_2025_06 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');
CREATE TABLE IF NOT EXISTS alarmlar_2025_07 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-07-01') TO ('2025-08-01');
CREATE TABLE IF NOT EXISTS alarmlar_2025_08 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-08-01') TO ('2025-09-01');
CREATE TABLE IF NOT EXISTS alarmlar_2025_09 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');
CREATE TABLE IF NOT EXISTS alarmlar_2025_10 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');
CREATE TABLE IF NOT EXISTS alarmlar_2025_11 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE TABLE IF NOT EXISTS alarmlar_2025_12 PARTITION OF alarmlar
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

-- Create partitions for 2026
CREATE TABLE IF NOT EXISTS alarmlar_2026_01 PARTITION OF alarmlar
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE IF NOT EXISTS alarmlar_2026_02 PARTITION OF alarmlar
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE IF NOT EXISTS alarmlar_2026_03 PARTITION OF alarmlar
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE INDEX IF NOT EXISTS idx_alarm_tarih ON alarmlar(tarih DESC);
CREATE INDEX IF NOT EXISTS idx_alarm_okunmadi ON alarmlar(okundu) WHERE okundu = FALSE;
CREATE INDEX IF NOT EXISTS idx_alarm_seviye ON alarmlar(seviye);

-- ==================== SCAN HISTORY ====================
CREATE TABLE IF NOT EXISTS tarama_gecmisi (
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

COMMENT ON TABLE tarama_gecmisi IS 'Tarama islem gecmisi';

CREATE INDEX IF NOT EXISTS idx_tarama_tarih ON tarama_gecmisi(baslangic DESC);
CREATE INDEX IF NOT EXISTS idx_tarama_kullanici ON tarama_gecmisi(kullanici_id);
CREATE INDEX IF NOT EXISTS idx_tarama_durum ON tarama_gecmisi(durum) WHERE durum = 'running';

-- ==================== API KEYS (ENCRYPTED) ====================
CREATE TABLE IF NOT EXISTS api_anahtarlari (
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

COMMENT ON TABLE api_anahtarlari IS 'Sifreli API anahtarlari (AES-256-GCM)';

-- ==================== SESSION LOGS (PARTITIONED) ====================
CREATE TABLE IF NOT EXISTS oturum_kayitlari (
    id BIGSERIAL,
    kullanici_id BIGINT,
    session_id VARCHAR(64) NOT NULL,
    ip INET,
    user_agent TEXT,
    giris TIMESTAMPTZ DEFAULT NOW(),
    cikis TIMESTAMPTZ,
    basarili BOOLEAN DEFAULT TRUE,
    cikis_nedeni VARCHAR(50),

    -- Partitioning
    created_date DATE DEFAULT CURRENT_DATE,
    PRIMARY KEY (id, created_date)
) PARTITION BY RANGE (created_date);

COMMENT ON TABLE oturum_kayitlari IS 'Kullanici oturum kayitlari';

-- Session partitions (son 3 ay yeterli)
CREATE TABLE IF NOT EXISTS oturum_kayitlari_2025_01 PARTITION OF oturum_kayitlari
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE IF NOT EXISTS oturum_kayitlari_2025_02 PARTITION OF oturum_kayitlari
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE IF NOT EXISTS oturum_kayitlari_2026_01 PARTITION OF oturum_kayitlari
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE IF NOT EXISTS oturum_kayitlari_2026_02 PARTITION OF oturum_kayitlari
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

-- ==================== PENTEST TABLES ====================
CREATE TABLE IF NOT EXISTS pentest_projeler (
    id BIGSERIAL PRIMARY KEY,
    ad VARCHAR(200) NOT NULL,
    aciklama TEXT,
    hedef JSONB,                       -- Multiple targets as JSON
    baslangic TIMESTAMPTZ DEFAULT NOW(),
    bitis TIMESTAMPTZ,
    durum VARCHAR(20) DEFAULT 'planning' CHECK (durum IN ('planning', 'active', 'paused', 'completed', 'archived')),
    olusturan BIGINT REFERENCES kullanicilar(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE pentest_projeler IS 'Penetrasyon testi projeleri';

CREATE INDEX IF NOT EXISTS idx_pentest_proje_durum ON pentest_projeler(durum);

CREATE TABLE IF NOT EXISTS pentest_bulgular (
    id BIGSERIAL PRIMARY KEY,
    proje_id BIGINT REFERENCES pentest_projeler(id) ON DELETE CASCADE,
    baslik VARCHAR(300) NOT NULL,
    aciklama TEXT,
    ciddiyet VARCHAR(10) CHECK (ciddiyet IN ('critical', 'high', 'medium', 'low', 'info')),
    kanit JSONB,                       -- Screenshots, logs, requests/responses
    tarih TIMESTAMPTZ DEFAULT NOW(),
    durum VARCHAR(20) DEFAULT 'new' CHECK (durum IN ('new', 'confirmed', 'fixed', 'wontfix', 'duplicate'))
);

COMMENT ON TABLE pentest_bulgular IS 'Pentest bulgu raporlari';

CREATE INDEX IF NOT EXISTS idx_pentest_bulgu_proje ON pentest_bulgular(proje_id);
CREATE INDEX IF NOT EXISTS idx_pentest_bulgu_ciddiyet ON pentest_bulgular(ciddiyet);

CREATE TABLE IF NOT EXISTS pentest_gorevler (
    id BIGSERIAL PRIMARY KEY,
    proje_id BIGINT REFERENCES pentest_projeler(id) ON DELETE CASCADE,
    baslik VARCHAR(300) NOT NULL,
    aciklama TEXT,
    atanan BIGINT REFERENCES kullanicilar(id),
    tarih TIMESTAMPTZ DEFAULT NOW(),
    son_tarih TIMESTAMPTZ,
    durum VARCHAR(20) DEFAULT 'todo' CHECK (durum IN ('todo', 'in_progress', 'done', 'blocked'))
);

COMMENT ON TABLE pentest_gorevler IS 'Pentest gorev takibi';

CREATE INDEX IF NOT EXISTS idx_pentest_gorev_proje ON pentest_gorevler(proje_id);
CREATE INDEX IF NOT EXISTS idx_pentest_gorev_atanan ON pentest_gorevler(atanan);

-- ==================== THREAT INTELLIGENCE ====================
CREATE TABLE IF NOT EXISTS threat_indicators (
    id BIGSERIAL PRIMARY KEY,
    indicator_type VARCHAR(30) NOT NULL,  -- 'ip', 'domain', 'hash', 'email', 'url', etc.
    value VARCHAR(500) NOT NULL,
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    source VARCHAR(100),
    tags TEXT[],
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB,

    UNIQUE(indicator_type, value)
);

COMMENT ON TABLE threat_indicators IS 'Tehdit istihbarat indikatotrleri (IOC)';

CREATE INDEX IF NOT EXISTS idx_threat_type_value ON threat_indicators(indicator_type, value);
CREATE INDEX IF NOT EXISTS idx_threat_tags ON threat_indicators USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_threat_source ON threat_indicators(source);

-- ==================== AUDIT LOG (PARTITIONED) ====================
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    user_id BIGINT,
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
    created_date DATE DEFAULT CURRENT_DATE,
    PRIMARY KEY (id, created_date)
) PARTITION BY RANGE (created_date);

COMMENT ON TABLE audit_log IS 'Sistem denetim kayitlari';

-- Audit partitions
CREATE TABLE IF NOT EXISTS audit_log_2025_01 PARTITION OF audit_log
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE IF NOT EXISTS audit_log_2025_02 PARTITION OF audit_log
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE IF NOT EXISTS audit_log_2026_01 PARTITION OF audit_log
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE IF NOT EXISTS audit_log_2026_02 PARTITION OF audit_log
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

-- ==================== FUNCTIONS ====================

-- Function: Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for kullanicilar
DROP TRIGGER IF EXISTS update_kullanicilar_updated_at ON kullanicilar;
CREATE TRIGGER update_kullanicilar_updated_at
    BEFORE UPDATE ON kullanicilar
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger for pentest_projeler
DROP TRIGGER IF EXISTS update_pentest_projeler_updated_at ON pentest_projeler;
CREATE TRIGGER update_pentest_projeler_updated_at
    BEFORE UPDATE ON pentest_projeler
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function: Create monthly partition automatically
CREATE OR REPLACE FUNCTION create_monthly_partition(
    table_name TEXT,
    partition_date DATE
)
RETURNS void AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    partition_name := table_name || '_' || to_char(partition_date, 'YYYY_MM');
    start_date := date_trunc('month', partition_date);
    end_date := start_date + INTERVAL '1 month';

    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
        partition_name,
        table_name,
        start_date,
        end_date
    );
END;
$$ LANGUAGE plpgsql;

-- ==================== INITIAL DATA ====================

-- Default admin user (password: change_me_immediately!)
-- Password hash: bcrypt('change_me_immediately!')
INSERT INTO kullanicilar (kullanici_adi, sifre_hash, rol, email)
VALUES (
    'admin',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.5LHNK5MkGJ5kWK',  -- change_me_immediately!
    'admin',
    'admin@tsunami.local'
) ON CONFLICT (kullanici_adi) DO NOTHING;

-- ==================== STATISTICS ====================

-- Update statistics for query planner
ANALYZE kullanicilar;
ANALYZE wifi_aglar;
ANALYZE bluetooth_cihazlar;
ANALYZE baz_istasyonlari;
ANALYZE iot_cihazlar;
ANALYZE zafiyetler;
ANALYZE threat_indicators;

-- ================================================================================
-- Migration complete!
--
-- Next steps:
-- 1. Run migrate_sqlite_to_postgresql.py to migrate existing data
-- 2. Update application DATABASE_URL to PostgreSQL
-- 3. Test all CRUD operations
-- 4. Enable SSL/TLS for production
-- ================================================================================
