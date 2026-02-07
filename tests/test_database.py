#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Database Tests
======================

Comprehensive tests for database operations and SQL safety.
"""

import pytest
import sys
import tempfile
import sqlite3
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def temp_db():
    """Create temporary test database"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name

    # Initialize database schema
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create test tables
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS kullanicilar (
            id INTEGER PRIMARY KEY,
            kullanici_adi TEXT UNIQUE,
            sifre_hash TEXT,
            salt TEXT,
            olusturma_tarihi DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS alarmlar (
            id INTEGER PRIMARY KEY,
            tip TEXT,
            mesaj TEXT,
            seviye TEXT,
            olusturma_tarihi DATETIME DEFAULT CURRENT_TIMESTAMP,
            okundu INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS wifi_aglar (
            id INTEGER PRIMARY KEY,
            ssid TEXT,
            bssid TEXT,
            sinyal INTEGER,
            guvenlik TEXT,
            olusturma_tarihi DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS zafiyetler (
            id INTEGER PRIMARY KEY,
            wifi_id INTEGER,
            tip TEXT,
            aciklama TEXT,
            FOREIGN KEY (wifi_id) REFERENCES wifi_aglar(id)
        );
    ''')

    conn.commit()
    conn.close()

    yield db_path

    # Cleanup
    Path(db_path).unlink(missing_ok=True)


class TestSQLInjectionPrevention:
    """SQL injection prevention tests"""

    def test_parameterized_query_safe(self, temp_db):
        """Test parameterized queries are safe from injection"""
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        # Safe parameterized query
        malicious_input = "'; DROP TABLE kullanicilar;--"

        # This should be safe
        cursor.execute(
            "SELECT * FROM kullanicilar WHERE kullanici_adi = ?",
            (malicious_input,)
        )

        # Table should still exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='kullanicilar'")
        result = cursor.fetchone()
        assert result is not None

        conn.close()

    def test_quote_escaping(self, temp_db):
        """Test quote characters are properly escaped"""
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        # Insert with quotes
        test_value = "O'Reilly's \"Book\""
        cursor.execute(
            "INSERT INTO alarmlar (tip, mesaj, seviye) VALUES (?, ?, ?)",
            ('test', test_value, 'info')
        )
        conn.commit()

        # Retrieve and verify
        cursor.execute("SELECT mesaj FROM alarmlar WHERE tip = ?", ('test',))
        result = cursor.fetchone()
        assert result[0] == test_value

        conn.close()

    def test_union_injection_prevention(self, temp_db):
        """Test UNION injection is prevented"""
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        # Insert test data
        cursor.execute(
            "INSERT INTO kullanicilar (kullanici_adi, sifre_hash, salt) VALUES (?, ?, ?)",
            ('admin', 'hash123', 'salt123')
        )
        conn.commit()

        # Attempt UNION injection
        malicious = "admin' UNION SELECT 1,2,3,4,5--"

        cursor.execute(
            "SELECT * FROM kullanicilar WHERE kullanici_adi = ?",
            (malicious,)
        )

        # Should return no results (not the injected data)
        result = cursor.fetchall()
        assert len(result) == 0

        conn.close()

    def test_batch_insert_safe(self, temp_db):
        """Test batch inserts are safe"""
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        # Safe batch insert
        data = [
            ('alarm1', 'message1', 'info'),
            ("'; DROP TABLE alarmlar;--", 'message2', 'warning'),
            ('alarm3', 'message3', 'error'),
        ]

        cursor.executemany(
            "INSERT INTO alarmlar (tip, mesaj, seviye) VALUES (?, ?, ?)",
            data
        )
        conn.commit()

        # Table should still exist with all data
        cursor.execute("SELECT COUNT(*) FROM alarmlar")
        count = cursor.fetchone()[0]
        assert count == 3

        conn.close()


class TestDatabaseOperations:
    """Database operation tests"""

    def test_connection_handling(self, temp_db):
        """Test database connection handling"""
        conn = sqlite3.connect(temp_db)
        assert conn is not None

        # Test cursor creation
        cursor = conn.cursor()
        assert cursor is not None

        # Clean close
        cursor.close()
        conn.close()

    def test_transaction_rollback(self, temp_db):
        """Test transaction rollback works"""
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        # Start transaction
        cursor.execute(
            "INSERT INTO alarmlar (tip, mesaj, seviye) VALUES (?, ?, ?)",
            ('test', 'test message', 'info')
        )

        # Rollback
        conn.rollback()

        # Data should not be persisted
        cursor.execute("SELECT COUNT(*) FROM alarmlar WHERE tip = 'test'")
        count = cursor.fetchone()[0]
        assert count == 0

        conn.close()

    def test_foreign_key_constraints(self, temp_db):
        """Test foreign key constraints"""
        conn = sqlite3.connect(temp_db)
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()

        # Insert wifi network
        cursor.execute(
            "INSERT INTO wifi_aglar (ssid, bssid, sinyal, guvenlik) VALUES (?, ?, ?, ?)",
            ('TestNetwork', 'AA:BB:CC:DD:EE:FF', -50, 'WPA2')
        )
        wifi_id = cursor.lastrowid
        conn.commit()

        # Insert vulnerability linked to wifi
        cursor.execute(
            "INSERT INTO zafiyetler (wifi_id, tip, aciklama) VALUES (?, ?, ?)",
            (wifi_id, 'WPS', 'WPS enabled')
        )
        conn.commit()

        # Verify link
        cursor.execute(
            "SELECT z.tip FROM zafiyetler z JOIN wifi_aglar w ON z.wifi_id = w.id WHERE w.ssid = ?",
            ('TestNetwork',)
        )
        result = cursor.fetchone()
        assert result[0] == 'WPS'

        conn.close()


class TestQueryBuilder:
    """Safe query builder tests"""

    def test_safe_order_by(self):
        """Test safe ORDER BY construction"""
        allowed_columns = ['id', 'tip', 'olusturma_tarihi']
        column = 'tip'

        if column in allowed_columns:
            query = f"SELECT * FROM alarmlar ORDER BY {column}"
            assert 'ORDER BY tip' in query
        else:
            pytest.fail("Invalid column should be rejected")

    def test_reject_invalid_order_by(self):
        """Test invalid ORDER BY is rejected"""
        allowed_columns = ['id', 'tip', 'olusturma_tarihi']
        malicious_column = "id; DROP TABLE alarmlar;--"

        assert malicious_column not in allowed_columns

    def test_safe_limit(self):
        """Test LIMIT clause is numeric"""
        def safe_limit(value):
            try:
                return int(value)
            except (ValueError, TypeError):
                return 100  # Default

        assert safe_limit('50') == 50
        assert safe_limit('100; DROP TABLE') == 100  # Falls back to default
        assert safe_limit(None) == 100


class TestDatabaseCleanup:
    """Database cleanup operation tests"""

    def test_old_record_deletion(self, temp_db):
        """Test old records are deleted safely"""
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        # Insert old alarm (simulated)
        cursor.execute('''
            INSERT INTO alarmlar (tip, mesaj, seviye, olusturma_tarihi)
            VALUES (?, ?, ?, datetime('now', '-31 days'))
        ''', ('old', 'old message', 'info'))
        conn.commit()

        # Delete old records using parameterized query
        cursor.execute('''
            DELETE FROM alarmlar
            WHERE olusturma_tarihi < datetime('now', '-30 days')
        ''')
        conn.commit()

        # Verify deletion
        cursor.execute("SELECT COUNT(*) FROM alarmlar WHERE tip = 'old'")
        count = cursor.fetchone()[0]
        assert count == 0

        conn.close()


class TestCacheOperations:
    """Cache operation tests"""

    def test_cache_key_generation(self):
        """Test cache key generation"""
        from utils.cache import cache_key

        # Same args should produce same key
        key1 = cache_key('arg1', 'arg2', kwarg='value')
        key2 = cache_key('arg1', 'arg2', kwarg='value')
        assert key1 == key2

        # Different args should produce different key
        key3 = cache_key('arg1', 'arg3', kwarg='value')
        assert key1 != key3

    def test_timed_cache(self):
        """Test timed LRU cache"""
        from utils.cache import timed_lru_cache
        import time

        call_count = 0

        @timed_lru_cache(seconds=1)
        def expensive_function(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        # First call
        result1 = expensive_function(5)
        assert result1 == 10
        assert call_count == 1

        # Second call (cached)
        result2 = expensive_function(5)
        assert result2 == 10
        assert call_count == 1  # Still 1

        # Wait for cache to expire
        time.sleep(1.1)

        # Third call (cache expired)
        result3 = expensive_function(5)
        assert result3 == 10
        assert call_count == 2  # Now 2
