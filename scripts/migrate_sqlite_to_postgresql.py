#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 - SQLite to PostgreSQL Migration Script
    Production-Ready Data Migration Tool
================================================================================

    Usage:
        python migrate_sqlite_to_postgresql.py [options]

    Options:
        --sqlite-db PATH    SQLite database path (default: ~/.dalga/dalga_v2.db)
        --postgres-dsn DSN  PostgreSQL connection string
        --dry-run           Show what would be migrated without executing
        --batch-size N      Batch size for inserts (default: 1000)
        --skip-tables       Comma-separated list of tables to skip
        --only-tables       Comma-separated list of tables to migrate only

    Environment Variables:
        SQLITE_DB_PATH      Alternative to --sqlite-db
        POSTGRES_DSN        Alternative to --postgres-dsn

================================================================================
"""

import os
import sys
import sqlite3
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Tuple

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('migration')

# Try to import psycopg2
try:
    import psycopg2
    from psycopg2.extras import execute_batch, RealDictCursor
    from psycopg2 import sql
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    logger.warning("psycopg2 not installed. Install with: pip install psycopg2-binary")


# ==================== CONFIGURATION ====================

DEFAULT_SQLITE_PATH = Path.home() / ".dalga" / "dalga_v2.db"
DEFAULT_POSTGRES_DSN = "postgresql://tsunami:password@localhost:5432/tsunami"

# Table mapping configuration
# Format: {
#     'table_name': {
#         'columns': [...],           # SQLite column names
#         'pg_columns': [...],        # PostgreSQL column names (if different)
#         'transforms': {...},        # Column transformation functions
#         'pre_migrate': func,        # Function to run before migration
#         'post_migrate': func,       # Function to run after migration
#         'skip_if_empty': bool,      # Skip if no data
#     }
# }

TABLE_CONFIG: Dict[str, Dict[str, Any]] = {
    'kullanicilar': {
        'columns': ['id', 'kullanici_adi', 'sifre_hash', 'rol', 'olusturma', 'son_giris', 'aktif'],
        'transforms': {
            'aktif': lambda x: bool(x) if x is not None else True,
            'rol': lambda x: x if x in ('admin', 'analyst', 'user', 'readonly') else 'user',
        },
        'skip_if_empty': False,
    },

    'wifi_aglar': {
        'columns': [
            'id', 'bssid', 'ssid', 'kanal', 'frekans', 'sinyal_dbm', 'sinyal_yuzde',
            'sifreleme', 'wps', 'gizli', 'satici', 'ilk_gorulme', 'son_gorulme',
            'enlem', 'boylam', 'istemci_sayisi', 'veri_hizi', 'notlar'
        ],
        'transforms': {
            'wps': lambda x: bool(x) if x is not None else False,
            'gizli': lambda x: bool(x) if x is not None else False,
        },
    },

    'bluetooth_cihazlar': {
        'columns': [
            'id', 'mac', 'ad', 'sinif', 'ble', 'satici', 'rssi',
            'ilk_gorulme', 'son_gorulme', 'enlem', 'boylam', 'notlar'
        ],
        'transforms': {
            'ble': lambda x: bool(x) if x is not None else False,
        },
    },

    'baz_istasyonlari': {
        'columns': [
            'id', 'mcc', 'mnc', 'lac', 'cid', 'sinyal', 'teknoloji',
            'operator', 'enlem', 'boylam', 'ilk_gorulme', 'son_gorulme', 'notlar'
        ],
    },

    'iot_cihazlar': {
        'columns': [
            'id', 'ip', 'mac', 'hostname', 'port', 'protokol', 'cihaz_tipi',
            'uretici', 'model', 'firmware', 'zafiyet_sayisi',
            'ilk_gorulme', 'son_gorulme', 'enlem', 'boylam', 'notlar'
        ],
    },

    'zafiyetler': {
        'columns': [
            'id', 'cihaz_id', 'cihaz_tipi', 'cve', 'aciklama', 'ciddiyet',
            'puan', 'kesfedilme', 'durum', 'notlar'
        ],
        'pg_columns': [
            'id', 'cihaz_id', 'cihaz_tipi', 'cve', 'aciklama', 'ciddiyet',
            'cvss_puan', 'kesfedilme', 'durum', 'notlar'
        ],
        'transforms': {
            'ciddiyet': lambda x: x if x in ('critical', 'high', 'medium', 'low', 'info') else 'info',
            'durum': lambda x: x if x in ('open', 'confirmed', 'mitigated', 'false_positive', 'accepted') else 'open',
        },
    },

    'alarmlar': {
        'columns': ['id', 'tip', 'seviye', 'mesaj', 'kaynak', 'tarih', 'okundu', 'notlar'],
        'pg_columns': ['id', 'tip', 'seviye', 'mesaj', 'kaynak', 'tarih', 'okundu', 'notlar', 'created_date'],
        'transforms': {
            'okundu': lambda x: bool(x) if x is not None else False,
            'seviye': lambda x: x if x in ('critical', 'high', 'medium', 'low', 'info') else 'info',
        },
        'row_transform': lambda row: row + (row[5].split('T')[0] if row[5] else datetime.now().strftime('%Y-%m-%d'),),
    },

    'tarama_gecmisi': {
        'columns': [
            'id', 'tarama_tipi', 'baslangic', 'bitis', 'bulunan_sayisi', 'durum', 'notlar'
        ],
        'transforms': {
            'durum': lambda x: x if x in ('running', 'completed', 'failed', 'cancelled') else 'completed',
        },
    },

    'api_anahtarlari': {
        'columns': ['id', 'servis', 'anahtar_sifreli', 'iv', 'ekleme'],
        'transforms': {
            'anahtar_sifreli': lambda x: x.encode() if isinstance(x, str) else x,
            'iv': lambda x: x.encode() if isinstance(x, str) else x,
        },
    },

    'oturum_kayitlari': {
        'columns': ['id', 'kullanici_id', 'ip', 'giris', 'cikis', 'basarili'],
        'pg_columns': ['id', 'kullanici_id', 'ip', 'giris', 'cikis', 'basarili', 'created_date'],
        'transforms': {
            'basarili': lambda x: bool(x) if x is not None else True,
        },
        'row_transform': lambda row: row + (row[3].split('T')[0] if row[3] else datetime.now().strftime('%Y-%m-%d'),),
    },

    'pentest_projeler': {
        'columns': ['id', 'ad', 'aciklama', 'hedef', 'baslangic', 'bitis', 'durum', 'olusturan'],
        'transforms': {
            'durum': lambda x: x if x in ('planning', 'active', 'paused', 'completed', 'archived') else 'planning',
        },
    },

    'pentest_bulgular': {
        'columns': ['id', 'proje_id', 'baslik', 'aciklama', 'ciddiyet', 'kanit', 'tarih', 'durum'],
        'transforms': {
            'ciddiyet': lambda x: x if x in ('critical', 'high', 'medium', 'low', 'info') else 'info',
            'durum': lambda x: x if x in ('new', 'confirmed', 'fixed', 'wontfix', 'duplicate') else 'new',
        },
    },

    'pentest_gorevler': {
        'columns': ['id', 'proje_id', 'baslik', 'aciklama', 'atanan', 'tarih', 'son_tarih', 'durum'],
        'transforms': {
            'durum': lambda x: x if x in ('todo', 'in_progress', 'done', 'blocked') else 'todo',
        },
    },
}


# ==================== MIGRATION CLASS ====================

class MigrationEngine:
    """SQLite to PostgreSQL Migration Engine"""

    def __init__(
        self,
        sqlite_path: str,
        postgres_dsn: str,
        batch_size: int = 1000,
        dry_run: bool = False
    ):
        self.sqlite_path = Path(sqlite_path)
        self.postgres_dsn = postgres_dsn
        self.batch_size = batch_size
        self.dry_run = dry_run

        self.sqlite_conn: Optional[sqlite3.Connection] = None
        self.pg_conn = None

        self.stats = {
            'tables_migrated': 0,
            'tables_skipped': 0,
            'total_rows': 0,
            'errors': [],
        }

    def connect(self) -> bool:
        """Establish database connections"""
        try:
            # SQLite connection
            if not self.sqlite_path.exists():
                logger.error(f"SQLite database not found: {self.sqlite_path}")
                return False

            self.sqlite_conn = sqlite3.connect(str(self.sqlite_path))
            self.sqlite_conn.row_factory = sqlite3.Row
            logger.info(f"Connected to SQLite: {self.sqlite_path}")

            # PostgreSQL connection
            if not self.dry_run:
                if not PSYCOPG2_AVAILABLE:
                    logger.error("psycopg2 is required for PostgreSQL connection")
                    return False

                self.pg_conn = psycopg2.connect(self.postgres_dsn)
                # Get server info
                with self.pg_conn.cursor() as cur:
                    cur.execute("SELECT version()")
                    version = cur.fetchone()[0]
                    logger.info(f"Connected to PostgreSQL: {version.split(',')[0]}")

            return True

        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False

    def disconnect(self):
        """Close database connections"""
        if self.sqlite_conn:
            self.sqlite_conn.close()
        if self.pg_conn:
            self.pg_conn.close()

    def get_sqlite_tables(self) -> List[str]:
        """Get list of tables in SQLite database"""
        cursor = self.sqlite_conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        return [row[0] for row in cursor.fetchall()]

    def get_table_row_count(self, table: str) -> int:
        """Get row count for a table"""
        cursor = self.sqlite_conn.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        return cursor.fetchone()[0]

    def migrate_table(self, table: str, config: Dict[str, Any]) -> Tuple[bool, int]:
        """
        Migrate a single table

        Returns:
            (success, row_count)
        """
        columns = config.get('columns', [])
        pg_columns = config.get('pg_columns', columns)
        transforms = config.get('transforms', {})
        row_transform = config.get('row_transform')
        skip_if_empty = config.get('skip_if_empty', True)

        # Get row count
        row_count = self.get_table_row_count(table)

        if row_count == 0 and skip_if_empty:
            logger.info(f"  Skipping {table}: no data")
            return True, 0

        logger.info(f"  Migrating {table}: {row_count} rows")

        if self.dry_run:
            return True, row_count

        try:
            # Read from SQLite
            sqlite_cursor = self.sqlite_conn.cursor()
            sqlite_cursor.execute(f"SELECT {','.join(columns)} FROM {table}")

            # Transform rows
            transformed_rows = []
            for row in sqlite_cursor.fetchall():
                new_row = list(row)

                # Apply column transforms
                for i, col in enumerate(columns):
                    if col in transforms:
                        try:
                            new_row[i] = transforms[col](row[i])
                        except Exception as e:
                            logger.warning(f"    Transform error on {col}: {e}")
                            new_row[i] = row[i]

                # Apply row transform
                if row_transform:
                    new_row = row_transform(tuple(new_row))
                else:
                    new_row = tuple(new_row)

                transformed_rows.append(new_row)

            # Insert into PostgreSQL in batches
            pg_cursor = self.pg_conn.cursor()

            # Build INSERT statement
            placeholders = ','.join(['%s'] * len(pg_columns))
            insert_sql = f"""
                INSERT INTO {table} ({','.join(pg_columns)})
                VALUES ({placeholders})
                ON CONFLICT DO NOTHING
            """

            # Execute in batches
            for i in range(0, len(transformed_rows), self.batch_size):
                batch = transformed_rows[i:i + self.batch_size]
                execute_batch(pg_cursor, insert_sql, batch, page_size=self.batch_size)
                self.pg_conn.commit()

                if len(transformed_rows) > self.batch_size:
                    progress = min(i + self.batch_size, len(transformed_rows))
                    logger.info(f"    Progress: {progress}/{len(transformed_rows)}")

            # Update sequence
            if 'id' in pg_columns:
                pg_cursor.execute(f"""
                    SELECT setval(
                        pg_get_serial_sequence('{table}', 'id'),
                        COALESCE((SELECT MAX(id) FROM {table}), 1)
                    )
                """)
                self.pg_conn.commit()

            return True, len(transformed_rows)

        except Exception as e:
            logger.error(f"    Migration error: {e}")
            if self.pg_conn:
                self.pg_conn.rollback()
            return False, 0

    def run(self, skip_tables: List[str] = None, only_tables: List[str] = None):
        """Run the migration"""
        skip_tables = skip_tables or []

        logger.info("=" * 60)
        logger.info("TSUNAMI SQLite -> PostgreSQL Migration")
        logger.info("=" * 60)

        if self.dry_run:
            logger.info("DRY RUN MODE - No changes will be made")

        logger.info(f"Source: {self.sqlite_path}")
        if not self.dry_run:
            # Hide password in DSN
            safe_dsn = self.postgres_dsn.split('@')[-1] if '@' in self.postgres_dsn else self.postgres_dsn
            logger.info(f"Target: {safe_dsn}")

        logger.info("")

        # Connect
        if not self.connect():
            return False

        try:
            # Get SQLite tables
            sqlite_tables = self.get_sqlite_tables()
            logger.info(f"Found {len(sqlite_tables)} tables in SQLite")
            logger.info("")

            # Determine which tables to migrate
            tables_to_migrate = []
            for table in TABLE_CONFIG.keys():
                if table in skip_tables:
                    logger.info(f"  Skipping {table} (--skip-tables)")
                    self.stats['tables_skipped'] += 1
                    continue

                if only_tables and table not in only_tables:
                    continue

                if table not in sqlite_tables:
                    logger.warning(f"  Table {table} not found in SQLite")
                    continue

                tables_to_migrate.append(table)

            logger.info(f"\nMigrating {len(tables_to_migrate)} tables...")
            logger.info("")

            # Migrate each table
            for table in tables_to_migrate:
                config = TABLE_CONFIG.get(table, {'columns': []})

                # Pre-migrate hook
                if 'pre_migrate' in config:
                    config['pre_migrate'](self)

                # Migrate
                success, count = self.migrate_table(table, config)

                if success:
                    self.stats['tables_migrated'] += 1
                    self.stats['total_rows'] += count
                else:
                    self.stats['errors'].append(table)

                # Post-migrate hook
                if 'post_migrate' in config:
                    config['post_migrate'](self)

            # Print summary
            logger.info("")
            logger.info("=" * 60)
            logger.info("MIGRATION SUMMARY")
            logger.info("=" * 60)
            logger.info(f"Tables migrated: {self.stats['tables_migrated']}")
            logger.info(f"Tables skipped:  {self.stats['tables_skipped']}")
            logger.info(f"Total rows:      {self.stats['total_rows']}")

            if self.stats['errors']:
                logger.error(f"Errors:          {len(self.stats['errors'])}")
                for table in self.stats['errors']:
                    logger.error(f"  - {table}")

            logger.info("=" * 60)

            return len(self.stats['errors']) == 0

        finally:
            self.disconnect()


# ==================== CLI ====================

def main():
    parser = argparse.ArgumentParser(
        description='TSUNAMI SQLite to PostgreSQL Migration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic migration
    python migrate_sqlite_to_postgresql.py

    # Custom paths
    python migrate_sqlite_to_postgresql.py \\
        --sqlite-db ./tsunami.db \\
        --postgres-dsn postgresql://user:pass@host:5432/db

    # Dry run
    python migrate_sqlite_to_postgresql.py --dry-run

    # Skip specific tables
    python migrate_sqlite_to_postgresql.py --skip-tables oturum_kayitlari,audit_log

    # Migrate only specific tables
    python migrate_sqlite_to_postgresql.py --only-tables kullanicilar,wifi_aglar
        """
    )

    parser.add_argument(
        '--sqlite-db',
        default=os.getenv('SQLITE_DB_PATH', str(DEFAULT_SQLITE_PATH)),
        help=f'SQLite database path (default: {DEFAULT_SQLITE_PATH})'
    )

    parser.add_argument(
        '--postgres-dsn',
        default=os.getenv('POSTGRES_DSN', DEFAULT_POSTGRES_DSN),
        help='PostgreSQL connection string'
    )

    parser.add_argument(
        '--batch-size',
        type=int,
        default=1000,
        help='Batch size for inserts (default: 1000)'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be migrated without executing'
    )

    parser.add_argument(
        '--skip-tables',
        help='Comma-separated list of tables to skip'
    )

    parser.add_argument(
        '--only-tables',
        help='Comma-separated list of tables to migrate only'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Parse table lists
    skip_tables = args.skip_tables.split(',') if args.skip_tables else []
    only_tables = args.only_tables.split(',') if args.only_tables else []

    # Create migration engine
    engine = MigrationEngine(
        sqlite_path=args.sqlite_db,
        postgres_dsn=args.postgres_dsn,
        batch_size=args.batch_size,
        dry_run=args.dry_run
    )

    # Run migration
    success = engine.run(
        skip_tables=skip_tables,
        only_tables=only_tables
    )

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
