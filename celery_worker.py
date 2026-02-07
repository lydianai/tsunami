#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI CELERY WORKER v1.0
    24/7 Otonom Arka Plan Görevleri
================================================================================

    Görevler:
    - Tehdit feed senkronizasyonu
    - Periyodik güvenlik taramaları
    - Sistem sağlık kontrolü
    - Veri temizliği
    - Coğrafi analiz
    - Rapor oluşturma
    - Alarm yönetimi

================================================================================
"""

import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging

# Celery
from celery import Celery
from celery.schedules import crontab

# Uygulama yolunu ekle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Loglama
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Celery uygulaması
celery = Celery(
    'tsunami',
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
)

# Celery yapılandırması
celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Europe/Istanbul',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 saat maksimum
    worker_prefetch_multiplier=1,
    worker_concurrency=4,
    result_expires=86400,  # 24 saat
)

# Beat zamanlama
celery.conf.beat_schedule = {
    # Her saat başı tehdit feed güncelleme
    'update-threat-feeds': {
        'task': 'celery_worker.sync_threat_feeds',
        'schedule': crontab(minute=0),
    },
    # Her 5 dakikada sistem sağlık kontrolü
    'health-check': {
        'task': 'celery_worker.system_health_check',
        'schedule': 300,  # 5 dakika
    },
    # Günlük veri temizliği (gece 03:00)
    'cleanup-old-data': {
        'task': 'celery_worker.cleanup_old_data',
        'schedule': crontab(hour=3, minute=0),
    },
    # Her 6 saatte coğrafi tehdit analizi
    'geo-analysis': {
        'task': 'celery_worker.run_geo_analysis',
        'schedule': crontab(hour='*/6', minute=30),
    },
    # Her 15 dakikada aktif saldırı izleme
    'active-attack-monitor': {
        'task': 'celery_worker.monitor_active_attacks',
        'schedule': 900,  # 15 dakika
    },
    # Saatlik istatistik raporu
    'hourly-stats': {
        'task': 'celery_worker.generate_hourly_stats',
        'schedule': crontab(minute=5),  # Her saat 05'te
    },
    # Günlük özet rapor (sabah 08:00)
    'daily-report': {
        'task': 'celery_worker.generate_daily_report',
        'schedule': crontab(hour=8, minute=0),
    },
}


# ============== GÖREVLER ==============

@celery.task(bind=True, max_retries=3)
def sync_threat_feeds(self) -> Dict[str, Any]:
    """Tehdit feed'lerini güncelle"""
    logger.info("[TASK] Tehdit feed senkronizasyonu başlatıldı")

    try:
        from dalga_threat_intel import threat_intel_al
        ti = threat_intel_al()
        results = ti.update_all_feeds()

        total_iocs = sum(v for v in results.values() if v > 0)
        logger.info(f"[TASK] {total_iocs} IOC güncellendi")

        return {
            'status': 'success',
            'feeds': results,
            'total_iocs': total_iocs,
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"[TASK] Tehdit feed hatası: {e}")
        raise self.retry(exc=e, countdown=300)


@celery.task
def system_health_check() -> Dict[str, Any]:
    """Sistem sağlık kontrolü"""
    logger.info("[TASK] Sistem sağlık kontrolü")

    health = {
        'status': 'healthy',
        'checks': {},
        'timestamp': datetime.now().isoformat()
    }

    # Veritabanı kontrolü
    try:
        from dalga_db import db_al
        db = db_al()
        db.conn.execute("SELECT 1")
        health['checks']['database'] = 'ok'
    except Exception as e:
        health['checks']['database'] = f'error: {e}'
        health['status'] = 'degraded'

    # Redis kontrolü
    try:
        import redis
        r = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        r.ping()
        health['checks']['redis'] = 'ok'
    except Exception as e:
        health['checks']['redis'] = f'error: {e}'
        health['status'] = 'degraded'

    # BEYIN modülü kontrolü
    try:
        from dalga_beyin import beyin_al
        beyin = beyin_al()
        health['checks']['beyin'] = 'active' if beyin._aktif else 'inactive'
    except Exception as e:
        health['checks']['beyin'] = f'error: {e}'

    # Disk alanı kontrolü
    try:
        import shutil
        total, used, free = shutil.disk_usage("/")
        free_gb = free // (1024**3)
        health['checks']['disk'] = f'{free_gb}GB free'
        if free_gb < 5:
            health['status'] = 'warning'
    except Exception as e:
        health['checks']['disk'] = f'error: {e}'

    # Bellek kontrolü
    try:
        import psutil
        mem = psutil.virtual_memory()
        health['checks']['memory'] = f'{mem.percent}% used'
        if mem.percent > 90:
            health['status'] = 'warning'
    except ImportError:
        health['checks']['memory'] = 'psutil not installed'

    # Tehdit Intel kontrolü
    try:
        from dalga_threat_intel import threat_intel_al
        ti = threat_intel_al()
        stats = ti.get_statistics()
        health['checks']['threat_intel'] = f"{stats['total_iocs']} IOCs"
    except Exception as e:
        health['checks']['threat_intel'] = f'error: {e}'

    logger.info(f"[TASK] Sağlık durumu: {health['status']}")

    # Kritik durum varsa alarm gönder
    if health['status'] != 'healthy':
        try:
            from dalga_db import db_al
            db = db_al()
            db.alarm_ekle(
                tip='system',
                kaynak='health_check',
                mesaj=f"Sistem durumu: {health['status']}",
                ciddiyet='yuksek' if health['status'] == 'degraded' else 'orta'
            )
        except:
            pass

    return health


@celery.task
def cleanup_old_data() -> Dict[str, int]:
    """Eski verileri temizle"""
    logger.info("[TASK] Veri temizliği başlatıldı")

    deleted = {
        'alarms': 0,
        'logs': 0,
        'scans': 0,
        'sessions': 0
    }

    try:
        from dalga_db import db_al
        db = db_al()

        # 30 günden eski alarmları temizle
        cursor = db.conn.cursor()

        cursor.execute("""
            DELETE FROM alarmlar
            WHERE tarih < datetime('now', '-30 days')
        """)
        deleted['alarms'] = cursor.rowcount

        # 7 günden eski oturum kayıtlarını temizle
        cursor.execute("""
            DELETE FROM oturum_kayitlari
            WHERE tarih < datetime('now', '-7 days')
        """)
        deleted['logs'] = cursor.rowcount

        # 90 günden eski tarama geçmişini temizle
        cursor.execute("""
            DELETE FROM tarama_gecmisi
            WHERE baslangic < datetime('now', '-90 days')
        """)
        deleted['scans'] = cursor.rowcount

        db.conn.commit()

        logger.info(f"[TASK] Temizlenen kayıtlar: {deleted}")

    except Exception as e:
        logger.error(f"[TASK] Temizlik hatası: {e}")

    return deleted


@celery.task
def run_geo_analysis() -> Dict[str, Any]:
    """Coğrafi tehdit analizi"""
    logger.info("[TASK] Coğrafi analiz başlatıldı")

    try:
        from dalga_db import db_al
        from dalga_threat_intel import threat_intel_al

        db = db_al()
        ti = threat_intel_al()

        # Son 24 saatteki alarmları analiz et
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT kaynak, COUNT(*) as sayi
            FROM alarmlar
            WHERE tarih > datetime('now', '-24 hours')
            GROUP BY kaynak
            ORDER BY sayi DESC
            LIMIT 20
        """)

        hot_sources = cursor.fetchall()

        # Her kaynağı tehdit intel ile kontrol et
        threats = []
        for row in hot_sources:
            source = row['kaynak']
            ioc = ti.check_ip(source)
            if ioc:
                threats.append({
                    'ip': source,
                    'count': row['sayi'],
                    'severity': ioc.severity.value,
                    'categories': [c.value for c in ioc.categories]
                })

        result = {
            'analyzed_sources': len(hot_sources),
            'confirmed_threats': len(threats),
            'top_threats': threats[:10],
            'timestamp': datetime.now().isoformat()
        }

        logger.info(f"[TASK] {len(threats)} doğrulanmış tehdit bulundu")

        return result

    except Exception as e:
        logger.error(f"[TASK] Coğrafi analiz hatası: {e}")
        return {'error': str(e)}


@celery.task
def monitor_active_attacks() -> Dict[str, Any]:
    """Aktif saldırı izleme"""
    logger.info("[TASK] Aktif saldırı izleme")

    try:
        from dalga_db import db_al
        from dalga_beyin import beyin_al

        db = db_al()
        beyin = beyin_al()

        # Son 15 dakikadaki yüksek ciddiyet alarmları
        cursor = db.conn.cursor()
        cursor.execute("""
            SELECT tip, kaynak, mesaj, ciddiyet, tarih
            FROM alarmlar
            WHERE tarih > datetime('now', '-15 minutes')
            AND ciddiyet IN ('kritik', 'yuksek')
            ORDER BY tarih DESC
        """)

        active_alerts = cursor.fetchall()

        # Saldırı pattern analizi
        attack_patterns = {}
        for alert in active_alerts:
            tip = alert['tip']
            if tip not in attack_patterns:
                attack_patterns[tip] = 0
            attack_patterns[tip] += 1

        # DEFCON durumu kontrolü
        defcon = beyin._tehdit.defcon_seviyesi_belirle()

        result = {
            'active_alerts': len(active_alerts),
            'patterns': attack_patterns,
            'defcon': defcon.value,
            'timestamp': datetime.now().isoformat()
        }

        # Çok sayıda kritik alarm varsa BEYIN'i uyar
        if len(active_alerts) > 10:
            beyin.tehdit_bildir('active_attack_monitor', 0.8, {
                'alert_count': len(active_alerts),
                'patterns': attack_patterns
            })
            logger.warning(f"[TASK] Yüksek saldırı aktivitesi: {len(active_alerts)} alarm")

        return result

    except Exception as e:
        logger.error(f"[TASK] Saldırı izleme hatası: {e}")
        return {'error': str(e)}


@celery.task
def generate_hourly_stats() -> Dict[str, Any]:
    """Saatlik istatistik raporu"""
    logger.info("[TASK] Saatlik istatistik raporu")

    try:
        from dalga_db import db_al

        db = db_al()
        cursor = db.conn.cursor()

        stats = {}

        # Alarm istatistikleri
        cursor.execute("""
            SELECT ciddiyet, COUNT(*) as sayi
            FROM alarmlar
            WHERE tarih > datetime('now', '-1 hour')
            GROUP BY ciddiyet
        """)
        stats['alarms_by_severity'] = {row['ciddiyet']: row['sayi'] for row in cursor.fetchall()}

        # WiFi ağ sayısı
        cursor.execute("SELECT COUNT(*) as sayi FROM wifi_aglar")
        stats['wifi_networks'] = cursor.fetchone()['sayi']

        # Bluetooth cihaz sayısı
        cursor.execute("SELECT COUNT(*) as sayi FROM bluetooth_cihazlar")
        stats['bluetooth_devices'] = cursor.fetchone()['sayi']

        # Zafiyet sayısı
        cursor.execute("SELECT COUNT(*) as sayi FROM zafiyetler WHERE durum='acik'")
        stats['open_vulnerabilities'] = cursor.fetchone()['sayi']

        # Aktif oturumlar
        cursor.execute("""
            SELECT COUNT(DISTINCT kullanici) as sayi
            FROM oturum_kayitlari
            WHERE tarih > datetime('now', '-1 hour')
        """)
        stats['active_users'] = cursor.fetchone()['sayi']

        stats['timestamp'] = datetime.now().isoformat()

        logger.info(f"[TASK] İstatistikler: {stats}")

        return stats

    except Exception as e:
        logger.error(f"[TASK] İstatistik hatası: {e}")
        return {'error': str(e)}


@celery.task
def generate_daily_report() -> Dict[str, Any]:
    """Günlük özet rapor"""
    logger.info("[TASK] Günlük rapor oluşturuluyor")

    try:
        from dalga_db import db_al
        from dalga_threat_intel import threat_intel_al

        db = db_al()
        ti = threat_intel_al()
        cursor = db.conn.cursor()

        report = {
            'date': datetime.now().strftime('%Y-%m-%d'),
            'summary': {},
            'threats': {},
            'recommendations': []
        }

        # 24 saatlik alarm özeti
        cursor.execute("""
            SELECT
                COUNT(*) as toplam,
                SUM(CASE WHEN ciddiyet='kritik' THEN 1 ELSE 0 END) as kritik,
                SUM(CASE WHEN ciddiyet='yuksek' THEN 1 ELSE 0 END) as yuksek,
                SUM(CASE WHEN ciddiyet='orta' THEN 1 ELSE 0 END) as orta,
                SUM(CASE WHEN ciddiyet='dusuk' THEN 1 ELSE 0 END) as dusuk
            FROM alarmlar
            WHERE tarih > datetime('now', '-24 hours')
        """)
        alarm_stats = cursor.fetchone()
        report['summary']['alarms'] = {
            'total': alarm_stats['toplam'],
            'critical': alarm_stats['kritik'],
            'high': alarm_stats['yuksek'],
            'medium': alarm_stats['orta'],
            'low': alarm_stats['dusuk']
        }

        # En aktif tehdit kaynakları
        cursor.execute("""
            SELECT kaynak, COUNT(*) as sayi
            FROM alarmlar
            WHERE tarih > datetime('now', '-24 hours')
            GROUP BY kaynak
            ORDER BY sayi DESC
            LIMIT 10
        """)
        report['threats']['top_sources'] = [
            {'source': row['kaynak'], 'count': row['sayi']}
            for row in cursor.fetchall()
        ]

        # Threat Intel istatistikleri
        ti_stats = ti.get_statistics()
        report['threats']['ioc_database'] = ti_stats['total_iocs']

        # Öneriler
        if alarm_stats['kritik'] > 0:
            report['recommendations'].append(
                f"{alarm_stats['kritik']} kritik alarm var - acil inceleme gerekli"
            )

        if alarm_stats['toplam'] > 100:
            report['recommendations'].append(
                "Yüksek alarm hacmi - firewall kurallarını gözden geçirin"
            )

        logger.info(f"[TASK] Günlük rapor oluşturuldu: {report['summary']}")

        return report

    except Exception as e:
        logger.error(f"[TASK] Rapor hatası: {e}")
        return {'error': str(e)}


@celery.task(bind=True)
def run_security_scan(self, target: str, scan_type: str = 'basic') -> Dict[str, Any]:
    """Manuel güvenlik taraması"""
    logger.info(f"[TASK] Güvenlik taraması: {target} ({scan_type})")

    try:
        from dalga_mcp import MCPClient

        mcp = MCPClient.get_instance()
        results = []

        if scan_type == 'basic':
            # Temel tarama
            if mcp.ARACLAR.get('ping'):
                result = mcp.calistir('ping', [target])
                results.append({'tool': 'ping', 'result': result})

            if mcp.ARACLAR.get('whois'):
                result = mcp.calistir('whois', [target])
                results.append({'tool': 'whois', 'result': result})

        elif scan_type == 'port':
            # Port taraması
            if mcp.ARACLAR.get('nmap'):
                result = mcp.calistir('nmap', ['-sV', '-T4', target])
                results.append({'tool': 'nmap', 'result': result})

        elif scan_type == 'full':
            # Tam tarama
            tools = ['ping', 'whois', 'dig', 'nmap']
            for tool in tools:
                if mcp.ARACLAR.get(tool):
                    result = mcp.calistir(tool, [target] if tool != 'nmap' else ['-sV', '-A', target])
                    results.append({'tool': tool, 'result': result})

        return {
            'target': target,
            'scan_type': scan_type,
            'results': results,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"[TASK] Tarama hatası: {e}")
        raise self.retry(exc=e, countdown=60, max_retries=2)


# ============== ÇALIŞTIRMA ==============

if __name__ == '__main__':
    celery.start()
