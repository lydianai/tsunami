#!/usr/bin/env python3
"""
TSUNAMI SOC - Tum SOC Blueprint'lerini topluca kaydeden araci modul.
Her modul bagimsiz try/except ile korunur.
"""
import logging

logger = logging.getLogger("soc.blueprints")


def register_soc_blueprints(app):
    """
    Tum SOC modulu Blueprint'lerini Flask app'e kaydeder.
    Basarili/basarisiz durumlari dict olarak doner.
    """
    durum = {}

    # 1) RBAC / Auth
    try:
        from modules.soc_core.rbac import create_auth_blueprint
        bp = create_auth_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['rbac'] = 'AKTIF'
        else:
            durum['rbac'] = 'PASIF'
    except Exception as e:
        durum['rbac'] = f'HATA: {e}'
        logger.warning("[SOC] RBAC yuklenemedi: %s", e)

    # 2) Alert Queue
    try:
        from modules.soc_core.alert_queue import create_alert_queue_blueprint
        bp = create_alert_queue_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['alert_queue'] = 'AKTIF'
        else:
            durum['alert_queue'] = 'PASIF'
    except Exception as e:
        durum['alert_queue'] = f'HATA: {e}'
        logger.warning("[SOC] Alert Queue yuklenemedi: %s", e)

    # 3) SOC Dashboard
    try:
        from modules.soc_core.soc_dashboard import create_dashboard_blueprint
        bp = create_dashboard_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['soc_dashboard'] = 'AKTIF'
        else:
            durum['soc_dashboard'] = 'PASIF'
    except Exception as e:
        durum['soc_dashboard'] = f'HATA: {e}'
        logger.warning("[SOC] Dashboard yuklenemedi: %s", e)

    # 4) Notification Engine
    try:
        from modules.soc_core.notification_engine import create_notification_blueprint
        bp = create_notification_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['notifications'] = 'AKTIF'
        else:
            durum['notifications'] = 'PASIF'
    except Exception as e:
        durum['notifications'] = f'HATA: {e}'
        logger.warning("[SOC] Bildirim yuklenemedi: %s", e)

    # 5) Approval Workflow
    try:
        from modules.soc_core.approval_workflow import create_approval_blueprint
        bp = create_approval_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['approval'] = 'AKTIF'
        else:
            durum['approval'] = 'PASIF'
    except Exception as e:
        durum['approval'] = f'HATA: {e}'
        logger.warning("[SOC] Onay Akisi yuklenemedi: %s", e)

    # 6) Auto Response
    try:
        from modules.soc_core.auto_response import create_auto_response_blueprint
        bp = create_auto_response_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['auto_response'] = 'AKTIF'
        else:
            durum['auto_response'] = 'PASIF'
    except Exception as e:
        durum['auto_response'] = f'HATA: {e}'
        logger.warning("[SOC] Oto Mudahale yuklenemedi: %s", e)

    # 7) Wazuh Connector
    try:
        from modules.siem_integration.wazuh_connector import create_wazuh_blueprint
        bp = create_wazuh_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['wazuh'] = 'AKTIF'
        else:
            durum['wazuh'] = 'PASIF'
    except Exception as e:
        durum['wazuh'] = f'HATA: {e}'
        logger.warning("[SOC] Wazuh yuklenemedi: %s", e)

    # 8) Suricata Connector
    try:
        from modules.siem_integration.suricata_connector import create_suricata_blueprint
        bp = create_suricata_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['suricata'] = 'AKTIF'
        else:
            durum['suricata'] = 'PASIF'
    except Exception as e:
        durum['suricata'] = f'HATA: {e}'
        logger.warning("[SOC] Suricata yuklenemedi: %s", e)

    # 9) Alert Normalizer
    try:
        from modules.siem_integration.alert_normalizer import create_normalizer_blueprint
        bp = create_normalizer_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['normalizer'] = 'AKTIF'
        else:
            durum['normalizer'] = 'PASIF'
    except Exception as e:
        durum['normalizer'] = f'HATA: {e}'
        logger.warning("[SOC] Normalizer yuklenemedi: %s", e)

    # 10) Sigma Engine
    try:
        from modules.siem_integration.sigma_engine import create_sigma_blueprint
        bp = create_sigma_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['sigma'] = 'AKTIF'
        else:
            durum['sigma'] = 'PASIF'
    except Exception as e:
        durum['sigma'] = f'HATA: {e}'
        logger.warning("[SOC] Sigma yuklenemedi: %s", e)

    # 11) IOC Enrichment
    try:
        from modules.enrichment.ioc_enrichment import create_enrichment_blueprint
        bp = create_enrichment_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['enrichment'] = 'AKTIF'
        else:
            durum['enrichment'] = 'PASIF'
    except Exception as e:
        durum['enrichment'] = f'HATA: {e}'
        logger.warning("[SOC] Zenginlestirme yuklenemedi: %s", e)

    # 12) Cortex Analyzer
    try:
        from modules.enrichment.cortex_analyzer import create_cortex_blueprint
        bp = create_cortex_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['cortex'] = 'AKTIF'
        else:
            durum['cortex'] = 'PASIF'
    except Exception as e:
        durum['cortex'] = f'HATA: {e}'
        logger.warning("[SOC] Cortex yuklenemedi: %s", e)

    # 13) TheHive
    try:
        from modules.case_management.thehive_connector import create_thehive_blueprint
        bp = create_thehive_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['thehive'] = 'AKTIF'
        else:
            durum['thehive'] = 'PASIF'
    except Exception as e:
        durum['thehive'] = f'HATA: {e}'
        logger.warning("[SOC] TheHive yuklenemedi: %s", e)

    # 14) MISP
    try:
        from modules.threat_sharing.misp_connector import create_misp_blueprint
        bp = create_misp_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['misp'] = 'AKTIF'
        else:
            durum['misp'] = 'PASIF'
    except Exception as e:
        durum['misp'] = f'HATA: {e}'
        logger.warning("[SOC] MISP yuklenemedi: %s", e)

    # 15) Compliance
    try:
        from modules.compliance.report_generator import create_compliance_blueprint
        bp = create_compliance_blueprint()
        if bp:
            app.register_blueprint(bp)
            durum['compliance'] = 'AKTIF'
        else:
            durum['compliance'] = 'PASIF'
    except Exception as e:
        durum['compliance'] = f'HATA: {e}'
        logger.warning("[SOC] Uyumluluk yuklenemedi: %s", e)

    aktif = sum(1 for v in durum.values() if v == 'AKTIF')
    logger.info("[SOC] %d/15 Blueprint kaydedildi", aktif)
    return durum
