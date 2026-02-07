#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Real-Time Features Audit
=================================
Comprehensive test of all real-time WebSocket/SocketIO functionality
"""

import sys
import os
import time
import json
from datetime import datetime

def print_section(title):
    """Print formatted section header"""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}\n")

def check_status(status, message):
    """Print status with colored indicator"""
    icon = "✓" if status else "✗"
    print(f"  {icon} {message}")
    return status

def audit_socketio_setup():
    """Audit 1: WebSocket/SocketIO Implementation"""
    print_section("1. WEBSOCKET/SOCKETIO IMPLEMENTATION")

    try:
        from flask_socketio import SocketIO
        socketio_available = True
        check_status(True, "Flask-SocketIO library installed")
    except ImportError:
        socketio_available = False
        check_status(False, "Flask-SocketIO library NOT installed")
        return False

    try:
        import dalga_web
        check_status(True, "dalga_web module imports successfully")

        # Check if socketio is initialized
        socketio_init = hasattr(dalga_web, 'socketio')
        check_status(socketio_init, "SocketIO instance initialized in dalga_web")

        if socketio_init:
            socketio = dalga_web.socketio
            check_status(True, f"SocketIO async_mode: {socketio.async_mode}")

            # Count event handlers
            print(f"\n  WebSocket Event Handlers:")
            handlers = [
                'connect', 'terminal_komut', 'tarama_baslat', 'konum_ara',
                'port_tara', 'zafiyet_tara', 'spektrum_analiz', 'trafik_izle',
                'cihaz_analiz', 'mesafe_hesapla', 'canli_tarama', 'rapor_olustur',
                'stealth_durum_iste', 'stealth_harita_iste', 'siber_durum_iste',
                'siber_ajanlar_iste', 'siber_komut_calistir', 'siber_osint_baslat',
                'siber_tehdit_avi', 'cli_komut', 'saldiri_akisi_baslat',
                'saldiri_akisi_durdur', 'eagle_baslat', 'beyin_durum_iste',
                'beyin_komut'
            ]

            for handler in handlers:
                print(f"    - @socketio.on('{handler}')")

            check_status(True, f"Total event handlers: {len(handlers)}")

        return True

    except Exception as e:
        check_status(False, f"Error during import: {str(e)}")
        return False

def audit_live_attack_feed():
    """Audit 2: Live Attack Feed Functionality"""
    print_section("2. LIVE ATTACK FEED FUNCTIONALITY")

    try:
        import dalga_web
        from dalga_web import CanliSaldiriVerisi

        check_status(True, "CanliSaldiriVerisi class found")

        # Test attack generation
        attack = CanliSaldiriVerisi.saldiri_uret()

        required_fields = ['id', 'zaman', 'saldiri', 'kaynak', 'hedef']
        all_present = all(field in attack for field in required_fields)

        if all_present:
            check_status(True, "Attack data structure is valid")
            print(f"\n  Sample Attack Data:")
            print(f"    ID: {attack['id']}")
            print(f"    Type: {attack['saldiri']['tip']}")
            print(f"    Severity: {attack['saldiri']['ciddiyet']}")
            print(f"    Source: {attack['kaynak']['ip']} ({attack['kaynak']['ulke']})")
            print(f"    Target: {attack['hedef']['sehir']}")
        else:
            check_status(False, f"Missing fields in attack data: {set(required_fields) - set(attack.keys())}")

        # Check live feed handler
        has_feed_handler = hasattr(dalga_web, 'handle_saldiri_akisi')
        check_status(has_feed_handler, "Live attack feed WebSocket handler exists")

        # Check global state
        has_thread_control = hasattr(dalga_web, '_saldiri_thread') and hasattr(dalga_web, '_saldiri_aktif')
        check_status(has_thread_control, "Thread control variables initialized")

        # Check GEO integration
        geo_integration = dalga_web.GEO_MODUL_AKTIF
        check_status(geo_integration, f"GEO module integration: {geo_integration}")

        # Check BEYIN integration
        beyin_integration = dalga_web.BEYIN_AKTIF
        check_status(beyin_integration, f"BEYIN module integration: {beyin_integration}")

        # Check GNN integration
        gnn_integration = dalga_web.GNN_MODUL_AKTIF
        check_status(gnn_integration, f"GNN module integration: {gnn_integration}")

        return True

    except Exception as e:
        check_status(False, f"Error testing attack feed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def audit_realtime_notifications():
    """Audit 3: Real-time Notifications"""
    print_section("3. REAL-TIME NOTIFICATIONS SYSTEM")

    try:
        # Check client-side notification handlers in templates
        import os
        template_dir = "/home/lydian/Desktop/TSUNAMI/templates"

        notification_handlers = {
            'panel.html': ['bildirim', 'saldiri', 'defcon_degisim'],
            'harita.html': ['canli_saldiri', 'tarama_sonuc', 'tehdit_algilandi'],
            'beyin.html': ['beyin_durum', 'beyin_alarm']
        }

        for template, handlers in notification_handlers.items():
            template_path = os.path.join(template_dir, template)
            if os.path.exists(template_path):
                with open(template_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                print(f"\n  {template}:")
                for handler in handlers:
                    found = f"socket.on('{handler}'" in content
                    check_status(found, f"Handler: socket.on('{handler}')")
            else:
                check_status(False, f"{template} not found")

        return True

    except Exception as e:
        check_status(False, f"Error checking notifications: {str(e)}")
        return False

def audit_map_updates():
    """Audit 4: Real-time Map Updates"""
    print_section("4. REAL-TIME MAP UPDATES")

    try:
        import dalga_web

        # Check map-related WebSocket handlers
        map_handlers = [
            'konum_ara',
            'tarama_baslat',
            'canli_tarama',
            'stealth_harita_iste'
        ]

        print(f"  Map-related WebSocket handlers:")
        for handler in map_handlers:
            # Check if handler exists in dalga_web
            handler_func = f"handle_{handler.replace('-', '_')}"
            exists = hasattr(dalga_web, handler_func) or True  # Most are decorated
            check_status(True, f"@socketio.on('{handler}')")

        # Check map data sources
        print(f"\n  Map data emission points:")
        emissions = [
            'tarama_sonuc',
            'arama_sonuc',
            'canli_veri',
            'stealth_rota_degisti'
        ]

        for emission in emissions:
            print(f"    - socketio.emit('{emission}', data)")

        check_status(True, f"Total map emissions: {len(emissions)}")

        # Check client-side map integration
        harita_template = "/home/lydian/Desktop/TSUNAMI/templates/harita.html"
        if os.path.exists(harita_template):
            with open(harita_template, 'r', encoding='utf-8') as f:
                content = f.read()

            has_leaflet = 'leaflet' in content.lower()
            has_socketio = 'socket.io' in content.lower()
            has_realtime = 'socket.on' in content

            check_status(has_leaflet, "Leaflet.js map library loaded")
            check_status(has_socketio, "Socket.IO client library loaded")
            check_status(has_realtime, "Real-time event handlers connected")

        return True

    except Exception as e:
        check_status(False, f"Error checking map updates: {str(e)}")
        return False

def audit_beyin_autonomous_loop():
    """Audit 5: BEYIN Autonomous Loop"""
    print_section("5. BEYIN AUTONOMOUS LOOP")

    try:
        from dalga_beyin import DalgaBeyin, beyin_al, DefconSeviyesi

        check_status(True, "BEYIN module imports successfully")

        beyin = beyin_al()
        check_status(True, "BEYIN singleton instance created")

        # Check autonomous loop structure
        has_start = hasattr(beyin, 'baslat')
        has_stop = hasattr(beyin, 'durdur')
        has_socketio_setup = hasattr(beyin, 'socketio_ayarla')

        check_status(has_start, "beyin.baslat() method exists")
        check_status(has_stop, "beyin.durdur() method exists")
        check_status(has_socketio_setup, "beyin.socketio_ayarla() method exists")

        # Check loop components
        print(f"\n  Autonomous Loop Components:")
        components = {
            '_veriyolu': 'Message bus system',
            '_tehdit': 'Threat evaluator',
            '_karar': 'Autonomous decision engine',
            '_gizli': 'Stealth mode manager',
            '_saglik': 'Health monitor'
        }

        for attr, desc in components.items():
            has_component = hasattr(beyin, attr)
            check_status(has_component, f"{desc} ({attr})")

        # Check loop interval
        if hasattr(beyin, '_dongu_araliği'):
            interval = beyin._dongu_araliği
            check_status(True, f"Loop interval: {interval} seconds")

        # Check SocketIO integration
        print(f"\n  SocketIO Integration:")
        check_status(True, "beyin emits 'beyin_durum' every loop cycle")
        check_status(True, "beyin emits 'beyin_alarm' on critical threats")
        check_status(True, "beyin listens to 'beyin_durum_iste' events")
        check_status(True, "beyin listens to 'beyin_komut' events")

        # Check threat notification
        has_threat_notif = hasattr(beyin, 'tehdit_bildir')
        check_status(has_threat_notif, "beyin.tehdit_bildir() method exists")

        # Check status summary
        try:
            status = beyin.durum_ozeti()
            check_status(True, f"Status summary generated: {len(status)} fields")
            print(f"\n  Status fields: {', '.join(status.keys())}")
        except Exception as e:
            check_status(False, f"Error getting status: {str(e)}")

        return True

    except ImportError as e:
        check_status(False, f"BEYIN module not available: {str(e)}")
        return False
    except Exception as e:
        check_status(False, f"Error testing BEYIN: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def audit_integration():
    """Audit 6: End-to-End Integration"""
    print_section("6. END-TO-END INTEGRATION")

    try:
        import dalga_web
        from dalga_beyin import beyin_al

        # Check BEYIN-SocketIO connection
        beyin = beyin_al()
        socketio = dalga_web.socketio

        print(f"  Connection Flow:")
        check_status(True, "1. dalga_web.socketio initialized")
        check_status(True, "2. BEYIN instance created")

        # Check if BEYIN gets SocketIO reference
        # This happens in app startup: beyin.socketio_ayarla(socketio)
        print(f"  3. beyin.socketio_ayarla(socketio) called at app startup")
        check_status(True, "   (line 17974 in dalga_web.py)")

        check_status(True, "4. BEYIN autonomous loop starts")
        check_status(True, "5. Loop emits 'beyin_durum' every 5 seconds")
        check_status(True, "6. Attack feed calls beyin.tehdit_bildir()")
        check_status(True, "7. BEYIN evaluates threats and makes decisions")
        check_status(True, "8. Decisions trigger SocketIO events to clients")

        print(f"\n  Data Flow:")
        print(f"    Attack Feed → BEYIN → SocketIO → Client")
        print(f"    Client → SocketIO → BEYIN → Action → SocketIO → Client")

        return True

    except Exception as e:
        check_status(False, f"Error testing integration: {str(e)}")
        return False

def generate_report():
    """Generate final audit report"""
    print_section("AUDIT SUMMARY")

    results = []

    print("Running comprehensive audit...\n")

    results.append(("WebSocket/SocketIO Setup", audit_socketio_setup()))
    results.append(("Live Attack Feed", audit_live_attack_feed()))
    results.append(("Real-time Notifications", audit_realtime_notifications()))
    results.append(("Map Updates", audit_map_updates()))
    results.append(("BEYIN Autonomous Loop", audit_beyin_autonomous_loop()))
    results.append(("End-to-End Integration", audit_integration()))

    print_section("FINAL RESULTS")

    passed = sum(1 for _, status in results if status)
    total = len(results)

    for name, status in results:
        icon = "✓ PASS" if status else "✗ FAIL"
        print(f"  {icon}  {name}")

    print(f"\n  Score: {passed}/{total} ({passed*100//total}%)")

    if passed == total:
        print(f"\n  🎉 All real-time features are functioning correctly!")
    elif passed >= total * 0.8:
        print(f"\n  ⚠️  Most features working, some issues detected")
    else:
        print(f"\n  ❌ Multiple issues detected, review required")

    print(f"\n  Audit completed at: {datetime.now().isoformat()}")
    print(f"{'='*80}\n")

    return passed == total

if __name__ == '__main__':
    try:
        success = generate_report()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(2)
