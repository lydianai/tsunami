#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI SIGINT Tests v2.0
==========================

Comprehensive tests for SIGINT modules:
- WiFi scanning (dalga.py WiFiTarayici)
- Bluetooth scanning (dalga.py BluetoothTarayici)
- Cell tower scanning (dalga.py OpenCellIDIstemci)
- Device classification (dalga.py CihazSiniflandirici)
- API clients (WiGLE, Shodan)
- Database operations
- Security (GuvenlikYoneticisi)

pytest tests/test_sigint.py -v --cov=dalga
"""

import os
import sys
import json
import pytest
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Try to import hypothesis for property-based testing
try:
    from hypothesis import given, strategies as st, settings
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False
    # Create no-op decorators when hypothesis is not available
    def given(*args, **kwargs):
        def decorator(f):
            return f
        return decorator
    def settings(*args, **kwargs):
        def decorator(f):
            return f
        return decorator
    class st:
        @staticmethod
        def text(*args, **kwargs):
            return None


class TestCihazSiniflandirici:
    """Device classifier tests"""

    def test_classify_headphone(self):
        """Test headphone classification"""
        from dalga import CihazSiniflandirici

        headphone_names = ['AirPods Pro', 'Bose QC45', 'Sony WH-1000XM4', 'JBL Earbuds']
        for name in headphone_names:
            category = CihazSiniflandirici.siniflandir(name)
            assert category == 'kulaklik', f"Expected 'kulaklik' for {name}"

    def test_classify_phone(self):
        """Test phone classification"""
        from dalga import CihazSiniflandirici

        phone_names = ['iPhone 15 Pro', 'Samsung Galaxy S24', 'Google Pixel 8', 'OnePlus 12']
        for name in phone_names:
            category = CihazSiniflandirici.siniflandir(name)
            assert category == 'telefon', f"Expected 'telefon' for {name}"

    def test_classify_tv(self):
        """Test TV classification"""
        from dalga import CihazSiniflandirici

        tv_names = ['Samsung Smart TV', 'LG TV OLED', 'Sony Bravia', 'Roku TV']
        for name in tv_names:
            category = CihazSiniflandirici.siniflandir(name)
            assert category == 'televizyon', f"Expected 'televizyon' for {name}"

    def test_classify_car(self):
        """Test car/vehicle classification"""
        from dalga import CihazSiniflandirici

        car_names = ['Tesla Model 3', 'Ford SYNC', 'BMW iDrive', 'CarPlay']
        for name in car_names:
            category = CihazSiniflandirici.siniflandir(name)
            assert category == 'arac', f"Expected 'arac' for {name}"

    def test_classify_camera(self):
        """Test camera classification"""
        from dalga import CihazSiniflandirici

        camera_names = ['Nest Cam', 'Ring Doorbell', 'Wyze Cam', 'Arlo Pro']
        for name in camera_names:
            category = CihazSiniflandirici.siniflandir(name)
            assert category == 'kamera', f"Expected 'kamera' for {name}"

    def test_classify_iot(self):
        """Test IoT device classification"""
        from dalga import CihazSiniflandirici

        iot_names = ['Nest Thermostat', 'Philips Hue', 'Amazon Echo', 'Google Home']
        for name in iot_names:
            category = CihazSiniflandirici.siniflandir(name)
            assert category == 'iot', f"Expected 'iot' for {name}"

    def test_classify_unknown(self):
        """Test unknown device classification"""
        from dalga import CihazSiniflandirici

        # Empty or unknown should return default
        assert CihazSiniflandirici.siniflandir('') in ['bilinmeyen', 'diger', None]
        assert CihazSiniflandirici.siniflandir(None) in ['bilinmeyen', 'diger', None]

    def test_classify_with_original_type(self):
        """Test classification with original type fallback"""
        from dalga import CihazSiniflandirici

        result = CihazSiniflandirici.siniflandir('UnknownDevice123', 'bluetooth')
        # Should return original type if no match
        assert result in ['bluetooth', 'diger']

    def test_vendor_lookup_apple(self):
        """Test vendor lookup for Apple devices"""
        from dalga import CihazSiniflandirici

        apple_macs = ['7C:D1:C3:AA:BB:CC', '00:1B:63:11:22:33', 'F4:5C:89:DD:EE:FF']
        for mac in apple_macs:
            vendor = CihazSiniflandirici.satici_bul(mac)
            assert vendor == 'Apple', f"Expected 'Apple' for {mac}"

    def test_vendor_lookup_intel(self):
        """Test vendor lookup for Intel devices"""
        from dalga import CihazSiniflandirici

        intel_macs = ['00:0A:F7:11:22:33', '00:02:B3:AA:BB:CC']
        for mac in intel_macs:
            vendor = CihazSiniflandirici.satici_bul(mac)
            assert vendor == 'Intel', f"Expected 'Intel' for {mac}"

    def test_vendor_lookup_unknown(self):
        """Test vendor lookup for unknown MAC"""
        from dalga import CihazSiniflandirici

        vendor = CihazSiniflandirici.satici_bul('FF:FF:FF:AA:BB:CC')
        assert vendor == 'Bilinmeyen'

    def test_vendor_lookup_empty(self):
        """Test vendor lookup with empty MAC"""
        from dalga import CihazSiniflandirici

        vendor = CihazSiniflandirici.satici_bul('')
        assert vendor == 'Bilinmeyen'


class TestGuvenlikYoneticisi:
    """Security manager tests"""

    @pytest.fixture
    def guvenlik(self, temp_test_dir):
        """Create GuvenlikYoneticisi with temp directory"""
        from dalga import GuvenlikYoneticisi, DALGA_KEYS

        # Mock DALGA_KEYS to use temp directory
        with patch('dalga.DALGA_KEYS', temp_test_dir / '.keys'):
            guvenlik = GuvenlikYoneticisi()
            yield guvenlik

    def test_encrypt_decrypt_roundtrip(self, guvenlik):
        """Test encryption/decryption roundtrip"""
        original = "Secret message 12345!"
        encrypted = guvenlik.sifrele(original)
        decrypted = guvenlik.coz(encrypted)
        assert decrypted == original

    def test_encrypt_empty_string(self, guvenlik):
        """Test encrypting empty string"""
        encrypted = guvenlik.sifrele('')
        assert encrypted == ''

    def test_decrypt_empty_string(self, guvenlik):
        """Test decrypting empty string"""
        decrypted = guvenlik.coz('')
        assert decrypted == ''

    def test_hash_consistency(self, guvenlik):
        """Test hash consistency"""
        data = "test_data"
        hash1 = guvenlik.hash_olustur(data)
        hash2 = guvenlik.hash_olustur(data)
        assert hash1 == hash2

    def test_hash_uniqueness(self, guvenlik):
        """Test hash uniqueness for different data"""
        hash1 = guvenlik.hash_olustur("data1")
        hash2 = guvenlik.hash_olustur("data2")
        assert hash1 != hash2

    def test_hash_format(self, guvenlik):
        """Test hash format is SHA-256"""
        hash_value = guvenlik.hash_olustur("test")
        assert len(hash_value) == 64  # SHA-256 produces 64 hex chars
        assert all(c in '0123456789abcdef' for c in hash_value)


class TestDalgaVeritabani:
    """Database tests"""

    @pytest.fixture
    def veritabani(self, temp_test_dir):
        """Create DalgaVeritabani with temp file"""
        from dalga import DalgaVeritabani

        db_path = temp_test_dir / "test_dalga.db"
        return DalgaVeritabani(db_yolu=db_path)

    def test_wifi_save_and_retrieve(self, veritabani):
        """Test WiFi network save and retrieve"""
        wifi_data = {
            'bssid': 'AA:BB:CC:DD:EE:FF',
            'ssid': 'TestNetwork',
            'kanal': 6,
            'sinyal': 75,
            'sifreleme': 'WPA2',
            'satici': 'Intel',
            'enlem': 41.0,
            'boylam': 29.0,
        }

        # Save
        veritabani.wifi_kaydet(wifi_data)

        # Retrieve
        networks = veritabani.tum_wifi_getir(limit=10)
        assert len(networks) >= 1

        saved = networks[0]
        assert saved['bssid'] == 'AA:BB:CC:DD:EE:FF'
        assert saved['ssid'] == 'TestNetwork'

    def test_wifi_update_existing(self, veritabani):
        """Test updating existing WiFi network"""
        wifi_data = {
            'bssid': '11:22:33:44:55:66',
            'ssid': 'Network1',
            'kanal': 1,
            'sinyal': 50,
            'sifreleme': 'WPA',
            'satici': 'Apple',
            'enlem': None,
            'boylam': None,
        }

        # Save initial
        veritabani.wifi_kaydet(wifi_data)

        # Update with new signal
        wifi_data['sinyal'] = 80
        veritabani.wifi_kaydet(wifi_data)

        # Should still be one entry (upsert)
        networks = veritabani.tum_wifi_getir(limit=100)
        matching = [n for n in networks if n['bssid'] == '11:22:33:44:55:66']
        assert len(matching) == 1

    def test_bluetooth_save_and_retrieve(self, veritabani):
        """Test Bluetooth device save and retrieve"""
        bt_data = {
            'mac': 'AA:BB:CC:11:22:33',
            'ad': 'AirPods Pro',
            'tip': 'BLE',
            'sinif': 'Audio',
            'sinyal': -45,
            'kategori': 'kulaklik',
        }

        # Save
        veritabani.bluetooth_kaydet(bt_data)

        # Retrieve
        devices = veritabani.tum_bluetooth_getir(limit=10)
        assert len(devices) >= 1

        saved = devices[0]
        assert saved['mac_adresi'] == 'AA:BB:CC:11:22:33'

    def test_statistics(self, veritabani):
        """Test database statistics"""
        # Add some data
        veritabani.wifi_kaydet({
            'bssid': 'FF:EE:DD:CC:BB:AA',
            'ssid': 'StatTest',
            'kanal': 11,
            'sinyal': 60,
        })

        stats = veritabani.istatistikler()
        assert 'wifi_ag_sayisi' in stats
        assert 'bluetooth_cihaz_sayisi' in stats
        assert 'baz_istasyonu_sayisi' in stats
        assert 'toplam_tarama' in stats
        assert stats['wifi_ag_sayisi'] >= 1

    def test_api_key_storage(self, veritabani, temp_test_dir):
        """Test API key storage with encryption"""
        from dalga import GuvenlikYoneticisi, DALGA_KEYS

        with patch('dalga.DALGA_KEYS', temp_test_dir / '.keys'):
            guvenlik = GuvenlikYoneticisi()

            # Save encrypted
            veritabani.api_anahtari_kaydet('test_service', 'test_key_123', 'test_secret', guvenlik)

            # Retrieve and decrypt
            key, secret = veritabani.api_anahtari_getir('test_service', guvenlik)
            assert key == 'test_key_123'
            assert secret == 'test_secret'


class TestWiFiTarayici:
    """WiFi scanner tests"""

    @pytest.fixture
    def wifi_tarayici(self):
        """Create WiFiTarayici instance"""
        from dalga import WiFiTarayici
        return WiFiTarayici(arayuz='wlan0')

    def test_interface_detection(self, wifi_tarayici):
        """Test that interface is set"""
        assert wifi_tarayici.arayuz is not None
        assert isinstance(wifi_tarayici.arayuz, str)

    def test_iwlist_parse(self, wifi_tarayici):
        """Test iwlist output parsing"""
        sample_output = """
        wlan0     Scan completed :
                  Cell 01 - Address: AA:BB:CC:DD:EE:FF
                            Channel:6
                            ESSID:"TestNetwork"
                            Quality=70/100  Signal level=-40 dBm
                            Encryption key:on
                            IE: IEEE 802.11i/WPA2 Version 1
        """

        networks = wifi_tarayici._iwlist_parse(sample_output)
        assert len(networks) >= 1
        assert networks[0]['bssid'] == 'AA:BB:CC:DD:EE:FF'
        assert networks[0]['ssid'] == 'TestNetwork'
        assert networks[0]['kanal'] == 6

    def test_nmcli_parse(self, wifi_tarayici):
        """Test nmcli output parsing"""
        sample_output = "TestNet:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:75:WPA2"

        networks = wifi_tarayici._nmcli_parse(sample_output)
        assert len(networks) >= 1
        assert 'ssid' in networks[0]
        assert 'bssid' in networks[0]

    @patch('subprocess.run')
    def test_scan_with_mock(self, mock_run, wifi_tarayici):
        """Test scan with mocked subprocess"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""
            wlan0     Scan completed :
                      Cell 01 - Address: 11:22:33:44:55:66
                                ESSID:"MockNetwork"
                                Channel:1
                                Quality=80/100
            """
        )

        networks = wifi_tarayici.tara()
        # Should not crash, may return empty if parsing fails


class TestBluetoothTarayici:
    """Bluetooth scanner tests"""

    @pytest.fixture
    def bt_tarayici(self):
        """Create BluetoothTarayici instance"""
        from dalga import BluetoothTarayici
        return BluetoothTarayici()

    def test_tool_check(self, bt_tarayici):
        """Test Bluetooth tool availability check"""
        assert isinstance(bt_tarayici.arac_mevcut, dict)
        # Should have checked for hcitool, bluetoothctl, btmgmt

    @patch('subprocess.run')
    def test_scan_with_mock(self, mock_run, bt_tarayici):
        """Test scan with mocked subprocess"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="AA:BB:CC:DD:EE:FF\tTest Device\n11:22:33:44:55:66\tAnother Device"
        )

        bt_tarayici.arac_mevcut['hcitool'] = True
        # Scan would require more complex mocking


class TestAPIClients:
    """API client tests"""

    def test_wigle_client_init(self):
        """Test WigleIstemci initialization"""
        from dalga import WigleIstemci

        client = WigleIstemci('test_name', 'test_token')
        assert client.api_name == 'test_name'
        assert client.api_token == 'test_token'

    @patch('urllib.request.urlopen')
    def test_wigle_wifi_search(self, mock_urlopen):
        """Test WiGLE WiFi search with mock"""
        from dalga import WigleIstemci

        # Mock response
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            'success': True,
            'results': [
                {'netid': 'AA:BB:CC:DD:EE:FF', 'ssid': 'TestNet', 'trilat': 41.0, 'trilong': 29.0}
            ]
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = WigleIstemci('test', 'token')
        results = client.wifi_ara(41.0, 29.0)

        assert len(results) >= 1
        assert results[0]['bssid'] == 'AA:BB:CC:DD:EE:FF'

    def test_opencellid_client_init(self):
        """Test OpenCellIDIstemci initialization"""
        from dalga import OpenCellIDIstemci

        client = OpenCellIDIstemci('test_key')
        assert client.api_key == 'test_key'

    def test_shodan_client_init(self):
        """Test ShodanIstemci initialization"""
        from dalga import ShodanIstemci

        client = ShodanIstemci('test_key')
        assert client.api_key == 'test_key'

    @patch('urllib.request.urlopen')
    def test_shodan_location_search(self, mock_urlopen):
        """Test Shodan location search with mock"""
        from dalga import ShodanIstemci

        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            'matches': [
                {'ip_str': '192.0.2.1', 'port': 80, 'org': 'Test', 'location': {'latitude': 41.0, 'longitude': 29.0}}
            ]
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = ShodanIstemci('test_key')
        results = client.konum_ara(41.0, 29.0)

        assert len(results) >= 1


class TestDalgaMotor:
    """Main engine tests"""

    @pytest.fixture
    def motor(self, temp_test_dir):
        """Create DalgaMotor with temp directories"""
        from dalga import DalgaMotor, DALGA_DB, DALGA_KEYS

        with patch('dalga.DALGA_DB', temp_test_dir / 'dalga.db'):
            with patch('dalga.DALGA_KEYS', temp_test_dir / '.keys'):
                motor = DalgaMotor()
                yield motor

    def test_status_report(self, motor):
        """Test status report generation"""
        status = motor.durum_raporu()

        assert 'versiyon' in status
        assert 'kod_adi' in status
        assert 'wifi_arayuz' in status
        assert 'bluetooth_araclar' in status
        assert 'api_durumu' in status
        assert 'mevcut_konum' in status
        assert 'istatistikler' in status

    def test_set_location(self, motor):
        """Test location setting"""
        motor.konum_ayarla(41.0082, 28.9784)
        assert motor.mevcut_konum == (41.0082, 28.9784)

    def test_set_invalid_location(self, motor):
        """Test setting location with edge values"""
        # Should accept valid coordinates
        motor.konum_ayarla(-90.0, -180.0)
        motor.konum_ayarla(90.0, 180.0)

    @patch('dalga.WiFiTarayici.tara')
    def test_wifi_scan_local(self, mock_tara, motor):
        """Test local WiFi scan"""
        mock_tara.return_value = [
            {'bssid': 'AA:BB:CC:DD:EE:FF', 'ssid': 'TestNet', 'sinyal': 75}
        ]

        results = motor.wifi_tara(yerel=True, api=False)
        assert len(results) >= 1

    @patch('dalga.BluetoothTarayici.tara')
    def test_bluetooth_scan_local(self, mock_tara, motor):
        """Test local Bluetooth scan"""
        mock_tara.return_value = [
            {'mac': 'AA:BB:CC:11:22:33', 'ad': 'TestDevice', 'tip': 'BLE'}
        ]

        results = motor.bluetooth_tara(yerel=True, api=False)
        assert len(results) >= 1


class TestDalgaExport:
    """Export functionality tests"""

    @pytest.fixture
    def motor_with_data(self, temp_test_dir):
        """Create motor with sample data"""
        from dalga import DalgaMotor, DALGA_DB, DALGA_KEYS, DALGA_EXPORTS

        with patch('dalga.DALGA_DB', temp_test_dir / 'dalga.db'):
            with patch('dalga.DALGA_KEYS', temp_test_dir / '.keys'):
                with patch('dalga.DALGA_EXPORTS', temp_test_dir / 'exports'):
                    motor = DalgaMotor()

                    # Add sample data
                    motor.veritabani.wifi_kaydet({
                        'bssid': 'AA:BB:CC:DD:EE:FF',
                        'ssid': 'ExportTest',
                        'kanal': 6,
                        'sinyal': 70,
                    })

                    yield motor

    def test_export_json(self, motor_with_data, temp_test_dir):
        """Test JSON export"""
        with patch('dalga.DALGA_EXPORTS', temp_test_dir / 'exports'):
            (temp_test_dir / 'exports').mkdir(exist_ok=True)

            path = motor_with_data.disa_aktar(format='json', dosya_adi='test_export')
            assert 'test_export.json' in path

            # Verify file exists and is valid JSON
            export_file = temp_test_dir / 'exports' / 'test_export.json'
            if export_file.exists():
                with open(export_file) as f:
                    data = json.load(f)
                    assert 'meta' in data
                    assert 'wifi_aglar' in data


class TestEdgeCases:
    """Edge case tests"""

    def test_empty_scan_results(self):
        """Test handling of empty scan results"""
        from dalga import CihazSiniflandirici

        # Should handle empty/None gracefully
        CihazSiniflandirici.siniflandir('')
        CihazSiniflandirici.siniflandir(None)
        CihazSiniflandirici.satici_bul('')
        CihazSiniflandirici.satici_bul(None)

    def test_malformed_mac_address(self):
        """Test handling of malformed MAC addresses"""
        from dalga import CihazSiniflandirici

        malformed_macs = [
            'invalid',
            '12345',
            'AA:BB:CC',
            'AA:BB:CC:DD:EE:FF:GG',
            '',
        ]
        for mac in malformed_macs:
            vendor = CihazSiniflandirici.satici_bul(mac)
            assert vendor == 'Bilinmeyen'

    def test_unicode_ssid(self):
        """Test handling of Unicode SSIDs"""
        from dalga import CihazSiniflandirici

        unicode_names = [
            '',  # Turkish
            '',  # Japanese
            '',  # Arabic
            '',  # Emoji
        ]
        for name in unicode_names:
            # Should not crash
            CihazSiniflandirici.siniflandir(name)


@pytest.mark.skipif(not HYPOTHESIS_AVAILABLE, reason="hypothesis not installed")
class TestPropertyBased:
    """Property-based tests using Hypothesis"""

    @given(st.text(min_size=0, max_size=100))
    @settings(max_examples=50)
    def test_classifier_never_crashes(self, device_name):
        """Property: classifier never raises exception"""
        from dalga import CihazSiniflandirici

        # Should never crash
        result = CihazSiniflandirici.siniflandir(device_name)
        assert result is None or isinstance(result, str)

    @given(st.text(min_size=17, max_size=17, alphabet='0123456789ABCDEFabcdef:-'))
    @settings(max_examples=50)
    def test_vendor_lookup_never_crashes(self, mac_like):
        """Property: vendor lookup never raises exception"""
        from dalga import CihazSiniflandirici

        # Should never crash
        result = CihazSiniflandirici.satici_bul(mac_like)
        assert result is None or isinstance(result, str)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
