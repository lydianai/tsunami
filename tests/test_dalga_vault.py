"""
TSUNAMI - dalga_vault.py Test Suite
TsunamiVault AES-256-GCM encryption tests
"""

import os
import pytest
import tempfile
from unittest.mock import patch, MagicMock
from pathlib import Path
from datetime import datetime, timedelta


class TestTsunamiVault:
    """TsunamiVault sınıfı testleri"""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Her test için temiz vault dizini"""
        self.vault_dir = tmp_path / ".vault"
        with patch('dalga_vault.TsunamiVault.VAULT_DIR', self.vault_dir), \
             patch('dalga_vault.TsunamiVault.VAULT_FILE', self.vault_dir / "secrets.vault"), \
             patch('dalga_vault.TsunamiVault.MASTER_KEY_FILE', self.vault_dir / ".master.key"):
            from dalga_vault import TsunamiVault
            self.vault = TsunamiVault(master_password="TestPassword123!")
            yield

    def test_vault_initialization(self):
        """Vault başlatılmalı"""
        assert self.vault._initialized is True
        assert self.vault._master_key is not None

    def test_vault_directory_created(self):
        """Vault dizini oluşturulmalı"""
        assert self.vault_dir.exists()

    def test_encrypt_decrypt_roundtrip(self):
        """Şifreleme/çözme döngüsü çalışmalı"""
        plaintext = "super-secret-api-key-12345"
        ciphertext, nonce, salt = self.vault._encrypt(plaintext)

        assert ciphertext != plaintext.encode()
        assert len(nonce) == 12  # GCM nonce

        decrypted = self.vault._decrypt(ciphertext, nonce, salt)
        assert decrypted == plaintext

    def test_encrypt_produces_different_output(self):
        """Aynı veri farklı nonce/salt ile farklı şifrelenecek"""
        plaintext = "same-data"
        ct1, n1, s1 = self.vault._encrypt(plaintext)
        ct2, n2, s2 = self.vault._encrypt(plaintext)

        assert ct1 != ct2  # Farklı ciphertext
        assert n1 != n2    # Farklı nonce

    def test_store_and_retrieve_secret(self):
        """Secret sakla ve geri al"""
        self.vault.store("api_key", "my-secret-key-value")
        result = self.vault.retrieve("api_key")
        assert result == "my-secret-key-value"

    def test_store_overwrite(self):
        """Mevcut secret üzerine yazılmalı"""
        self.vault.store("key", "value1")
        self.vault.store("key", "value2")
        assert self.vault.retrieve("key") == "value2"

    def test_get_nonexistent(self):
        """Olmayan secret None dönmeli"""
        result = self.vault.retrieve("nonexistent")
        assert result is None

    def test_delete_secret(self):
        """Secret silinebilmeli"""
        self.vault.store("temp_key", "temp_value")
        assert self.vault.retrieve("temp_key") == "temp_value"
        self.vault.delete("temp_key")
        assert self.vault.retrieve("temp_key") is None

    def test_list_secrets(self):
        """Secret listesi alınabilmeli"""
        self.vault.store("key1", "val1")
        self.vault.store("key2", "val2")
        names = self.vault.list_secrets()
        assert "key1" in names
        assert "key2" in names

    def test_unicode_content(self):
        """Unicode içerik şifrelenebilmeli"""
        plaintext = "Türkçe şifre: Özel karakterler ğüşıöç"
        self.vault.store("tr_key", plaintext)
        assert self.vault.retrieve("tr_key") == plaintext


class TestEncryptedSecret:
    """EncryptedSecret dataclass testleri"""

    def test_creation(self):
        from dalga_vault import EncryptedSecret
        secret = EncryptedSecret(
            name="test",
            ciphertext=b"encrypted",
            nonce=b"nonce12bytes",
            salt=b"salt" * 8,
            created_at=datetime.now()
        )
        assert secret.name == "test"
        assert secret.version == 1
        assert secret.expires_at is None


class TestVaultWithoutPassword:
    """Şifresiz vault (auto key) testleri"""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        vault_dir = tmp_path / ".vault"
        with patch('dalga_vault.TsunamiVault.VAULT_DIR', vault_dir), \
             patch('dalga_vault.TsunamiVault.VAULT_FILE', vault_dir / "secrets.vault"), \
             patch('dalga_vault.TsunamiVault.MASTER_KEY_FILE', vault_dir / ".master.key"):
            from dalga_vault import TsunamiVault
            self.vault = TsunamiVault()
            yield

    def test_auto_key_generation(self):
        """Otomatik key oluşturulmalı"""
        assert self.vault._initialized is True
        assert self.vault._master_key is not None
        assert len(self.vault._master_key) == 32

    def test_roundtrip_auto_key(self):
        """Auto key ile şifreleme/çözme çalışmalı"""
        self.vault.store("auto_key", "auto_value")
        assert self.vault.retrieve("auto_key") == "auto_value"
