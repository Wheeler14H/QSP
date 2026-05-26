import os
import json
import base64
import tempfile
import unittest
from cryptography.exceptions import InvalidTag

# 假设你的项目根目录在 sys.path 中
from src.app.vault_crypto import VaultCrypto, PasswordAuthError

class TestQSPVaultSecurityMechanisms(unittest.TestCase):
    """
    QSP 系统 C4 (抵御物理攻破) 与 C9 (及时的密码错误检测) 标准的安全性综合测试
    """

    def setUp(self):
        """
        测试前置准备：创建一个安全的临时目录，隔离真实的系统文件
        """
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = self.temp_dir.name
        
        # 隔离的测试文件路径
        self.salt_path = os.path.join(self.temp_path, ".vault_salt")
        self.verifier_path = os.path.join(self.temp_path, ".vault_verifier")
        self.identity_path = os.path.join(self.temp_path, "node_identity.dat")
        
        # 模拟的用户密码
        self.correct_password = "SuperSecretPassword_2026!"
        self.wrong_password = "SuperSecretPassword_2026?"  # 模拟错打了一个符号

    def tearDown(self):
        """
        测试清理：销毁临时目录
        """
        self.temp_dir.cleanup()

    # ==========================================
    # 测试环节 1: 验证 C9 标准 (密码输入错误拦截)
    # ==========================================

    def test_01_first_run_initialization(self):
        """测试首次运行能否正确生成盐值和 HMAC 验证器"""
        vault = VaultCrypto(
            password=self.correct_password, 
            salt_path=self.salt_path, 
            verifier_path=self.verifier_path
        )
        self.assertTrue(os.path.exists(self.salt_path), "盐值文件未能成功落盘")
        self.assertTrue(os.path.exists(self.verifier_path), "HMAC验证器未能成功落盘")
        
        # 检查生成的文件是否有数据
        self.assertEqual(os.path.getsize(self.salt_path), 16)
        self.assertEqual(os.path.getsize(self.verifier_path), 32) # SHA256 length

    def test_02_password_auth_success(self):
        """测试使用正确密码能够顺利通过 HMAC 校验进入系统"""
        # 1. 模拟首次运行建立金库
        VaultCrypto(self.correct_password, self.salt_path, self.verifier_path)
        
        # 2. 模拟第二次启动，使用相同的密码
        try:
            vault_reloaded = VaultCrypto(self.correct_password, self.salt_path, self.verifier_path)
            self.assertIsNotNone(vault_reloaded.key, "派生主密钥失败")
        except PasswordAuthError:
            self.fail("正确密码不应触发 PasswordAuthError 异常")

    def test_03_password_auth_rejection(self):
        """测试使用错误密码会立即触发熔断 (防御错字和爆破)"""
        # 1. 模拟首次运行建立金库
        VaultCrypto(self.correct_password, self.salt_path, self.verifier_path)
        
        # 2. 模拟第二次启动，输入了错误的密码
        with self.assertRaises(PasswordAuthError) as context:
            VaultCrypto(self.wrong_password, self.salt_path, self.verifier_path)
            
        self.assertIn("主密码错误", str(context.exception))

    # ==========================================
    # 测试环节 2: 验证 C4 标准 (静态数据加密与防篡改)
    # ==========================================

    def test_04_identity_encryption_and_decryption(self):
        """测试身份私钥的二进制加解密完整生命周期"""
        vault = VaultCrypto(self.correct_password, self.salt_path, self.verifier_path)
        
        # 模拟内存中的明文身份 JSON (包含假设的 Dilithium 私钥)
        dummy_identity = {
            "node_id": "test_node_001",
            "pk": "dummy_public_key_base64",
            "sk": "dummy_secret_key_base64_which_is_very_secret"
        }
        plaintext_bytes = json.dumps(dummy_identity).encode('utf-8')
        
        # 1. 执行加密
        encrypted_data = vault.encrypt_data(plaintext_bytes)
        
        # 验证密文长度：12(Nonce) + 明文长度 + 16(Tag)
        expected_len = 12 + len(plaintext_bytes) + 16
        self.assertEqual(len(encrypted_data), expected_len)
        
        # 2. 模拟写盘与读盘
        with open(self.identity_path, "wb") as f:
            f.write(encrypted_data)
            
        with open(self.identity_path, "rb") as f:
            loaded_encrypted_data = f.read()
            
        # 3. 执行解密并验证内容
        decrypted_bytes = vault.decrypt_data(loaded_encrypted_data)
        restored_identity = json.loads(decrypted_bytes.decode('utf-8'))
        
        self.assertEqual(restored_identity["sk"], dummy_identity["sk"], "解密出的私钥与原始私钥不一致！")

    def test_05_tamper_resistance_invalid_tag(self):
        """测试密文被物理篡改时的防御机制 (触发 InvalidTag)"""
        vault = VaultCrypto(self.correct_password, self.salt_path, self.verifier_path)
        
        original_data = b"Some highly classified quantum-safe secrets."
        encrypted_data = bytearray(vault.encrypt_data(original_data))
        
        # 模拟黑客试图篡改密文 (改变密文中的第 15 个字节)
        encrypted_data[15] ^= 0x01  # 翻转一个比特位
        
        # 当被篡改的密文送入解密器时，AES-GCM 的 Tag 校验必定失败
        with self.assertRaises(InvalidTag):
            vault.decrypt_data(bytes(encrypted_data))

    def test_06_tamper_resistance_truncated_file(self):
        """测试硬盘损坏导致文件截断的防御机制"""
        vault = VaultCrypto(self.correct_password, self.salt_path, self.verifier_path)
        encrypted_data = vault.encrypt_data(b"Short data")
        
        # 截断文件，破坏末尾的 Authentication Tag
        truncated_data = encrypted_data[:-5] 
        
        with self.assertRaises((InvalidTag, ValueError)):
            vault.decrypt_data(truncated_data)

if __name__ == "__main__":
    unittest.main(verbosity=2)
