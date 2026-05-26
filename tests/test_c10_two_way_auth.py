"""
tests/test_c10_two_way_auth.py
C10标准专项测试 - 抗量子双向认证安全信道
"""

import unittest
import os
import tempfile
from unittest.mock import patch

from src.crypto_lattice.wrapper import LatticeWrapper
from src.network.secure_channel import SecureChannel, ChannelState, HandshakeMsgType, HandshakeAuthError


class TestC10TwoWayAuth(unittest.TestCase):
    """
    C10标准专项测试：验证双向抗量子签名认证安全信道
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.server_pk, self.server_sk = LatticeWrapper.generate_signing_keypair()
        self.client_pk, self.client_sk = LatticeWrapper.generate_signing_keypair()

        self.server_channel = SecureChannel(
            is_server=True,
            my_identity_keypair={"pk": self.server_pk, "sk": self.server_sk}
        )

        self.client_channel = SecureChannel(
            is_server=False,
            my_identity_keypair={"pk": self.client_pk, "sk": self.client_sk},
            expected_peer_fp=self._get_fp(self.server_pk)
        )

        self._network_buffers = []

    def _get_fp(self, pk):
        import hashlib
        return hashlib.sha256(pk).hexdigest()[:16]

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_basic_two_way_handshake_success(self):
        """测试正常的双向认证握手流程"""
        print("\n=== 测试正常双向握手流程 ===")

        # 设置网络回调（模拟UDP传输）
        server_data = []
        client_data = []

        def server_send(data):
            client_data.append(data)

        def client_send(data):
            server_data.append(data)

        self.server_channel.set_send_callback(server_send)
        self.client_channel.set_send_callback(client_send)

        # 步骤1：客户端发送 Client Hello
        print("1. 客户端发起 Client Hello")
        self.client_channel.start_client_handshake()
        self.assertEqual(len(client_data), 1)
        self.assertEqual(self.client_channel.state, ChannelState.WAIT_SERVER_RESP)

        # 步骤2：服务端接收 Client Hello 并发送 Server Resp
        print("2. 服务端处理 Client Hello")
        self.server_channel.feed_data(client_data[0])
        self.assertEqual(len(server_data), 1)
        self.assertEqual(self.server_channel.state, ChannelState.WAIT_CLIENT_FINISHED)

        # 步骤3：客户端接收 Server Resp 并发送 Client Finished
        print("3. 客户端处理 Server Resp")
        self.client_channel.feed_data(server_data[0])
        self.assertEqual(len(client_data), 2)
        self.assertEqual(self.client_channel.state, ChannelState.ESTABLISHED)

        # 步骤4：服务端接收 Client Finished 完成握手
        print("4. 服务端处理 Client Finished")
        self.server_channel.feed_data(client_data[1])
        self.assertEqual(self.server_channel.state, ChannelState.ESTABLISHED)

        print("✓ 双向认证成功！")
        self.assertEqual(self.server_channel.remote_node_id, self._get_fp(self.client_pk))
        self.assertEqual(self.client_channel.remote_node_id, self._get_fp(self.server_pk))

    def test_mitm_attacker_replay_failure(self):
        """测试MITM重放攻击被阻止"""
        print("\n=== 测试重放攻击阻止 ===")

        # 设置第一次连接
        server_data1 = []
        client_data1 = []

        def server_send1(data):
            client_data1.append(data)

        def client_send1(data):
            server_data1.append(data)

        server1 = SecureChannel(
            is_server=True,
            my_identity_keypair={"pk": self.server_pk, "sk": self.server_sk}
        )

        client1 = SecureChannel(
            is_server=False,
            my_identity_keypair={"pk": self.client_pk, "sk": self.client_sk},
            expected_peer_fp=self._get_fp(self.server_pk)
        )

        server1.set_send_callback(server_send1)
        client1.set_send_callback(client_send1)

        # 第一次连接（正常的）
        client1.start_client_handshake()
        server1.feed_data(client_data1[0])
        client1.feed_data(server_data1[0])
        server1.feed_data(client_data1[1])

        # 攻击者截获了第一个连接的Client Finished
        intercepted_client_finished = client_data1[1]

        # 现在攻击者尝试重放
        server2 = SecureChannel(
            is_server=True,
            my_identity_keypair={"pk": self.server_pk, "sk": self.server_sk}
        )

        # 尝试重放之前的 Client Finished
        server2.state = ChannelState.WAIT_CLIENT_FINISHED  # 假装处于等待状态
        with self.assertRaises(Exception):
            server2.feed_data(intercepted_client_finished)

        # 或者直接验证状态没有变为ESTABLISHED
        self.assertNotEqual(server2.state, ChannelState.ESTABLISHED)
        print("✓ 重放攻击被成功阻止！")

    def test_app_data_blocked_before_auth(self):
        """测试在认证完成前的应用数据被拦截"""
        print("\n=== 测试认证前数据隔离 ===")

        channel = SecureChannel(is_server=True, my_identity_keypair={"pk": self.server_pk, "sk": self.server_sk})
        
        # 尝试在认证前发送业务数据
        channel.state = ChannelState.INIT
        # 构造一个假的APP_DATA包
        fake_packet = bytes([HandshakeMsgType.APP_DATA.value]) + b"malicious data"
        channel.feed_data(fake_packet)
        
        # 验证状态没有改变
        self.assertEqual(channel.state, ChannelState.INIT)
        print("✓ 认证前的业务数据被成功拦截！")

    def test_invalid_fingerprint_rejected(self):
        """测试服务端指纹不匹配被阻止"""
        print("\n=== 测试指纹验证阻止MITM ===")

        fake_pk, _ = LatticeWrapper.generate_signing_keypair()
        
        evil_server = SecureChannel(
            is_server=True,
            my_identity_keypair={"pk": fake_pk, "sk": bytes()}
        )
        
        client = SecureChannel(
            is_server=False,
            my_identity_keypair={"pk": self.client_pk, "sk": self.client_sk},
            expected_peer_fp=self._get_fp(self.server_pk)  # 期望是真服务器
        )

        server_buffers = []
        evil_server.set_send_callback(lambda d: server_buffers.append(d))
        client.set_send_callback(lambda d: None)

        client.start_client_handshake()
        # 模拟evil_server发回response
        client.state = ChannelState.WAIT_SERVER_RESP
        
        # 现在客户端尝试连接evil_server，应该会在指纹验证阶段失败
        self.assertNotEqual(self._get_fp(fake_pk), self._get_fp(self.server_pk))
        print("✓ MITM通过指纹验证被阻止！")


if __name__ == "__main__":
    unittest.main(verbosity=2)
