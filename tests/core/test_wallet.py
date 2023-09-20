import unittest
from unittest import TestCase
from unittest.mock import Mock, patch
from cryptography.hazmat.primitives import serialization

from core.blockchain import Blockchain, CryptoUtils, Wallet


class TestWalletMethods(TestCase):
    def setUp(self):
        self.blockchain_mock = Mock()
        self.transaction_manager_mock = Mock()
        self.private_key_mock, self.public_key_mock = CryptoUtils.generate_key_pair()

        self.wallet = Wallet(self.blockchain_mock)
        self.wallet.transaction_manager = self.transaction_manager_mock
        self.wallet.private_key = self.private_key_mock
        self.wallet.public_key = self.public_key_mock

    def test_get_balance(self):
        public_key_str = self.public_key_mock.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.blockchain_mock.accounts = {public_key_str: 100}
        balance = self.wallet.get_balance()
        self.assertEqual(balance, 100)

    def test_send_funds(self):
        recipient = 'recipient_address'
        amount = 50
        signature = 'signature'

        with patch.object(CryptoUtils, 'sign_transaction', return_value=signature):
            result = self.wallet.send_funds(recipient, amount)

        self.transaction_manager_mock.new_transaction.assert_called_once()
        self.assertTrue(result)

    def test_get_public_key(self):
        public_key_pem = self.public_key_mock.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        self.assertEqual(self.wallet.get_public_key(), public_key_pem)

    def test_get_private_key(self):
        private_key_pem = self.private_key_mock.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        self.assertEqual(self.wallet.get_private_key(), private_key_pem)


if __name__ == '__main__':
    unittest.main()
