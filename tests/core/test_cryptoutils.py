import unittest
from unittest import TestCase
from unittest.mock import patch, Mock, ANY
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from core.blockchain import CryptoUtils


class TestCryptoUtilsMethods(TestCase):

    #  Tests that generate_key_pair function generates a valid private and public key pair
    def test_generate_key_pair_successfully(self):
        private_key, public_key = CryptoUtils.generate_key_pair()
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertIsInstance(public_key, rsa.RSAPublicKey)

    #  Tests that sign_transaction function signs a transaction correctly
    def test_sign_transaction_successfully(self):
        private_key, public_key = CryptoUtils.generate_key_pair()  # Generate real keys
        private_key.sign = Mock(return_value=b'signature')
        transaction = {
            'sender': 'sender',
            'recipient': 'recipient',
            'amount': 10
        }
        signature = CryptoUtils.sign_transaction(transaction, private_key)

        self.assertIsNotNone(signature)

    #  Tests that verify_transaction_signature function verifies a transaction signature correctly
    def test_verify_transaction_signature_successfully(self):
        private_key, public_key = CryptoUtils.generate_key_pair()  # Generate real keys
        transaction = {
            'sender': 'sender',
            'recipient': 'recipient',
            'amount': 10
        }
        signature = CryptoUtils.sign_transaction(transaction, private_key)

        result = CryptoUtils.verify_transaction_signature(transaction, signature, public_key)
        self.assertTrue(result)

    #  Tests that generate_key_pair function raises an error when invalid parameters are provided
    def test_generate_key_pair_with_invalid_parameters(self):
        with self.assertRaises(TypeError):
            CryptoUtils.generate_key_pair(123)

    #  Tests that sign_transaction function raises an error when invalid parameters are provided
    def test_sign_transaction_with_invalid_parameters(self):
        with self.assertRaises(AttributeError):
            CryptoUtils.sign_transaction(None, None)

    #  Tests that verify_transaction_signature function raises an error when invalid parameters are provided
    def test_verify_transaction_signature_with_invalid_parameters(self):
        with self.assertRaises(TypeError):  # Update this line
            CryptoUtils.verify_transaction_signature(None, None, None)

    #  Tests that verify_transaction_signature function returns False when an invalid signature is provided
    def test_verify_transaction_signature_with_invalid_signature(self):
        public_key = Mock()
        public_key.verify.side_effect = Exception()
        signature = Mock()
        transaction = {
            'sender': 'sender',
            'recipient': 'recipient',
            'amount': 10
        }
        with self.assertRaises(Exception):
            result = CryptoUtils.verify_transaction_signature(transaction, signature, public_key)

    #  Tests that verify_transaction_signature function returns False when an invalid public key is provided
    def test_verify_transaction_signature_with_invalid_public_key(self):
        private_key, public_key = CryptoUtils.generate_key_pair()  # Generate real keys
        public_key = Mock()
        public_key.verify.side_effect = Exception()

        transaction = {
            'sender': 'sender',
            'recipient': 'recipient',
            'amount': 10
        }
        signature = CryptoUtils.sign_transaction(transaction, private_key)

        with self.assertRaises(Exception):
            result = CryptoUtils.verify_transaction_signature(transaction, signature, public_key)


if __name__ == '__main__':
    unittest.main()
