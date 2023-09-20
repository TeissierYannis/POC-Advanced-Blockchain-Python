import unittest
from unittest import TestCase
from unittest.mock import Mock, patch
from cryptography.hazmat.primitives import serialization

from core.blockchain import Blockchain, CryptoUtils, Wallet, TransactionPool


class TestWalletMethods(TestCase):
    def setUp(self):
        self.transaction_pool = TransactionPool()
        self.sample_transactions = [
            {'sender': 'Alice', 'recipient': 'Bob', 'amount': 10},
            {'sender': 'Bob', 'recipient': 'Charlie', 'amount': 20},
            {'sender': 'Charlie', 'recipient': 'Alice', 'amount': 30},
            {'sender': 'Alice', 'recipient': 'Charlie', 'amount': 40},
            {'sender': 'Bob', 'recipient': 'Alice', 'amount': 50}
        ]

    def test_add_transaction(self):
        self.transaction_pool.add_transaction(self.sample_transactions[0])
        self.assertEqual(self.transaction_pool.transactions, [self.sample_transactions[0]])

    def test_get_transactions_with_default_limit(self):
        self.transaction_pool.transactions = self.sample_transactions.copy()
        transactions_to_move = self.transaction_pool.get_transactions()
        self.assertEqual(transactions_to_move, self.sample_transactions[:10])
        self.assertEqual(self.transaction_pool.transactions, self.sample_transactions[10:])

    def test_get_transactions_with_custom_limit(self):
        self.transaction_pool.transactions = self.sample_transactions.copy()
        transactions_to_move = self.transaction_pool.get_transactions(3)
        self.assertEqual(transactions_to_move, self.sample_transactions[:3])
        self.assertEqual(self.transaction_pool.transactions, self.sample_transactions[3:])

    def test_get_transactions_with_empty_pool(self):
        transactions_to_move = self.transaction_pool.get_transactions()
        self.assertEqual(transactions_to_move, [])
        self.assertEqual(self.transaction_pool.transactions, [])


if __name__ == '__main__':
    unittest.main()
