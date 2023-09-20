import unittest
from unittest import TestCase
from unittest.mock import patch

from core.blockchain import Transaction, CryptoUtils, AccountManager, TransactionPool, Blockchain


class TestTransactionMethods(TestCase):

    def setUp(self):
        self.transaction_pool = TransactionPool()
        self.account_manager = AccountManager()
        self.blockchain = Blockchain(self.transaction_pool, self.account_manager)
        self.transaction = Transaction()
        self.transaction.set_blockchain(self.blockchain)
        self.transaction.set_transaction_pool(self.transaction_pool)

    def test_verify_transaction_valid(self):
        sender = 'sender_public_key'
        recipient = 'recipient_public_key'
        amount = 10
        private_key, public_key = CryptoUtils.generate_key_pair()
        signature = CryptoUtils.sign_transaction({'sender': sender, 'recipient': recipient, 'amount': amount},
                                                 private_key)

        # Mocking get_balance to return a valid balance
        with patch.object(AccountManager, 'get_balance', return_value=20):
            self.assertTrue(self.transaction.verify_transaction(sender, recipient, amount, signature, public_key))

    def test_verify_transaction_invalid(self):
        sender = 'sender_public_key'
        recipient = 'recipient_public_key'
        amount = -10  # Invalid amount
        private_key, public_key = CryptoUtils.generate_key_pair()
        signature = CryptoUtils.sign_transaction({'sender': sender, 'recipient': recipient, 'amount': amount},
                                                 private_key)

        self.assertFalse(self.transaction.verify_transaction(sender, recipient, amount, signature, public_key))

    def test_new_transaction(self):
        sender = 'sender_public_key'
        recipient = 'recipient_public_key'
        amount = 10
        private_key, public_key = CryptoUtils.generate_key_pair()
        signature = CryptoUtils.sign_transaction({'sender': sender, 'recipient': recipient, 'amount': amount},
                                                 private_key)

        # Mocking get_balance to return a valid balance
        with patch.object(AccountManager, 'get_balance', return_value=20):
            self.assertTrue(self.transaction.new_transaction(sender, recipient, amount, signature, public_key))

    def test_apply_transactions(self):
        # Mocking current_transactions to simulate a block of transactions
        self.blockchain.current_transactions = [
            {'sender': 'Alice', 'recipient': 'Bob', 'amount': 5},
            {'sender': 'Bob', 'recipient': 'Charlie', 'amount': 2},
        ]

        # Mocking account balances
        self.account_manager.accounts = {'Alice': 10, 'Bob': 5, 'Charlie': 0}

        self.transaction.apply_transactions()

        # Check if the account balances are updated correctly
        self.assertEqual(self.account_manager.accounts['Bob'], 8)
        self.assertEqual(self.account_manager.accounts['Alice'], 5)
        self.assertEqual(self.account_manager.accounts['Charlie'], 2)


if __name__ == '__main__':
    unittest.main()
