import unittest
from unittest import TestCase
from unittest.mock import Mock, patch
from cryptography.hazmat.primitives import serialization

from core.blockchain import Blockchain, CryptoUtils, Wallet, AccountManager


class TestWalletMethods(TestCase):
    def setUp(self):
        self.account_manager = AccountManager()
        self.sample_transaction1 = {'sender': 'Alice', 'recipient': 'Bob', 'amount': 10}
        self.sample_transaction2 = {'sender': 'Bob', 'recipient': 'Charlie', 'amount': 5}

    def test_update_accounts_new_accounts(self):
        self.account_manager.update_accounts(self.sample_transaction1)
        self.assertEqual(self.account_manager.accounts, {'Alice': -10, 'Bob': 10})

    def test_update_accounts_existing_accounts(self):
        self.account_manager.accounts = {'Alice': 20, 'Bob': 5}
        self.account_manager.update_accounts(self.sample_transaction1)
        self.assertEqual(self.account_manager.accounts, {'Alice': 10, 'Bob': 15})

    def test_get_balance_existing_account(self):
        self.account_manager.accounts = {'Alice': 20}
        balance = self.account_manager.get_balance('Alice')
        self.assertEqual(balance, 20)

    def test_get_balance_new_account(self):
        balance = self.account_manager.get_balance('Bob')
        self.assertEqual(balance, 0)


if __name__ == '__main__':
    unittest.main()
