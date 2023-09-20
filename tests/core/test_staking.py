import unittest
from unittest import TestCase
from unittest.mock import Mock, patch

from core.blockchain import CryptoUtils, Staking


class TestStakingMethods(TestCase):
    def setUp(self):
        self.blockchain_mock = Mock()
        self.transaction_manager_mock = Mock()
        self.staking = Staking(self.blockchain_mock)
        self.staking.transaction_manager = self.transaction_manager_mock

    def test_add_stake_successfully(self):
        blockchain = Mock()
        blockchain.account_manager.get_balance.return_value = 100
        self.staking.blockchain = blockchain

        private_key, public_key = CryptoUtils.generate_key_pair()

        result = self.staking.add_stake("node_address", 50, public_key, private_key)

        self.assertTrue(result)
        self.transaction_manager_mock.new_transaction.assert_called()

    def test_add_stake_insufficient_balance(self):
        self.blockchain_mock.account_manager.get_balance.return_value = 40

        result = self.staking.add_stake("node_address", 50, None, None)

        self.assertFalse(result)

    def test_choose_block_creator(self):
        self.staking.stakeholders = {'node1': 50, 'node2': 50}
        with patch('random.randint', return_value=49):
            result = self.staking.choose_block_creator()

        self.assertEqual(result, 'node1')

    def test_choose_block_creator_no_stakeholders(self):
        self.staking.stakeholders = {}

        result = self.staking.choose_block_creator()

        self.assertIsNone(result)

    def test_remove_stake_successfully(self):
        self.staking.stakeholders = {'node_address': 100}
        self.blockchain_mock.account_manager.get_private_key.return_value = Mock()
        self.blockchain_mock.account_manager.get_public_key.return_value = Mock()

        result = self.staking.remove_stake("node_address", 50)

        self.assertTrue(result)
        self.transaction_manager_mock.new_transaction.assert_called()

    def test_remove_stake_insufficient_stake(self):
        self.staking.stakeholders = {'node_address': 40}

        result = self.staking.remove_stake("node_address", 50)

        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
