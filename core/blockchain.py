import hashlib
import json
import random
from enum import Enum
from time import time

import ecdsa
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_der, sigencode_der
from web3 import Web3

from common.logging import logger

BLOCK_GAS_LIMIT = 1000000
INITIAL_NODE_IP = "127.0.0.1"
INITIAL_NODE_PORT = 5000
TIME_BETWEEN_BLOCKS = 120  # seconds


class TransactionType(Enum):
    SIMPLE = 1
    STAKING = 2
    CREATE_TOKEN = 3
    CONTRACT_DEPLOY = 4
    CONTRACT_EXECUTION = 5


def singleton(class_):
    instances = {}

    def get_instance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]

    return get_instance


class MerkleTree:
    def __init__(self, transaction_list):
        self.transaction_list = transaction_list
        self.tree = []
        self.create_tree()

    def create_tree(self):
        tx_hashes = [hashlib.sha256(str(tx).encode('utf-8')).hexdigest() for tx in self.transaction_list]
        # if no transaction return empty hash
        if len(tx_hashes) == 0:
            tx_hashes.append(hashlib.sha256(''.encode('utf-8')).hexdigest())

        self.tree.append(tx_hashes)
        while len(tx_hashes) != 1:
            tx_hashes = self.hash_pair(tx_hashes)
            self.tree.append(tx_hashes)

    def hash_pair(self, tx_hashes):
        new_hash_list = []
        # Pairwise hash the elements in the list
        for i in range(0, len(tx_hashes) - 1, 2):
            new_hash = hashlib.sha256((tx_hashes[i] + tx_hashes[i + 1]).encode('utf-8')).hexdigest()
            new_hash_list.append(new_hash)
        # If the list has an odd length, hash the last element with itself
        if len(tx_hashes) % 2 == 1:
            new_hash = hashlib.sha256((tx_hashes[-1] + tx_hashes[-1]).encode('utf-8')).hexdigest()
            new_hash_list.append(new_hash)
        return new_hash_list

    def get_merkle_proof(self, tx_index):
        proof = []
        index = tx_index
        for level in self.tree[:-1]:  # Exclude the root
            if index % 2 == 0:
                sibling_index = index + 1
                direction = 'right'
            else:
                sibling_index = index - 1
                direction = 'left'

            # Add the sibling hash to the proof (if it exists)
            if sibling_index < len(level):
                proof.append((level[sibling_index], direction))
            else:
                proof.append((None, direction))

            # Move up the tree
            index = index // 2
        return proof

    def get_root(self):
        return self.tree[-1][0]


class CryptoUtils:

    @staticmethod
    def generate_key_pair():
        # Generating ECDSA key pair with der encoding
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()

        return private_key, public_key

    @staticmethod
    def sign_transaction(transaction, private_key):
        # Ensure the transaction is a dictionary before proceeding
        if not isinstance(transaction, dict):
            raise TypeError("Invalid transaction provided.")

        # Serialize and encode the transaction for signing
        transaction = json.dumps(transaction, sort_keys=True).encode()

        # Creating a SigningKey object for ECDSA signing
        if not isinstance(private_key, ecdsa.keys.SigningKey):
            raise TypeError("Invalid private key provided.")

        # Signing the transaction using ECDSA
        signature = private_key.sign(transaction, hashfunc=hashlib.sha256, sigencode=sigencode_der)

        return signature

    @staticmethod
    def verify_transaction_signature(transaction, signature, public_key):
        # Ensure the transaction is a dictionary before proceeding
        if not isinstance(transaction, dict):
            raise TypeError("Invalid transaction provided.")

        # Serialize and encode the transaction for verification
        transaction = json.dumps(transaction, sort_keys=True).encode()

        # Creating a VerifyingKey object for ECDSA verification
        if not isinstance(public_key, ecdsa.keys.VerifyingKey):
            try:
                # convert this string to hex
                public_key_bytes = bytes.fromhex(public_key)
                public_key = VerifyingKey.from_string(public_key_bytes[1:], curve=SECP256k1)
            except:
                raise TypeError("Invalid public key provided.")

        # Check if signature is bytes
        if not isinstance(signature, bytes):
            try:
                signature = bytes.fromhex(signature)
            except:
                raise TypeError("Invalid signature provided.")

        # Verifying the ECDSA signature
        try:
            logger.debug(f"Verifying signature {signature} for transaction {transaction}")
            return public_key.verify(signature, transaction, hashfunc=hashlib.sha256, sigdecode=sigdecode_der)
        except ecdsa.BadSignatureError:
            raise ValueError("Invalid signature. Transaction was not signed by the provided public key.")

    @staticmethod
    def get_v_r_s(signature, public_key):
        """Get the v, r, s values from the ECDSA signature."""
        if not isinstance(public_key, ecdsa.keys.VerifyingKey):
            raise TypeError("Invalid public key provided." + str(public_key))
        # Get the r, s values from the signature
        r, s = sigdecode_der(signature, public_key.pubkey.curve)
        # You can compute v using other means if necessary
        v = 27  # This is a placeholder, you'd have to find the correct way to compute v
        return v, r, s

    @classmethod
    def verify_v_r_s(cls, signature, public_key, v, r, s):
        vb, rb, sb = cls.get_v_r_s(signature, public_key)
        return vb == v and rb == r and sb == s

    @staticmethod
    def recover_public_key(message, signature, curve=SECP256k1):
        if isinstance(message, str):
            message = message.encode()

        # Hash the message
        message_hash = hashlib.sha256(message).digest()

        if isinstance(signature, str):
            signature = bytes.fromhex(signature)

        for i in range(0, 4):
            try:
                vk = VerifyingKey.from_public_key_recovery_with_digest(
                    signature, message_hash, curve, hashfunc=hashlib.sha256, sigdecode=sigdecode_der
                )
                return vk
            except ecdsa.BadSignatureError:
                continue
        return None


@singleton
class Blockchain:
    def __init__(self,
                 token_name='MyToken',
                 token_symbol='MTK',
                 initial_supply=1000000,
                 decimals=18,
                 void_address="0x00000000000000000000000000000000000000",
                 initial_addresses=[{
                     "address": "0x00000000000000000000000000000000000000",
                     "percent": 1
                 }]
                 ):
        # If there is no actual instance of Blockchain, create one
        self.token_name = token_name
        self.token_symbol = token_symbol
        self.initial_supply = initial_supply
        self.decimals = decimals
        self.void_address = void_address
        self.initial_addresses = initial_addresses

        self.chain = []
        self.current_transactions = []
        self.nodes = []
        self.nodes.append(
            Node(
                wallet_address="TODO",
                ip=INITIAL_NODE_IP,
                port=INITIAL_NODE_PORT,
                public_key="TODO"
            )
        )

        self.transaction_pool = TransactionPool()

        Transaction().set_transaction_pool(self.transaction_pool)
        self.token_registry = TokenRegistry()

        # Remove the initial wallet creation here
        self.create_genesis_block()

    def get_balance(self, address, token_symbol):
        # Search through the chain to find a transaction involving the address
        balance = 0
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['data'].get('token_symbol') == token_symbol:
                    if transaction['recipient'] == address:
                        balance += transaction['amount']
                    elif transaction['sender'] == address:
                        balance -= transaction['amount']
        return balance

    def replace_chain(self, new_chain):
        tmp_chain = self.chain
        self.chain = new_chain
        for block in self.chain:
            if not self.validate_block(block):
                self.chain = tmp_chain
                raise ValueError("Invalid chain.")

    def get_transactions_count(self, address):
        count = 0
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['sender'] == address:
                    count += 1
        return count

    def get_merkle_proof_for_tx(self, transaction_hash=None):
        block, tx_index, transaction = self.get_transaction_details(transaction_hash)
        if block is None:
            return None, None, None

        merkle_tree = MerkleTree(block['transactions'])
        proof = merkle_tree.get_merkle_proof(tx_index)
        return proof, tx_index, merkle_tree.get_root()

    def get_transaction_details(self, transaction_hash=None):
        for block in self.chain:
            transactions = block['transactions']
            for i, transaction in enumerate(transactions):
                tx_hash = hashlib.sha256(str(transaction).encode('utf-8')).hexdigest()
                if tx_hash == transaction_hash:
                    return block, i, transaction
        return None, None, None

    def create_genesis_block(self):
        """
        Create the Genesis Block without initial distribution of tokens.
        """
        private_key, public_key = CryptoUtils.generate_key_pair()

        # Create a transaction to assign the initial supply to the void address
        self.create_token(self.void_address, self.token_name, self.token_symbol, self.initial_supply, self.decimals)
        # Dispatch initial tokens to the initial addresses (if any)
        if self.initial_addresses is not None:
            # Check if the sum of each % do not exceed 100%
            if sum([initial['percent'] for initial in self.initial_addresses]) > 1:
                raise ValueError("The sum of each initial address percentage cannot exceed 100%.")
            for initial in self.initial_addresses:
                transaction = Transaction().create_transaction(
                    sender=self.token_registry.get_token_details(self.token_symbol)['token_address'],
                    recipient=initial['address'],
                    amount=self.initial_supply * initial['percent'],
                    tx_type=TransactionType.SIMPLE,
                    nonce=0,
                    data={
                        'type': 'transfer',
                        'token_symbol': self.token_symbol
                    }
                )
                # Sign the transaction with the void address' private key
                transaction.sign(private_key, public_key)
                # Create a new transaction
                result = Transaction().new_transaction(
                    transaction
                )

        # Create the Genesis Block
        block = self.new_block(previous_hash='1', block_creator=self.void_address, skip_validation=True)

        return block

    def new_transaction(self, transaction, public_key):
        verify = Validator().verify_transaction(transaction, public_key, self)
        if len(self.chain) > 0 and verify != True:
            raise ValueError(verify)
        # Create a new transaction
        result = Transaction().new_transaction(
            transaction
        )

        # return tx hash
        return result

    def create_token(self, sender, token_name, token_symbol, initial_supply, decimals=18):
        result = self.token_registry.get_token_details(token_symbol)
        # If result throws an error, the token already exists
        if result:
            raise ValueError("Token already exists.")
        # Generate address for the token
        token_address = self.generate_contract_address()

        transaction = Transaction().create_transaction(
            tx_type=TransactionType.CREATE_TOKEN,
            sender=self.void_address,
            recipient=token_address,
            amount=initial_supply * (10 ** decimals),
            nonce=0,
            data={
                'type': 'initial_supply',
                'token_name': token_name,
                'token_symbol': token_symbol,
                'decimals': decimals
            }
        )

        # Sign and add the transaction to the transaction pool
        private_key, public_key = CryptoUtils.generate_key_pair()
        transaction.sign(private_key, public_key)
        self.transaction_pool.add_transaction(transaction.to_dict())

        token_detail = {
            'name': token_name,
            'initial_supply': initial_supply * (10 ** decimals),
            'decimals': decimals,
            'creator': sender,
            'total_supply': initial_supply * (10 ** decimals),
            'token_address': token_address
        }

        self.token_registry.add_token(token_symbol, token_detail)

    def get_token_details(self, token_symbol):
        # Search through the chain to find a transaction involving the token
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['data'].get('token_symbol') == token_symbol and transaction['type'] == "initial_supply":
                    return transaction['data']
        return None

    def get_state_root(self):
        # Find all the account balances for each token by iterating through the chain
        accounts = {}
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['data']['type'] == "initial_supply":
                    token_symbol = transaction['data']['token_symbol']
                    accounts[token_symbol] = accounts.get(token_symbol, 0) + transaction['amount']
                elif transaction['data']['type'] == "transfer":
                    token_symbol = transaction['data']['token_symbol']
                    accounts[token_symbol] = accounts.get(token_symbol, 0) + transaction['amount']
                elif transaction['data']['type'] == "stake":
                    token_symbol = transaction['data']['token_symbol']
                    accounts[token_symbol] = accounts.get(token_symbol, 0) + transaction['amount']
                elif transaction['data']['type'] == "unstake":
                    token_symbol = transaction['data']['token_symbol']
                    accounts[token_symbol] = accounts.get(token_symbol, 0) + transaction['amount']

        # Sort the accounts by token symbol
        sorted_accounts = sorted(accounts.items(), key=lambda x: x[0])

        # Create a string representation of the accounts
        accounts_string = json.dumps(sorted_accounts, sort_keys=True)

        # Hash the string representation
        return hashlib.sha256(accounts_string.encode('utf-8')).hexdigest()

    def new_block(self, previous_hash=None, block_creator=None, skip_validation=False):
        self.move_transactions_from_pool()
        merkle = MerkleTree(self.current_transactions)
        block = {
            'block_number': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
            'creator': block_creator,
            'fees': sum([tx['fee'] for tx in self.current_transactions]),
            'transactionsRoot': merkle.get_root(),
            'stateRoot': self.get_state_root(),
            'receiptRoot': self.get_receipt_root()
        }
        logger.info(f"Merkle root for block {block['block_number']}: {block['transactionsRoot']}")

        if self.validate_block(block) or skip_validation:
            logger.info(f"Block {block['block_number']} added to the chain.")
            self.chain.append(block)

            # Create a transaction to assign the initial supply to the void address
            transaction = Transaction().create_transaction(
                sender=self.void_address,
                recipient=block_creator,
                amount=block['fees'],
                tx_type=TransactionType.SIMPLE,
                nonce=0,
                data={
                    'type': 'transfer',
                    'token_symbol': self.token_symbol
                }
            )
            private_key, public_key = CryptoUtils.generate_key_pair()
            # Sign the transaction with the void address' private key
            transaction.sign(private_key, public_key)
            # Create a new transaction
            result = Transaction().new_transaction(
                transaction
            )
            self.current_transactions = []
            return block
        else:
            self.current_transactions = []
            raise ValueError("Invalid block. Not added to the chain.")

    def get_receipt_root(self):
        total_fees = sum([tx['fee'] for tx in self.current_transactions])
        total_amounts = sum([tx['amount'] for tx in self.current_transactions])
        receipt_string = json.dumps({"fees": total_fees, "amounts": total_amounts}, sort_keys=True)
        receipt_hash = hashlib.sha256(receipt_string.encode()).hexdigest()
        return receipt_hash

    def validate_block(self, block):
        last_block = self.last_block
        logger.info(f"Validating block {block['block_number']} with previous hash {block['previous_hash']}")
        if last_block is None:
            if block['block_number'] != 1:
                logger.error("No blocks in the chain.")
                return False
        else:
            if last_block['block_number'] + 1 != block['block_number']:
                logger.error("Invalid block number.")
                return False

            if self.hash(last_block) != block['previous_hash']:
                logger.error("Invalid previous hash.")
                return False

        total_gas_used = sum(tx['gas_limit'] for tx in block['transactions'])
        if total_gas_used > BLOCK_GAS_LIMIT:
            logger.error("Block gas limit exceeded.")
            return False

        # Validate that the block creator is the correct stakeholder
        if block['block_number'] > 1:
            chosen_creator = self.choose_node_validator()
            if block['creator'] != chosen_creator:
                logger.error("Invalid block creator :", block['creator'], "should be :", chosen_creator)
                return False

            # Validate Merkle Proofs for all transactions in the block
            for tx in block['transactions']:
                # Get the transaction hash
                tx_hash = hashlib.sha256(str(tx).encode('utf-8')).hexdigest()
                self.chain.append(block)
                # Get the Merkle proof for the transaction
                proof, tx_index, root = self.get_merkle_proof_for_tx(tx_hash)

                # Verify the Merkle proof
                if not self.verify_merkle_proof(proof, tx_hash, root):
                    logger.error(f"Invalid Merkle proof for transaction {tx_hash}.")
                    self.chain.pop()
                    return False
                self.chain.pop()

        return True

    def verify_merkle_proof(self, proof, tx_hash, root):
        """Verify the Merkle proof for a transaction.

        Parameters:
            proof (list): The Merkle proof for the transaction.
            tx_hash (str): The hash of the transaction.
            root (str): The root hash of the Merkle tree.

        Returns:
            bool: True if the proof is valid, False otherwise.
        """
        if proof is None or tx_hash is None or root is None:
            return False

        merkle_proof_hash = tx_hash
        logger.info(f"Verifying Merkle proof for transaction {tx_hash} with root {root} and proof {proof}")

        for proof_elem, direction in proof:
            logger.info(f"Hashing {merkle_proof_hash} and {proof_elem}")

            # Correctly order the concatenation based on the direction
            if direction == 'left':
                concat_data = proof_elem + merkle_proof_hash
            else:
                concat_data = merkle_proof_hash + proof_elem

            # Hash the concatenated data
            merkle_proof_hash = hashlib.sha256(concat_data.encode()).hexdigest()

        # The final hash should match the Merkle root if the proof is valid
        return merkle_proof_hash == root

    def move_transactions_from_pool(self, max_transactions=10):
        self.current_transactions.extend(self.transaction_pool.get_transactions(max_transactions))

    def generate_contract_address(self):
        """Generate a unique address for a new contract."""
        # 20 bytes of 0s
        return Web3.to_checksum_address('0x' + hashlib.sha256(str(time()).encode()).hexdigest()[:40])

    def get_nodes(self):
        return self.nodes

    def get_node(self, address):
        for validator in self.nodes:
            if validator.get_address() == address:
                return validator
        return None

    def get_node_balance(self, address, token_symbol):
        return self.get_balance(address, token_symbol)

    def get_nodes_balances(self, token_symbol):
        balances = {}
        for validator in self.nodes:
            balances[validator.get_address()] = self.get_node_balance(validator.get_address(), token_symbol)
        return balances

    def choose_node_validator(self):
        # Check if there is more than one validator
        if len(self.nodes) == 0:
            raise ValueError("No validators in the network.")

        # check if the time between blocks is greater than the time between blocks, reference is the timestamp of the genesis block
        if len(self.chain) > 0:
            ref = self.chain[0]['timestamp']
            if time() - ref < TIME_BETWEEN_BLOCKS:
                raise ValueError("Time between blocks is too low.")

        # Choose a validator based on stake
        balances = self.get_nodes_balances(self.token_symbol)
        total_stake = sum(balances.values())
        # Init the dict with the validators addresses and their % of the total stake and balances
        nodes = {validator.get_address(): {'percent': 0, 'balance': balances[validator.get_address()]} for validator in
                 self.nodes}
        # Set a % for each validator based on their stake and the total stake
        for validator in self.nodes:
            nodes[validator.get_address()]['percent'] = nodes[validator.get_address()]['balance'] / total_stake

        # Choose a random number between 0 and 1
        random_number = random.random()
        # Iterate through the validators and choose the one whose % is greater than the random number
        for validator in self.nodes:
            if nodes[validator.get_address()]['percent'] > random_number:
                return validator.get_address()
            else:
                random_number -= nodes[validator.get_address()]['percent']
        return None

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        if len(self.chain) == 0:
            return None
        return self.chain[-1]

    def get_blocks(self):
        return self.chain

    def get_block(self, block_number):
        for block in self.chain:
            if block['block_number'] == block_number:
                return block
        return None

    def get_balances(self):
        """
        Return the balances of all accounts in the system with all tokens.
        """
        balances = {}
        for block in self.chain:
            for transaction in block['transactions']:
                token_symbol = transaction['data']['token_symbol']
                if transaction['recipient'] not in balances:
                    balances[transaction['recipient']] = {}
                if token_symbol not in balances[transaction['recipient']]:
                    balances[transaction['recipient']][token_symbol] = 0
                balances[transaction['recipient']][token_symbol] += transaction['amount']
                if transaction['sender'] not in balances:
                    balances[transaction['sender']] = {}
                if token_symbol not in balances[transaction['sender']]:
                    balances[transaction['sender']][token_symbol] = 0
                balances[transaction['sender']][token_symbol] -= transaction['amount']
        return balances

    def add_node(self, ip, port, address, public_key):
        logger.info(f"Adding node {address} with ip {ip} and port {port}")
        self.nodes.append(
            Node(
                wallet_address=address,
                ip=ip,
                port=port,
                public_key=public_key
            )
        )
        logger.info(f"Nodes: {self.nodes}")

    def remove_node(self, address):
        for node in self.nodes:
            if node.get_address() == address:
                self.nodes.remove(node)
                return True
        return False

    def get_all_balances(self, address):
        """
        Return the balances of all accounts in the system with all tokens.
        """
        balances = {}
        for block in self.chain:
            for transaction in block['transactions']:
                token_symbol = transaction['data']['token_symbol']
                if transaction['recipient'] not in balances:
                    balances[transaction['recipient']] = {}
                if token_symbol not in balances[transaction['recipient']]:
                    balances[transaction['recipient']][token_symbol] = 0
                balances[transaction['recipient']][token_symbol] += transaction['amount']
                if transaction['sender'] not in balances:
                    balances[transaction['sender']] = {}
                if token_symbol not in balances[transaction['sender']]:
                    balances[transaction['sender']][token_symbol] = 0
                balances[transaction['sender']][token_symbol] -= transaction['amount']
        return balances[address]

    def get_transactions(self, address):
        """
        Return the balances of all accounts in the system with all tokens.
        """
        transactions = []
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['recipient'] == address or transaction['sender'] == address:
                    transactions.append(transaction)
        return transactions


@singleton
class Transaction:

    def __init__(self):
        self.transaction_pool = None

    def set_transaction_pool(self, transaction_pool):
        self.transaction_pool = transaction_pool

    def get_fee(self, tx_type, gas_price, gas_limit):
        base_fee = 1.0
        congestion_factor = len(self.transaction_pool.read_transactions()) / 100
        new_fee = base_fee * (1 + congestion_factor)

        logger.debug(f"[DEBUG] Congestion factor: {congestion_factor}")
        # if it's an int then, find the enum
        tx_type = TransactionType(tx_type)

        if tx_type == TransactionType.SIMPLE:
            base_fee = new_fee
        elif tx_type == TransactionType.STAKING:
            base_fee = new_fee + 1
        elif tx_type == TransactionType.CREATE_TOKEN:
            base_fee = new_fee + 5
        else:
            raise ValueError("Invalid transaction type.")

        # Calculate the final fee using the gas price and gas limit
        final_fee = base_fee * gas_price

        return min(final_fee, gas_limit)

    def create_transaction(self,
                           sender,
                           recipient,
                           amount,
                           tx_type=TransactionType.SIMPLE,
                           contract_code=None,
                           nonce=None,
                           gas_price=1,
                           gas_limit=21000,
                           method_call=None,
                           args=None,
                           v=None,
                           r=None,
                           s=None,
                           init=None,
                           data=None,
                           signature=None):

        fee = self.get_fee(tx_type, gas_price, gas_limit)

        return UnifiedTransaction(
            tx_type=tx_type,
            sender=sender,
            recipient=recipient,
            amount=amount,
            fee=fee,
            nonce=nonce,
            gas_price=gas_price,
            gas_limit=gas_limit,
            v=v,
            r=r,
            s=s,
            init=init,
            data=data,
            contract_code=contract_code,
            signature=signature,
            method_call=method_call,
            args=args
        )

    def __str__(self):
        return str(self.__dict__)

    def new_transaction(self, unified_transaction):
        self.transaction_pool.add_transaction(unified_transaction.to_dict())
        return True


class Validator:
    def verify_balance_integrity(self):
        # Step 1: Verify the stateRoot in each block is correct
        for block in self.blockchain.chain:
            # Recreate the stateRoot from the account balances at this point in time
            calculated_state_root = self.blockchain.account_manager.get_state_root()

            # Compare it with the stateRoot stored in the block
            if calculated_state_root != block['stateRoot']:
                logger.error(f"[State root mismatch in block {block['block_number']}.")
                return False

        # Step 2: Verify the total supply of the tokens
        total_supply_in_system = sum(self.blockchain.account_manager.accounts.values())
        if total_supply_in_system != self.blockchain.initial_supply:
            logger.error("Total supply mismatch.")
            return False

        logger.info("User balance integrity verified.")
        return True

    def is_valid_gas_limit(self, gas_limit):
        if gas_limit < 0 or gas_limit > BLOCK_GAS_LIMIT:
            return False
        return True

    def is_valid_gas_price(self, gas_price):
        if gas_price < 0:
            return False
        return True

    def verify_transaction(self, unified_transaction, public_key, blockchain):

        # verify the sender and recipient are not the same, also the amount is not 0
        if unified_transaction.sender == unified_transaction.recipient or unified_transaction.amount == 0:
            return "Invalid transaction."

        transaction_without_signature = unified_transaction.to_dict()
        transaction_without_signature.pop('signature')
        transaction_without_signature.pop('v')
        transaction_without_signature.pop('r')
        transaction_without_signature.pop('s')

        signature = unified_transaction.signature

        logger.debug(f"Signature: {unified_transaction.signature} Public key: {public_key}")

        if not isinstance(public_key, ecdsa.keys.VerifyingKey):
            try:
                # convert this string to hex
                public_key_bytes = bytes.fromhex(public_key)
                public_key = VerifyingKey.from_string(public_key_bytes[1:], curve=SECP256k1)
            except:
                raise TypeError("Invalid public key provided.")

        # Check if signature is bytes
        if not isinstance(signature, bytes):
            try:
                signature = bytes.fromhex(signature)
            except:
                raise TypeError("Invalid signature provided.")

        # Verify the signature
        try:
            CryptoUtils.verify_transaction_signature(
                transaction_without_signature,
                signature,
                public_key)
        except ValueError as e:
            raise ValueError(e)

        if not CryptoUtils.verify_v_r_s(
                signature,
                public_key,
                unified_transaction.v,
                unified_transaction.r,
                unified_transaction.s):
            return "Invalid v, r, s values."

        if unified_transaction.tx_type == TransactionType.CREATE_TOKEN or unified_transaction.tx_type == TransactionType.SIMPLE or unified_transaction.tx_type == TransactionType.STAKING:
            # We need to have the token_symbol in the data field
            if unified_transaction.data is None or unified_transaction.data.get('token_symbol') is None:
                return "Invalid token symbol."

        # Verify the amount and fee
        # if is string, convert it to float
        if isinstance(unified_transaction.amount, str):
            logger.info(f"Transaction amount : {unified_transaction.amount} is string.")
            unified_transaction.amount = float(unified_transaction.amount)
        if isinstance(unified_transaction.fee, str):
            logger.info("Transaction fee : {unified_transaction.fee} is string.")
            unified_transaction.fee = float(unified_transaction.fee)
        total_amount = unified_transaction.amount + unified_transaction.fee
        if total_amount <= 0:
            return "Invalid amount."

        # Verify sender's balance
        sender_balance = blockchain.get_balance(unified_transaction.sender,
                                                unified_transaction.data['token_symbol']
                                                )
        if sender_balance < total_amount:
            return "Insufficient balance."

        # Verify the gas price and gas limit (you will need to set acceptable limits)
        if not self.is_valid_gas_price(unified_transaction.gas_price) or not self.is_valid_gas_limit(
                unified_transaction.gas_limit):
            return "Invalid gas price or gas limit."

        return True


class TransactionPool:
    def __init__(self):
        self.transactions = []

    def add_transaction(self, transaction):
        self.transactions.append(transaction)

    def read_transactions(self):
        return self.transactions

    def get_transactions(self, max_transactions=10):
        transactions_to_move = self.transactions[:max_transactions]
        self.transactions = self.transactions[max_transactions:]
        return transactions_to_move


class UnifiedTransaction:
    def __init__(self,
                 tx_type,
                 sender=None,
                 recipient=None,
                 amount=None,
                 signature=None,
                 nonce=None,
                 gas_price=1,
                 gas_limit=21000,
                 v=None,
                 r=None,
                 s=None,
                 init=None,
                 data=None,
                 fee=0.0,
                 contract_code=None,
                 method_call=None,
                 args=None):
        self.tx_type = tx_type
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature
        self.nonce = nonce
        self.gas_price = gas_price
        self.gas_limit = gas_limit
        self.v = v
        self.r = r
        self.s = s
        self.init = init
        self.data = data
        self.contract_code = contract_code
        self.fee = fee
        self.method_call = method_call
        self.args = args

    def sign(self, private_key, public_key):
        transaction_as_dict = {
            'tx_type': self.tx_type.value,
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'fee': self.fee,
            'nonce': self.nonce,
            'gas_price': self.gas_price,
            'gas_limit': self.gas_limit,
            'v': self.v,
            'r': self.r,
            's': self.s,
            'init': self.init,
            'data': self.data,
            'contract_code': self.contract_code,
            'method_call': self.method_call,
            'args': self.args
        }

        transaction_as_dict = {k: v for k, v in transaction_as_dict.items() if v is not None}

        # Generate signature
        self.signature = CryptoUtils.sign_transaction(transaction_as_dict, private_key)

        # Get v, r, s values from the signature
        self.v, self.r, self.s = CryptoUtils.get_v_r_s(self.signature, public_key)

    def recover_transaction_signer(self):
        transaction_as_dict = {
            'tx_type': self.tx_type.value,
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'fee': self.fee,
            'nonce': self.nonce,
            'gas_price': self.gas_price,
            'gas_limit': self.gas_limit,
            'v': None,
            'r': None,
            's': None,
            'init': self.init,
            'data': self.data,
            'contract_code': self.contract_code,
            'method_call': self.method_call,
            'args': self.args
        }

        transaction_as_dict = {k: v for k, v in transaction_as_dict.items() if v is not None}
        tx = json.dumps(transaction_as_dict, sort_keys=True).encode()

        recovered_public_key = CryptoUtils.recover_public_key(
            message=tx,
            signature=self.signature,
            curve=SECP256k1
        )

        for i, vk in enumerate(recovered_public_key):
            # try to match the recovered public key with the sender by verifying the signature
            if CryptoUtils.verify_transaction_signature(
                    transaction_as_dict,
                    self.signature,
                    vk):
                return vk
        return None

    def to_dict(self):
        # if tx type is int, convert it to enum
        if isinstance(self.tx_type, int):
            self.tx_type = TransactionType(self.tx_type)

        # check the type of the signature, if it's bytes, convert it to hex
        if isinstance(self.signature, bytes):
            self.signature = self.signature.hex()

        transaction_dict = {
            'tx_type': self.tx_type.value,
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'fee': self.fee,
            'signature': self.signature,
            'nonce': self.nonce,
            'gas_price': self.gas_price,
            'gas_limit': self.gas_limit,
            'v': self.v,
            'r': self.r,
            's': self.s,
            'init': self.init,
            'data': self.data,
            'contract_code': self.contract_code,
            'method_call': self.method_call,
            'args': self.args
        }

        return {k: v for k, v in transaction_dict.items() if v is not None}


class TokenRegistry:
    def __init__(self):
        self.tokens = {}

    def add_token(self, symbol, details):
        self.tokens[symbol] = details

    def get_token_details(self, symbol):
        return self.tokens.get(symbol, None)

    def list_all_tokens(self):
        return self.tokens.keys()

    def update_token_details(self, symbol, new_details):
        self.tokens[symbol] = new_details


class Node:
    def __init__(self, ip, port, wallet_address, public_key):
        # self.ip = ip
        self.ip = "127.0.0.1"
        self.port = port
        self.address = wallet_address
        self.public_key = public_key

    def __str__(self):
        return f"Validator at {self.ip}:{self.port} with address {self.address}"

    def __repr__(self):
        return f"Validator at {self.ip}:{self.port} with address {self.address}"

    def get_proxy(self):
        return f"{self.ip}:{self.port}"

    def get_public_key(self):
        return self.public_key

    def get_address(self):
        return self.address

    # allow serialization to json
    def to_dict(self):
        return {
            "ip": self.ip,
            "port": self.port,
            "address": self.address,
            "public_key": self.public_key
        }
