import hashlib
import json
import socket
from enum import Enum

import ecdsa
import requests
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigencode_der, sigdecode_der
from mnemonic import Mnemonic

from common.logging import logger


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


@singleton
class Transaction:

    def __init__(self, node_url=None):
        self.node_url = node_url
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host, port = self.node_url.split(":")
        self.socket.connect((host, int(port)))

    def get_fee(self, tx_type, gas_price, gas_limit):
        base_fee = 1.0
        try:
            print("Fetching transaction pool")
            # http request to get the number of transactions in the transaction pool
            self.socket.sendall(json.dumps({
                'type': 'READ_TRANSACTION_POOL'
            }).encode())
            response = json.loads(self.socket.recv(1024 * 1024 * 10).decode())
            print("Transaction pool fetched: ", response)

            json_response = response.get('content')
            transaction_pool = json_response.get('transactions')

            # Calculate the congestion factor
            congestion_factor = len(transaction_pool) / 100
        except:
            congestion_factor = 0
        new_fee = base_fee * (1 + congestion_factor)

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
                           data=None
                           ):

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
            signature=None,
            method_call=method_call,
            args=args
        )


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

    def to_dict(self):
        transaction_dict = {
            'tx_type': self.tx_type.value,
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'fee': self.fee,
            'signature': self.signature.hex() if self.signature else None,
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


class CryptoUtils:

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
            raise TypeError("Invalid public key provided.")

        # Verifying the ECDSA signature
        try:
            return public_key.verify(signature, transaction, hashfunc=hashlib.sha256, sigdecode=sigdecode_der)
        except ecdsa.BadSignatureError:
            return False

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


class Wallet:
    def __init__(self, node_url=None, from_seed_phrase=False):
        self.mnemonic = Mnemonic("english")
        self.transactions = []
        self.node_url = node_url
        self.socket = None
        # check if class have attr
        if not from_seed_phrase:
            self.private_key = None
            self.public_key = None
            self.address = None
            self.restore_from_seed_phrase(instance=self)

    def get_socket(self):
        return self.socket

    @staticmethod
    def generate_seed_phrase():
        mnemonic = Mnemonic("english")
        seed_phrase = mnemonic.generate(strength=128)
        return seed_phrase

    def get_private_key(self):
        return self.private_key.to_string().hex()

    def get_public_key(self):
        # Get the uncompressed format of the public key
        return self.public_key.to_string("uncompressed").hex()

    def get_address(self):
        # Get the address from the public key
        return self.address

    @classmethod
    def restore_from_seed_phrase(cls, seed_phrase=None, instance=None):
        if not seed_phrase:
            seed_phrase = cls.generate_seed_phrase()
            # Save seed phrase to file
            with open("seed_phrase.txt", "w") as f:
                f.write(seed_phrase)
        if not Mnemonic("english").check(seed_phrase):
            raise ValueError("Invalid seed phrase")

        # Generate seed from mnemonic
        seed = Bip39SeedGenerator(seed_phrase).Generate()

        # Create a Bip44 object (BIP-44: hierarchical deterministic wallets)
        bip_obj = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)

        # Get the private key (in bytes) at the BIP-44 standard path for the first account and first address
        private_key_bytes = bip_obj.PrivateKey().Raw().ToBytes()

        # Create an ECDSA private key from the bytes
        private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        if instance:
            instance.private_key = private_key
            instance.public_key = private_key.get_verifying_key()
            instance.address = bip_obj.PublicKey().ToAddress()
        else:
            wallet = cls(from_seed_phrase=True, node_url="http://localhost:5000")
            wallet.private_key = private_key
            wallet.public_key = private_key.get_verifying_key()
            wallet.address = bip_obj.PublicKey().ToAddress()
            return wallet
        print("===========================================")
        print("Seed phrase:", seed_phrase)
        print("Private key:", private_key.to_string().hex())
        print("Public key:", private_key.get_verifying_key().to_string("uncompressed").hex())
        print("Address:", bip_obj.PublicKey().ToAddress())
        print("===========================================")

    def set_node_url(self, node_url):
        self.node_url = node_url
        host, port = self.node_url.split(":")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, int(port)))

    def sign_message(self, message):
        if isinstance(message, str):
            message = message.encode()
        signature = self.private_key.sign(message)
        return signature.hex()

    def verify_signature(self, message, signature, public_key=None):
        if isinstance(message, str):
            message = message.encode()
        if isinstance(signature, str):
            signature = bytes.fromhex(signature)
        public_key = public_key or self.public_key
        verifying_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
        return verifying_key.verify(signature, message)

    def get_balance(self):
        self.socket.sendall(json.dumps({
            'type': 'READ_BALANCE',
            'address': self.address
        }).encode())
        response = json.loads(self.socket.recv(1024).decode())

        return response

    def send_funds(self, to_address, amount, token):

        self.get_transaction_history()

        transaction = Transaction(node_url=self.node_url).create_transaction(
            sender=self.address,
            recipient=to_address,
            amount=amount,
            tx_type=TransactionType.SIMPLE,
            nonce=len(self.transactions) + 1,
            data={
                'type': 'transfer',
                'token_symbol': token
            }
        )

        # Sign the transaction with the void address' private key
        transaction.sign(self.private_key, self.public_key)

        print("======= CURRENT PUBLIC KEY =======")
        print(self.public_key.to_string("uncompressed").hex())
        print("==================================")

        # Convert transaction to dict and to json
        tx = transaction.to_dict()
        tx = json.dumps(tx)

        logger.debug(f"Sending transaction: {tx}")

        content = {
            'transaction': tx,
            'public_key': self.public_key.to_string("uncompressed").hex()
        }

        self.socket.sendall(json.dumps({
            'type': 'NEW_TRANSACTION',
            'content': content
        }).encode())

        response = json.loads(self.socket.recv(1024).decode())

        return response

    def get_transaction_history(self):
        self.socket.sendall(json.dumps({
            'type': 'READ_TRANSACTIONS',
            'content': {
                'address': self.address
            }
        }).encode())

        response = json.loads(self.socket.recv(1024 * 1024 * 10).decode())

        logger.debug(f"Received READ_TRANSACTIONS response: {response}")
        transactions = response.get('content').get('transactions')

        self.transactions = transactions
        return transactions

    def stake_funds(self, amount, token):
        # Get the stake address
        self.socket.sendall(json.dumps({
            "type": "READ_NODE_ADDRESS",
            "content": ""
        }).encode())
        response = json.loads(self.socket.recv(1024).decode())
        stake_address = response.get('content').get('node_address')

        self.get_transaction_history()

        transaction = Transaction(node_url=self.node_url).create_transaction(
            sender=self.address,
            recipient=stake_address,
            amount=amount,
            tx_type=TransactionType.STAKING,
            nonce=len(self.transactions) + 1,
            data={
                'type': 'stake',
                'token_symbol': token
            }
        )
        # Sign the transaction with the void address' private key
        transaction.sign(self.private_key, self.public_key)

        tx = transaction.to_dict()
        tx = json.dumps(tx)

        self.socket.sendall(json.dumps({
            'type': 'NEW_TRANSACTION',
            'content': {
                'transaction': tx,
                'public_key': self.public_key.to_string("uncompressed").hex()
            }
        }).encode())

        response = json.loads(self.socket.recv(1024).decode())

        return response

    def unstake_funds(self, amount, token):
        # TODO
        # Get the stake address
        response = requests.get(f"{self.node_url}/node/stake_address")
        stake_address = response.json().get('stake_address')

        transaction = Transaction(node_url=self.node_url).create_transaction(
            sender=self.address,
            recipient=stake_address,
            amount=amount,
            tx_type=TransactionType.STAKING,
            nonce=len(self.transactions) + 1,
            data={
                'type': 'unstake',
                'token_symbol': token
            }
        )
        # Sign the transaction with the void address' private key
        transaction.sign(self.private_key, self.public_key)

        content = {
            'transaction': transaction.to_dict(),
            'public_key': self.public_key.to_string("uncompressed").hex()
        }

        response = requests.post(f"{self.node_url}/transactions/new", json=content)
