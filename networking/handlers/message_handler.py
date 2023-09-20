import json

from common.logging import logger
from common.singleton import singleton
from networking.handlers.discover_handler import DiscoverHandler
from networking.handlers.hello_handler import HelloHandler
from networking.handlers.message_content_handler import MessageContentHandler
from networking.handlers.new_transaction_handler import NewTransactionHandler
from networking.handlers.ping_handler import PingHandler
from networking.handlers.pong_handler import PongHandler
from networking.handlers.read_balance_handler import ReadBalanceHandler
from networking.handlers.read_chain_handler import ReadChainHandler
from networking.handlers.read_node_address_handler import ReadNodeAddressHandler
from networking.handlers.read_nodes_handler import ReadNodesHandler
from networking.handlers.read_transaction_pool import ReadTransactionPool
from networking.handlers.read_transactions_handler import ReadTransactionsHandler
from networking.handlers.sync_transaction_pool_handler import SyncTransactionPoolHandler


@singleton
class MessageHandler:
    def __init__(self, peer):
        if not hasattr(self, 'peer'):
            self.peer = peer
        self.handlers = {
            "HELLO": HelloHandler(peer),
            "PING": PingHandler(peer),
            "PONG": PongHandler(peer),
            "MESSAGE": MessageContentHandler(peer),
            "DISCOVER": DiscoverHandler(peer),
            "READ_CHAIN": ReadChainHandler(peer),
            "READ_BALANCE": ReadBalanceHandler(peer),
            "NEW_TRANSACTION": NewTransactionHandler(peer),
            "READ_TRANSACTION_POOL": ReadTransactionPool(peer),
            "SYNC_TRANSACTION_POOL": SyncTransactionPoolHandler(peer),
            "READ_NODES": ReadNodesHandler(peer),
            "READ_TRANSACTIONS": ReadTransactionsHandler(peer),
            "READ_NODE_ADDRESS": ReadNodeAddressHandler(peer),
        }

    def handle(self, data, connection):
        try:
            message_data = json.loads(data.decode('utf-8'))
            handler = self.handlers.get(message_data.get('type'))
            if handler:
                handler.handle(message_data.get('content'), connection)
            else:
                logger.error(f"Unknown message type: {message_data.get('type')}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON message: {str(e)} {data}")