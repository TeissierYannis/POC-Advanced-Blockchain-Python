import socket
import time

from common.json import send_json_message
from common.logging import logger
from networking.handlers.base_handler import BaseHandler


class ReadTransactionPool(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)

    def handle(self, message_content, connection):
        """
        :param message_content:
        :param connection:
        :return:
        """
        logger.info(f"Received READ_CHAIN message from {connection.getpeername()}")

        response = {
            'transactions': self.peer.blockchain.transaction_pool.read_transactions(),
            'length': len(self.peer.blockchain.transaction_pool.read_transactions()),
        }

        send_json_message(connection, 'READ_TRANSACTION_POOL_RESPONSE', response)
