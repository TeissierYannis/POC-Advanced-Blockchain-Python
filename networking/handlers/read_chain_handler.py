import socket
import time

from common.json import send_json_message
from common.logging import logger
from networking.handlers.base_handler import BaseHandler


class ReadChainHandler(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)

    def handle(self, message_content, connection):
        """
        :param message_content:
        :param connection:
        :return:
        """
        logger.info(f"Received READ_CHAIN message from {connection.getpeername()}")

        result = {
            'chain': self.peer.blockchain.chain,
            'length': len(self.peer.blockchain.chain)
        }

        send_json_message(connection, 'READ_CHAIN_RESPONSE', result)
