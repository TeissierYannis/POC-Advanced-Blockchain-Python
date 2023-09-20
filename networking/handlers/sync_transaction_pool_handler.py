import socket
import time

from common.json import send_json_message
from common.logging import logger
from core.blockchain import UnifiedTransaction
from networking.handlers.base_handler import BaseHandler


class SyncTransactionPoolHandler(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)

    def handle(self, message_content, connection):
        """
        :param message_content:
        :param connection:
        :return:
        """
        logger.info(f"Received SYNC_TRANSACTION_POOL_HANDLER message from {connection.getpeername()}")

        pool = message_content['pool']
        for tx in pool:
            tx = UnifiedTransaction(**tx)

            public_key = tx.recover_transaction_signer()

            self.peer.blockchain.new_transaction(tx, public_key)

        logger.info(f"Transaction pool updated with {len(pool)} transactions")
