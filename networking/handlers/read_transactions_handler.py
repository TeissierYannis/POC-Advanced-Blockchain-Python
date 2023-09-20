from common.json import send_json_message
from common.logging import logger
from networking.handlers.base_handler import BaseHandler


class ReadTransactionsHandler(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)

    def handle(self, message_content, connection):
        """
        :param message_content:
        :param connection:
        :return:
        """
        logger.info(f"Received READ_TRANSACTIONS message from {connection.getpeername()}")

        address = message_content['address']

        transactions = self.peer.blockchain.get_transactions(address)

        response = {
            'transactions': transactions
        }

        send_json_message(connection, 'READ_TRANSACTIONS_RESPONSE', response)
