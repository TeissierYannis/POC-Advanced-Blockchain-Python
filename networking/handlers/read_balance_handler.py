from common.json import send_json_message
from common.logging import logger
from networking.handlers.base_handler import BaseHandler


class ReadBalanceHandler(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)

    def handle(self, message_content, connection):
        """
        :param message_content:
        :param connection:
        :return:
        """
        logger.info(f"Received GET_BALANCE message from {connection.getpeername()}")

        try:
            address = message_content['address']
            balances = self.peer.blockchain.get_all_balances(address)
        except:
            response = {
                'message': 'No address found',
            }
            send_json_message(connection, 'GET_BALANCE_RESPONSE', response)
            return
        response = {
            'address': address,
            'balance': balances,
        }

        send_json_message(connection, 'GET_BALANCE_RESPONSE', response)
