from common.json import send_json_message
from common.logging import logger
from networking.handlers.base_handler import BaseHandler


class ReadNodeAddressHandler(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)

    def handle(self, message_content, connection):
        """
        :param message_content:
        :param connection:
        :return:
        """
        logger.info(f"Received READ_NODE_ADDRESS message from {connection.getpeername()}")

        # Get the node address
        node_address = self.peer.node_wallet.get_address()

        # Send the node address back to the sender
        response = {
            'node_address': node_address
        }
        send_json_message(connection, 'READ_NODE_ADDRESS_RESPONSE', response)
        return
