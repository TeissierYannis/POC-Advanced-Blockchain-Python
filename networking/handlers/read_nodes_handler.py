import json
from common.json import send_json_message
from common.logging import logger
from networking.handlers.base_handler import BaseHandler


class ReadNodesHandler(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)

    def handle(self, message_content, connection):
        """
        :param message_content:
        :param connection:
        :return:
        """
        logger.info(f"Received READ_NODES message from {connection.getpeername()}")

        nodes = self.peer.blockchain.get_nodes()
        # generate a json response
        nodes_as_json = []
        for node in nodes:
            nodes_as_json.append(node.to_dict())

        response = {
            'nodes': nodes_as_json
        }
        send_json_message(connection, 'READ_NODES_RESPONSE', response)
        return
