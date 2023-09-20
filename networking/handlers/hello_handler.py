from common.logging import logger
from networking.handlers.base_handler import BaseHandler


class HelloHandler(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)

    def handle(self, message_content, connection):
        host, port = self.get_peer_name(connection)
        self.peer.add_peer(connection)
        self.peer.update_peer_port(host, port, message_content)
        logger.info(f"Updated port for {host} to {message_content}")