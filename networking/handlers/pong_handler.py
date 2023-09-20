import socket
import time

from common.logging import logger
from networking.handlers.base_handler import BaseHandler


class PongHandler(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)

    def handle(self, message_content, connection):
        # update the peer_last_response dict using the IP and port from the message content
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect((message_content['ip'], message_content['port']))

            key = (message_content['ip'], message_content['port'])
            hashed_key = hash(key)
            self.peer.peer_last_response[hashed_key] = time.time()
            self.peer.add_peer(conn)
            logger.info(f"Received PONG from {message_content['ip']}:{message_content['port']}")
        except:
            logger.error(f"Failed to update last response time for {message_content['ip']}:{message_content['port']}")
            pass