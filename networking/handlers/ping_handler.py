import socket
import time

from common.json import send_json_message
from common.logging import logger
from networking.handlers.base_handler import BaseHandler


class PingHandler(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)

    def handle(self, message_content, connection):
        con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        con.connect((message_content['ip'], message_content['port']))

        logger.info(f"Sending PONG to {message_content['ip']}:{message_content['port']}")
        send_json_message(con, "PONG", {
            "ip": self.peer.host,
            "port": self.peer.port
        })
        con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        con.connect((message_content['ip'], message_content['port']))
        self.peer.add_peer(con)
        key = (message_content['ip'], message_content['port'])
        hashed_key = hash(key)
        # update the time for the peer
        self.peer.peer_last_response[hashed_key] = time.time()