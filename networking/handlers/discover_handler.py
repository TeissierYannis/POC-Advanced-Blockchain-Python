import socket
import time

from common.json import send_json_message
from common.logging import logger
from networking.handlers.base_handler import BaseHandler


class DiscoverHandler(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)
        self.handled_request_ids = set()

    def handle(self, message_content, connection):
        logger.info(f"Received DISCOVER message from a node, content: {message_content}")

        request_id = message_content.get('request_id')
        if not request_id or request_id in self.handled_request_ids:
            # Ignore this request but
            logger.info(f"Request ID {request_id} already handled, ignoring")
            return

        # Mark this request as handled
        self.handled_request_ids.add(request_id)

        known_hosts = set(self.peer.get_peer_addresses())  # Getting known hosts of the receiver as a set of tuples
        sender_host, sender_port = message_content['host'], message_content['port']
        received_known_hosts = set(tuple(x) for x in message_content[
            'known'])  # Converting received known hosts list of lists to a set of tuples

        # Create a base set which includes all the hosts known by the sender plus the sender itself and the receiver
        base = received_known_hosts | {(self.peer.host, self.peer.port), (sender_host, sender_port)}

        # Find the hosts that are known to the sender but not to the receiver and remove the current node (self.host, self.port)
        hosts_to_notify = known_hosts - {(self.peer.host, self.peer.port)} - base

        # Add the sender to the known hosts of the receiver
        known_hosts.add((sender_host, sender_port))

        # Loop over the hosts to notify and send them the updated list of known hosts
        for host in hosts_to_notify:
            try:
                # Skip if the host is the sender itself
                if host[0] == sender_host and host[1] == sender_port:
                    continue
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.connect((host[0], host[1]))

                send_json_message(conn, "DISCOVER", {
                    "request_id": request_id,
                    "host": sender_host,
                    "port": sender_port,
                    "known": [list(x) for x in known_hosts]
                    # Convert set of tuples to list of lists for JSON serialization
                })
                time.sleep(3)
                self.peer.connect(sender_host, sender_port)
                # delete con
                conn.close()
            except Exception as e:
                logger.error(f"Could not connect to {host[0]}:{host[1]}, error: {e}")
