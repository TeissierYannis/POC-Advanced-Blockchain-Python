import time
from common.json import send_json_message
from common.logging import logger


class PeerCleanupManager:
    def __init__(self, peer_manager):
        self.peer_manager = peer_manager
        self.retry_counter = {}

    def start_cleanup(self):
        """Starts the cleanup process in a loop."""
        logger.info("Starting peer cleanup process")
        while True:
            self._send_ping_to_all()
            time.sleep(5)
            self._check_last_response_times()
            time.sleep(25)

    def _send_ping_to_all(self):
        """Sends a PING message to all connections to check their status."""
        for connection in self.peer_manager.connections.get_connections():
            try:
                send_json_message(connection, "PING", {
                    "ip": self.peer_manager.host,
                    "port": self.peer_manager.port
                })
                # Sync the chain, if needed
                self.peer_manager.sync_chain(connection)
            except:
                peername = self._get_peer_name(connection)
                logger.error(f"Failed to send PING to {peername}")

    def _check_last_response_times(self):
        """Checks the last response times and removes stale connections."""
        current_time = time.time()
        for connection in list(self.peer_manager.connections.get_connections()):
            ip, port = self._get_peer_name(connection)
            key = (ip, port)
            hashed_key = hash(key)
            try:
                last_response = self.peer_manager.peer_last_response[hashed_key]
            except:
                last_response = time.time()
            if current_time - last_response > 30:
                peername = self._get_peer_name(connection)

                # Increment the retry counter for this connection
                self.retry_counter[connection] = self.retry_counter.get(connection, 0) + 1

                # If the retry count exceeds a threshold, remove the connection
                if self.retry_counter[connection] > 3:  # Adjust the threshold as needed
                    logger.warning(
                        f"No PONG received from {peername} for more than 30 seconds, removing after retries.")
                    self._remove_connection(connection)
                    del self.retry_counter[connection]  # Reset the retry counter for this connection
                else:
                    logger.warning(f"No PONG received from {peername} for more than 30 seconds, retrying.")
            else:
                # If a PONG is received, reset the retry counter for this connection
                if connection in self.retry_counter:
                    del self.retry_counter[connection]

    def _get_peer_name(self, connection):
        """Gets the name of a peer from a connection object."""
        try:
            return connection.getpeername()
        except:
            return "unknown"

    def _remove_connection(self, connection):
        """Removes a connection and cleans up."""
        try:
            self.peer_manager.connections.remove_connection(connection)
            connection.close()
        except Exception as e:
            logger.error("Failed to remove connection", exc_info=e)
        except KeyError as e:
            logger.error("Failed to remove connection", exc_info=e)
        except:
            logger.error("Failed to remove connection")
            pass