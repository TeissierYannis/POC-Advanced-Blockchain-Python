import socket
import time

from common.colors import bcolors
from common.json import send_json_message
from common.logging import logger
from networking.connection_manager import ConnectionManager
from networking.handlers.message_handler import MessageHandler


class PeerManager:
    def __init__(self, host, port, blockchain, node_wallet):
        self.host = host
        self.port = port
        self.handler = MessageHandler(self)
        self.connections = ConnectionManager()
        self.peer_last_response = {}
        self.blockchain = blockchain
        self.node_wallet = node_wallet

    def connect(self, host, port):
        """Connects to a new peer."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        try:
            s.connect((host, port))
            self.add_peer(s)
        except ConnectionRefusedError:
            logger.error(f"Connection refused by {host}:{port}")

    def sync_chain(self, connection):
        # Sync the chain, if needed
        # 1. Look for the longest chain in the peers (broadcast ask length to all peers and wait for response)
        # 2. Broadcast the chain to other peers and check if it's valid.
        # 3. Broadcast tx pools and verify if there is duplications etc.
        # 4. If valid, overwrite the current chain.
        # 5. Continue validating
        pass

    def update_peer_port(self, host, old_port, new_port):
        """Updates the port number for a peer."""
        logger.info(f"Updating port for {host} from {old_port} to {new_port}")
        for index, conn in enumerate(self.connections.get_connections()):
            if conn.getpeername() == (host, old_port):
                logger.info(f"Found connection to {host}:{old_port}")
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.connect((host, new_port))
                # Also update the peer_last_response dict
                key = (host, new_port)
                hashed_key = hash(key)
                self.peer_last_response[hashed_key] = time.time()
                # Remove the old connection from the connections list
                self.connections.remove_connection(self.connections.get_connections()[index])
                key = (host, old_port)
                hashed_key = hash(key)
                try:
                    self.peer_last_response.pop(hashed_key)
                except:
                    continue
                break

    def get_peer_addresses(self):
        """Returns a list of all connected peers."""
        result = []
        for connection in self.connections.get_connections():
            try:
                result.append(connection.getpeername())
            except:
                pass
        return result

    def print_peer_addresses(self):
        """Prints a list of all connected peers."""
        print("=== Connected peers ===")
        for peer in self.get_peer_addresses():
            print(f"{peer[0]}:{peer[1]}")
        print("======================")

    def print_ping_history(self):
        print("=== Ping history ===")
        for peer in self.peer_last_response:
            time_diff = time.time() - self.peer_last_response[peer]
            print(f"{peer}: {time_diff} seconds")
        print("====================")

    def print_node_info(self):
        print("=== Node info ===")
        print(f"Host: {self.host}")
        print(f"Port: {self.port}")
        print(f"Connections: {len(self.connections.get_connections())}")
        print(f"Peer last response: {len(self.peer_last_response)}")
        print(f"To connect use {bcolors.OKCYAN}/connect {self.host}:{self.port}{bcolors.ENDC}")
        print("\nTo see the list of available commands type /help")
        print("=================")

    def send_hello(self, connection):
        logger.info(f"Sending HELLO to {self._get_peer_name(connection)}")
        # check fi the connection is instance of socket.socket
        if not isinstance(connection, socket.socket):
            logger.error(f"Failed to send HELLO to {self._get_peer_name(connection)}")
            return

        try:
            send_json_message(connection, "HELLO", self.port)
        except:
            logger.error(f"Failed to send HELLO to {self._get_peer_name(connection)}")

    def broadcast_message(self, message="", *args, **kwargs):
        """Broadcasts a message to all connected peers."""
        for connection in self.connections.get_connections():
            try:
                self.send_message(self._get_peer_name(connection)[0], self._get_peer_name(connection)[1], message)
            except:
                logger.error(f"Failed to send MESSAGE to {self._get_peer_name(connection)}")
                continue

    def discover(self):
        for connection in self.connections.get_connections():
            logger.info(f"Sending DISCOVER to {self._get_peer_name(connection)}")
            # Generate random hash
            id = hash(time.time())
            send_json_message(connection, "DISCOVER", {
                "request_id": id,
                "host": self.host,
                "port": self.port,
                "known": self.get_peer_addresses()
            })

    def send_message(self, host=None, port=None, message=""):
        # check if the connection is instance of socket.socket
        if not isinstance(self.connections.get_connection(host, int(port)), socket.socket):
            return

        try:
            send_json_message(self.connections.get_connection(host, int(port)), "MESSAGE", message)
        except:
            logger.error(f"Failed to send MESSAGE to {host}:{port}")

    def _get_peer_name(self, connection):
        """Gets the name of a peer from a connection object."""
        try:
            return connection.getpeername()
        except:
            return "unknown"

    def _add_connection(self, connection):
        """Adds a connection and cleans up."""
        try:
            self.connections.add_connection(connection)
        except:
            pass

    def add_peer(self, connection):
        time.sleep(5)
        try:
            # add the connection to the connections list if it's not already there
            for con in self.connections.get_connections():
                # check if connection is instance of socket.socket
                if not isinstance(con, socket.socket):
                    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    connection.connect(con)

                if con.getpeername() == connection.getpeername():
                    logger.info(f"Connection to {connection.getpeername()} already exists")
                    return
        except Exception as e:
            logger.error("Failed to add peer", exc_info=e)
            return

        self._add_connection(connection)
        self.send_hello(connection)

    def start_discovery(self):
        """Starts the discovery process in a loop."""
        logger.info("Starting discovery process")
        while not self.stop_event.is_set():
            self.discover()
            time.sleep(60)
