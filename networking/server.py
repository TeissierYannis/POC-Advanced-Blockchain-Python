import socket
import threading

from common.colors import bcolors
from common.logging import logger, DEFAULT_COLOR
from networking.handlers.message_handler import MessageHandler


class Server:
    def __init__(self, host, port, connection_manager, peer_manager):
        self.host = host
        self.port = port
        self.handler = MessageHandler(None)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = connection_manager
        self.peer_manager = peer_manager

    def listen(self):
        """Starts the server and listens for incoming connections."""
        self.socket.bind((self.host, self.port))
        self.socket.listen(10)
        logger.info(
            f"Listening for connections on {bcolors.OKCYAN}{bcolors.UNDERLINE}{self.host}:{self.port}{DEFAULT_COLOR}")

        while True:
            connection, address = self.socket.accept()
            logger.info(f"Connected to {connection.getpeername()}")
            threading.Thread(target=self.handle_connection, args=(connection,)).start()

    def handle_connection(self, connection):
        """Handle incoming data from a connection."""
        while True:
            try:
                data = connection.recv(1024)
                if data:
                    self.handler.handle(data, connection)
                else:
                    break
            except ConnectionResetError:
                logger.info(f"Connection reset by peer")
                break
            except OSError:
                logger.info(f"Connection reset by peer")
                break
            except Exception as e:
                logger.error("Exception while handling connection", exc_info=e)
                break
            except:
                break
