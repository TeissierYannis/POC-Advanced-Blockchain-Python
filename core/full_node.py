import sys
import threading
from threading import Event

from accounts.Wallet import Wallet
from common.colors import bcolors
from common.exception import exception_handler
from common.logging import logger
from common.networking import find_free_port
from core.blockchain import Blockchain
from networking.block_validation_manager import BlockValidationManager
from networking.command import Command
from networking.command_list import CommandList
from networking.connection_manager import ConnectionManager
from networking.peer_cleanup_manager import PeerCleanupManager
from networking.peer_manager import PeerManager
from networking.server import Server

# White color for the logging messages
DEFAULT_COLOR = bcolors.ENDC

sys.excepthook = exception_handler


def main():
    # Initialize the host and find a free port
    host = "127.0.0.1"
    port = find_free_port()

    # Create a Wallet instance and a Blockchain instance
    test_wallet = Wallet(node_url=f"{host}:{port}")

    blockchain = Blockchain(
        token_name='DebugToken', token_symbol='DT', initial_addresses=[
            {
                'address': test_wallet.get_address(),
                'percent': 0.2
            }
        ]
    )

    blockchain.add_node(host, port, test_wallet.get_address(), test_wallet.get_public_key())

    connection_manager = ConnectionManager()
    peer_manager = PeerManager(host, port, blockchain, node_wallet=test_wallet)

    server = Server(host, port, connection_manager, peer_manager)
    server_thread = threading.Thread(target=server.listen)
    server_thread.start()

    # Create a PeerCleanupManager instance and start the cleanup process in a separate thread
    peer_cleanup_manager = PeerCleanupManager(peer_manager)
    cleanup_thread = threading.Thread(target=peer_cleanup_manager.start_cleanup)
    cleanup_thread.start()

    peer_manager.stop_event = Event()
    discovery_thread = threading.Thread(target=peer_manager.start_discovery)
    discovery_thread.start()

    bvm = BlockValidationManager(blockchain, peer_manager)

    # Initialize the CommandList and add commands to it
    commands = CommandList()
    commands.add_command(Command("help", "Show this help message", None, commands.help))
    commands.add_command(Command("connect", "Connect to a peer", ["host:port"], peer_manager.connect))
    commands.add_command(Command("peers", "Show the list of connected peers", None, peer_manager.print_peer_addresses))
    commands.add_command(
        Command("pinghistory", "Show the ping history of a peer", None, peer_manager.print_ping_history))
    commands.add_command(
        Command("send", "Send a message to a peer ", ["host:port", "message"], peer_manager.send_message))
    commands.add_command(
        Command("broadcast", "Send a message to all peers", ["message"], peer_manager.broadcast_message))
    commands.add_command(
        Command("discover", "Recursively fetch all known nodes from other nodes", None, peer_manager.discover))
    commands.add_command(
        Command("info", "Show information about the node", None, peer_manager.print_node_info))

    test_wallet.set_node_url(f"{host}:{port}")

    # Start a loop to continuously accept user input for executing commands
    while True:
        command = input()
        if command.startswith("/"):
            try:
                command = command[1:]
                command_type, *args = command.split(" ")
                commands.execute(command_type, *args)
            except Exception as e:
                logger.error("Failed to execute command", exc_info=e)
            except KeyboardInterrupt:
                logger.info("Exiting...")
                peer_manager.stop_event.set()
                sys.exit(0)
        else:
            print("Unknown command. Type '/help' to see the list of available commands.")


if __name__ == "__main__":
    main()
