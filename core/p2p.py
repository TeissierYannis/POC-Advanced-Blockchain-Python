import json
import socket
import threading
import time

class P2PNode:
    def __init__(self, host, port, blockchain):
        self.host = host
        self.port = port
        self.blockchain = blockchain
        self.connected_sockets = []  # Holds the socket objects
        self.connected_nodes = []  # Holds the IP and port of nodes
        self.last_heartbeat = {}

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen()
        print(f"Server started on {self.host}:{self.port}")

        heartbeat_thread = threading.Thread(target=self.send_heartbeats)
        heartbeat_thread.start()

        while True:
            client_socket, address = server.accept()
            print(f"Connection from {address} has been established!")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

    def handle_client(self, client_socket):
        self.connected_sockets.append(client_socket)
        self.last_heartbeat[client_socket] = time.time()
        while True:
            msg = client_socket.recv(1024).decode('utf-8')
            print(f"Received message: {msg}")

            if msg == 'quit':
                client_socket.close()
                self.connected_sockets.remove(client_socket)
                break
            elif msg == 'heartbeat':
                self.last_heartbeat[client_socket] = time.time()
            elif msg == 'get_blockchain':
                self.send_blockchain(client_socket)
            elif msg == 'get_peers':
                self.send_peers(client_socket)
            elif msg.startswith('{"type": "heartbeat",'):
                try:
                    heartbeat_data = json.loads(msg)
                    self.last_heartbeat[client_socket] = time.time()
                    self.update_peers(heartbeat_data['peers'])
                except Exception as e:
                    print(f"Error processing heartbeat: {e}")

    def send_peers(self, client_socket):
        peer_addresses = json.dumps(self.connected_nodes)
        client_socket.send(peer_addresses.encode('utf-8'))

    def update_peers(self, new_peers):
        for peer_address in new_peers:
            peer_host, peer_port = None, None

            if isinstance(peer_address, str):
                try:
                    peer_host, peer_port = peer_address.split(':')
                    peer_port = int(peer_port)
                except ValueError as e:
                    print(f"Skipping invalid peer_address: {peer_address}, reason: {e}")
                    continue

            elif isinstance(peer_address, (tuple, list)) and len(peer_address) == 2:
                peer_host, peer_port = peer_address

            else:
                print(f"Skipping invalid peer_address: {peer_address}, unsupported type or format.")
                continue

            if (peer_host, peer_port) not in self.connected_nodes:
                self.connected_nodes.append((peer_host, peer_port))

            try:
                new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                new_socket.connect((peer_host, peer_port))
                self.connected_nodes.append(new_socket)
                self.last_heartbeat[new_socket] = time.time()
                print(f"Successfully connected to new peer: {peer_host}:{peer_port}")

            except Exception as e:
                print(f"Could not connect to peer {peer_host}:{peer_port}, reason: {e}")

    def resolve_conflicts_with_nodes(self):
        """
        Collect chains from other nodes and resolve any conflicts.
        """
        candidate_chains = [self.blockchain.chain]  # Collect chains from other nodes here

        # For now, let's just add the current chain as a candidate
        # In a real-world scenario, you'd collect chains from other connected nodes

        replaced = self.blockchain.resolve_conflicts(candidate_chains)
        if replaced:
            print("Chain was replaced.")
        else:
            print("Chain is authoritative.")

    def send_blockchain(self, client_socket):
        """
        Send the current blockchain to the client.
        """
        blockchain_json = json.dumps(self.blockchain.chain)
        client_socket.send(blockchain_json.encode('utf-8'))

    def broadcast(self, message_type, data):
        """
        Broadcast a message to all connected nodes.

        :param message_type: <str> Type of the message ('new_transaction', 'new_block')
        :param data: <dict> The data to be sent
        """
        message = {
            'type': message_type,
            'data': data
        }
        message_json = json.dumps(message)
        for client_socket in self.connected_nodes:
            client_socket.send(f"{message_type}:{message_json}".encode('utf-8'))

    def send_heartbeats(self):
        while True:
            time.sleep(5)
            heartbeat_message = {
                'type': 'heartbeat',
                'peers': self.connected_nodes  # Send the list of tuples
            }
            heartbeat_json = json.dumps(heartbeat_message)
            for client_socket in self.connected_sockets:  # Use the list of socket objects
                try:
                    client_socket.send(heartbeat_json.encode('utf-8'))
                except:
                    print(f"Could not send heartbeat to {client_socket.getpeername()}, removing from list.")
                    self.connected_sockets.remove(client_socket)
                    self.connected_nodes.remove((self.host, self.port))  # Remove the corresponding tuple
                    del self.last_heartbeat[client_socket]

    def check_for_inactivity(self):
        """
        Periodically check for inactive nodes and remove them from the list of connected nodes.
        """
        while True:
            time.sleep(10)
            current_time = time.time()
            inactive_nodes = []

            for client_socket, last_time in self.last_heartbeat.items():
                if current_time - last_time > 15:
                    print(f"Node {client_socket.getpeername()} is inactive, removing from list.")
                    inactive_nodes.append(client_socket)

            for client_socket in inactive_nodes:
                self.connected_sockets.remove(client_socket)
                self.connected_nodes.remove((self.host, self.port))
                del self.last_heartbeat[client_socket]
