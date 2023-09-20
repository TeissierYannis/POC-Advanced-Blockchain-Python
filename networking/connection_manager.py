import threading

from common.singleton import singleton


@singleton
class ConnectionManager:
    def __init__(self):
        self.connections = []
        self.lock = threading.Lock()

    def add_connection(self, connection):
        with self.lock:
            if connection not in self.connections:
                self.connections.append(connection)

    def remove_connection(self, connection):
        with self.lock:
            if connection in self.connections:
                self.connections.remove(connection)

    def get_connections(self):
        with self.lock:
            return self.connections

    def get_connection(self, host, port):
        with self.lock:
            for conn in self.connections:
                if conn.getpeername() == (host, port):
                    return conn
        return None
