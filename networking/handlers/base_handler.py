class BaseHandler:
    """Base class for all handler classes. Contains methods common to all handlers."""

    def __init__(self, peer):
        self.peer = peer

    def handle(self, message_content, connection):
        raise NotImplementedError("Subclasses must implement this method")

    def get_peer_name(self, connection):
        try:
            return connection.getpeername()
        except:
            return "unknown"
