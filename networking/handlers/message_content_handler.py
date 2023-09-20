from networking.handlers.base_handler import BaseHandler


class MessageContentHandler(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)

    def handle(self, message_content, connection):
        print(message_content)