import json


def send_json_message(connection, message_type, content):
    """Creates and sends a JSON message through the specified connection."""
    message = json.dumps({"type": message_type, "content": content}).encode('utf-8')
    connection.send(message)