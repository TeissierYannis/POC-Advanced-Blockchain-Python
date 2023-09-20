from threading import Thread

import requests

from core.full_node import run_app, port

if __name__ == "__main__":
    # run the main function of full_node.py
    flask_thread = Thread(target=run_app)
    flask_thread.start()

    ip = requests.get('https://api.ipify.org').text
    print(f'Public IP address: {ip} (port {port})')
