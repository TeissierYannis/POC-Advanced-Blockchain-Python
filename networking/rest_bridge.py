import json
import socket

from flask import Flask, jsonify, request

from accounts.Wallet import Transaction

app = Flask(__name__)

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(('127.0.0.1', 54431))


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['transaction', 'public_key']
    if not all(k in values for k in required):
        return 'Missing values', 400

    transaction = Transaction().create_transaction(
        tx_type=values['transaction']['tx_type'],
        sender=values['transaction']['sender'],
        recipient=values['transaction']['recipient'],
        amount=values['transaction']['amount'],
        nonce=values['transaction']['nonce'],
        data=values['transaction']['data'],
        signature=values['transaction']['signature'],
        v=values['transaction']['v'],
        r=values['transaction']['r'],
        s=values['transaction']['s']
    )

    payload = {
        "type": "NEW_TRANSACTION",
        "content": {
            "transaction": transaction.to_json(),
            "public_key": values['public_key']
        }
    }
    global socket
    socket.send(json.dumps(payload).encode('utf-8'))
    response = socket.recv(
        1024 * 1024 * 10
    ).decode('utf-8')
    response = json.loads(response)

    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    payload = {
        "type": "READ_CHAIN",
        "content": ""
    }
    global socket
    socket.send(json.dumps(payload).encode('utf-8'))
    # Handle response without limiting the size of the response
    response = socket.recv(
        1024 * 1024 * 10
    ).decode('utf-8')
    response = json.loads(response)
    return jsonify(response), 200


@app.route('/nodes', methods=['GET'])
def get_nodes():
    payload = {
        "type": "READ_NODES",
        "content": ""
    }
    global socket
    socket.send(json.dumps(payload).encode('utf-8'))
    response = socket.recv(
        1024 * 1024 * 10
    ).decode('utf-8')
    response = json.loads(response)

    return jsonify(response), 200


# Transaction pool
@app.route('/transactions/pool', methods=['GET'])
def get_transaction_pool():
    payload = {
        "type": "READ_TRANSACTION_POOL",
        "content": ""
    }
    global socket
    socket.send(json.dumps(payload).encode('utf-8'))
    response = socket.recv(
        1024 * 1024 * 10
    ).decode('utf-8')
    response = json.loads(response)

    return jsonify(response), 200


# /address/{self.address}/balance
@app.route('/address/<address>/balance', methods=['GET'])
def get_balance(address):
    payload = {
        "type": "READ_BALANCE",
        "content": {
            "address": address
        }
    }
    global socket
    socket.send(json.dumps(payload).encode('utf-8'))
    response = socket.recv(
        1024 * 1024 * 10
    ).decode('utf-8')
    response = json.loads(response)

    return jsonify(response), 200


@app.route('/address/<address>/transactions', methods=['GET'])
def get_transactions(address):
    payload = {
        "type": "READ_TRANSACTIONS",
        "content": {
            "address": address
        }
    }
    global socket
    socket.send(json.dumps(payload).encode('utf-8'))
    response = socket.recv(
        1024 * 1024 * 10
    ).decode('utf-8')
    response = json.loads(response)

    return jsonify(response), 200


@app.route('/', methods=['GET'])
def index():
    # Return all routes available
    return jsonify({
        'routes': [
            '/transactions/new',
            '/chain',
            '/nodes',
            '/transactions/pool',
            '/address/<address>/balance'
        ]
    }), 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=6356)
