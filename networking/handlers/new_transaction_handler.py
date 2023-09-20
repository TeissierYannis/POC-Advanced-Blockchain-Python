import json
from common.json import send_json_message
from common.logging import logger
from core.blockchain import Transaction
from networking.handlers.base_handler import BaseHandler


class NewTransactionHandler(BaseHandler):
    def __init__(self, peer):
        super().__init__(peer)

    def handle(self, message_content, connection):
        """
        :param message_content:
        :param connection:
        :return:
        """
        logger.info(f"Received NEW_TRANSACTION message from {connection.getpeername()}")

        tx = message_content['transaction']
        public_key = message_content['public_key']

        if tx is None and public_key is None:
            response = {
                'message': 'No transaction found',
            }
            send_json_message(connection, 'NEW_TRANSACTION_RESPONSE', response)
            return

        json_tx = json.loads(tx)

        transaction = Transaction().create_transaction(
            tx_type=json_tx['tx_type'],
            sender=json_tx['sender'],
            recipient=json_tx['recipient'],
            amount=json_tx['amount'],
            nonce=json_tx['nonce'],
            data=json_tx['data'],
            signature=json_tx['signature'],
            v=json_tx['v'],
            r=json_tx['r'],
            s=json_tx['s']
        )

        # Create a new Transaction
        try:
            self.peer.blockchain.new_transaction(transaction, public_key)
        except ValueError as e:
            logger.error(f"Failed to add transaction to the blockchain: {str(e)}")
            # response with the error message
            response = {'message': e.args[0]}
            json_response = json.dumps(response)
            send_json_message(connection, 'NEW_TRANSACTION_RESPONSE', json_response)
            return

        # Broadcast the current transaction pool to all nodes in the network (except this node)
        pool = self.peer.blockchain.transaction_pool.read_transactions()
        # broadcast the transaction pool to all nodes in the network (except this node)
        logger.info(f"Broadcasting transaction pool to all nodes in the network: {pool}")
        self.peer.broadcast_message('SYNC_TRANSACTION_POOL', pool)
        logger.info(f"Transaction pool broadcasted to all nodes in the network")


        # response with the success message
        response = {
            'TYPE': 'NEW_TRANSACTION_RESPONSE',
            'message': 'Transaction added to the blockchain',
        }
        logger.info(f"Transaction added to the blockchain")

        send_json_message(connection, 'NEW_TRANSACTION_RESPONSE', response)
