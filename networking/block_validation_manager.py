import time
import threading

from common.logging import logger


class BlockValidationManager:

    def __init__(self, blockchain, peer_manager):
        self.blockchain = blockchain
        self.pm = peer_manager
        logger.info(f"Starting block validation manager")
        # launch a thread
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        # Look for validator every 3 minutes
        while True:
            try:
                self.validate()
            except Exception as e:
                error_message = e.args[0]
                logger.error(f"Exception while validating blocks {error_message}")
            time.sleep(180)

    def validate(self):
        result = self.blockchain.new_block(self.blockchain.hash(self.blockchain.last_block), self.pm.node_wallet.get_address())