import json

from core.blockchain import Blockchain
from accounts.Wallet import Wallet
#from accounts.Wallet import Wallet
def main():

    # Initialize wallets for Alice and Bob
    alice_wallet = Wallet(node_url='http://localhost:5000')
    bob_wallet = Wallet(node_url='http://localhost:5000')

    # Initialize the blockchain
    blockchain = Blockchain(token_name='DebugToken', token_symbol='DT', initial_addresses = [
        {
            'address': alice_wallet.get_address(),
            'percent': 0.2
        },
        {
            'address': bob_wallet.get_address(),
            'percent': 0.1
        }
    ])

    alice_wallet.send_funds(bob_wallet.get_address(), 10, 'DT')

    #print(blockchain.token_registry.get_token_details('DT'))

    #print("Account Balances:", blockchain.account_manager.dump_state())

    #result = staking.add_stake(alice_wallet.get_address(), 20, 'DT', alice_wallet.public_key, alice_wallet.private_key)

    # Print out the blockchain and account balances
    print("Blockchain:", json.dumps(blockchain.chain, indent=4))
    print("Account Balances:", blockchain.get_balances())


if __name__ == "__main__":
    #main()
    wallet = Wallet().restore_from_seed_phrase(seed_phrase="discover magnet idea shadow absent afraid problem blade admit stool letter canal")
    wallet.get_address()
    wallet.set_node_url('127.0.0.1:54431')

    wallet2 = Wallet().restore_from_seed_phrase(seed_phrase="food gate syrup category tackle mechanic receive ignore speak same control day")
    wallet2.set_node_url("127.0.0.1:54431")

    w2_address = wallet2.get_address()
    print(wallet.send_funds(w2_address, 1000, 'DT'))

    print("Wallet 1 address:", wallet.get_address())
    print("Wallet 2 address:", w2_address)
    print("Wallet 1 balance:", wallet.get_balance())
    print("Wallet 2 balance:", wallet2.get_balance())

    # Stake some token
    wallet2.stake_funds(10, 'DT')
