# TODO LIST

- [ ] Explore more complexe choose_validator function
- [ ] Improve the errors handling, add more details, and more specific errors
- [ ] **Storage**
  - [ ] Add a storage system (like a database)
  - [ ] Add a storage system for the transaction pool
  - [ ] Add a storage system for the blockchain
  - [ ] Add a storage system for the wallet (private and public keys) (maybe in a file)
- [ ] **Add networking features**
    - [X] ~~RPC server~~
    - [ ] Rest API server
    - [ ] Sync chain (~~longest valid chain wins~~) -> When a new node join the network ask for download all the chain from the genesis and do continuous sync, when a validator is choosen, all the nodes ask for the new block and the new transactions to the validator
    - [ ] Sync transaction pool -> When a transaction is validated by a node, broadcast it to all others nodes
    - [X] Choose a validator each 10 minutes (in fact of the first block of the chain) -> to verify with multiples nodes
    - [ ] Add a new node to the network
    - [ ] Remove a node from the network
    - [ ] Broadcast a new transaction
    - [ ] Broadcast a new block
    - [ ] Verify integrity of the full chain when receiving a new block
- [ ] Transaction expiration, après un laps de temps si la transaction n'a pas été validé ou ajouté elle est supprimé
- [ ] Ajouter les validateurs qui rejoignent le réseau et qui quitte dans le bloc

There is an error when my wallet call for a new transaction