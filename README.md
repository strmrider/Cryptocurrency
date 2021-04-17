# Cryptocurrency
Cryptocurrency system, including complete Blockchain implementaion, nodes, miners, digital wallets and netwrok API's.

## Features
* Complete Blockchain implementaion.
* Full nodes
* Miners
* Digital wallets.

## Model
The currency's system model is simmilar to other known currencies such as Bitcoin or Ethereum.
The blockchian is composed of blocks, referenced by their hash value. Each block contains a block header and block data. 

The block's data is a list of transactions. Each transaction composed by 1) transaction's general and authentication data 2) inputs- list of unspent outputs signed by their owner's private key 3) outputs- list of recipients addresses and amount of currency to be spent. The transaction and its data is digitly signed.

Nodes are used to maintaine a blockhchain copy, track and serve it's data to users and verify new blocks. Miners are used to mine new block (using the proof work method) contiaing new verified transactions.

## How it works
### Blockchain
Create a blockchain instance:
```Python
from blockchain import BlockChain
# creates new chain
chain = BlockChain()
```
Create initial transactions in order to use the blockchain. Use it with a completly new blockchain only since nodes will approve this new block for their own copy as there are no existed unspent outputs to support new transactions. Otherwise you will have to apply this action manually for all nodes.
```Python
from miner import mine_initial_txs
# list of tuples containing pairs of recipient address and amount
recipients = [('efdsf2', 1), ('das676df', 0.8), ('pmawq44', 0.2)]
prev_hash = chain.get_blocks(-1).hash_block()
mine_initial_txs(prev_hash, recipients)
```
#### API
### Nodes
Nodes holds a blockchian copy and responsible for: 
* Serve chain's blocks and it's data (transactions).
* Track and confirm unspent transaction outputs (UTXO).
* Verifiy new transactions.
* Verify and add new blocks to the chain.
* Broadcast new data to other nodes in the network.

In order to broadcast and distrubute new data a node must be provided with a nodes peers network. If such a network isn't provided the node will not forward the data.
A peers network is simply consisted of an array of tuples of the size of the network, where each tuple contains a peer's ip address and port number.
```Python
from node import Node

peers = [('104.245.162.198', 62541), ('90.99.183.255', 62541), ('81.180.92.198', 61380)]
node_id = 'node123'
# creates a node
node = Node(node_id, chain, peers)
# use the node as a server
ip = '127.0.0.1'
port = 64123
node.run(ip, port)
```
### Miners
Miners receive and verify new transactions and mine new blocks using the PoW method.
```Python
from miner import Miner
# miner's address, to which the minning fee will be sent 
miner_address = 'ef16fdsfe'
# mode 0 - using node instance
# mode 1 - connecting to the node server
# node is either a Node instance or tuple of node server's ip and port
miner = Miner(miner_address, node, 0) # using node instance

# send new transaction. tx = new transaction
miner.handle_transaction(tx)
```
Miner as server:
```Python
miner.run_server('195.185.48.25', 65412) # ip, port

# connect to miner server as client
from miner import MinerClient
client = MinerClient()
client.connect('195.185.48.25', 65412)
# send transaction
client.send_tx(tx)
```
### Wallets
Digital wallets manage keys and addresses, send/receive new transactions and store transactions data such history, balance and available UTXO's. Wallets must be connected to a Node in order to extract relevant data from the blockchain. Wallet may also connect to a miner (or any server that connects to a miner), to which it will send new transactions to be verified and inserted into a block. This option is optional, and in such case new transaction will have to be sent manually to the miner.
```Python
from wallet import Wallet

# node and miner connection addresses samples
node_address = ('82.254.148.222', 64123)
miner_address = ('175.171.218.10', 52132)

wallet = Wallet(node_address, miner_address)
# create transaction
# list of tuples containing pairs of recipient address and amount
recipients = [('efdsf2', 1), ('das676df', 0.8), ('pmawq44', 0.2)]
# parameters are sender address (optional- used for additoinal signature), recipients list, total amount and miners fee
# the method returns the new transaction in case no miner was provided
wallet.create_transaction('eewr', recipients, 2, 0.01)

# use wallet as a server and communicate it with a client, which provides the capability to use it from another 
# machine/socket or a client written in any programming language other than python.
wallet_server = WalletServer(wallet)
wallet_server.start('127.0.0.1', 45174)
```
### Web client
