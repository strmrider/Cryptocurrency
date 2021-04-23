import pickle
from net import NodeSocket, Request
from net import NodeAPI as node_api
from block import Block

# alias for net.NodeAPI
NodeAPI = node_api

class Peer:
    """
    Holds network peer info
    """
    def __init__(self, peer_id, ip, port):
        """
        :param peer_id: str
        :param ip: str
        :param port: int
        """
        self.id = peer_id
        self.ip = ip
        self.port = port

class UTXO:
    """
    Unspent Transaction output
    """
    def __init__(self, output, date, tx_hash, block):
        """
        :param output: Output
        :param date: str
        :param tx_hash: bytes
        :param block: int
        """
        self.output = output
        self.date = date
        self.tx = tx_hash
        # block index
        self.block = block

    def hash(self):
        """
        hash utxo
        :return: bytes
        """
        return self.output.hash()

    def serialize(self):
        """
        Serialize utxo
        :return: bytes
        """
        return pickle.dumps(self.__dict__)

    def str_date(self):
        return self.date.strftime('%m/%d/%Y, %H:%M:%S')

    def summary(self):
        return {'address': self.output.recipient, 'amount': self.output.amount}

class UTXOSet:
    """
    A set of unspent transaction outputs per addresses.
    Necessary for tracking and confirming transactions
    """
    def __init__(self,chain=None):
        """
        Initializes set. If a block chain is provided the set will be built completely
        :param chain: BlockChain
        """
        self.__set = self.build(chain) if chain and len(chain) > 1 else {}

    def build(self, chain):
        """
        Builds set from a block chain
        :param chain: BlockChain
        :return: None
        """
        for block in iter(chain):
            for tx in block.data:
                self.new_tx(tx, block.index)

    def __new_outputs(self, tx, block_index):
        """
        Sets new outputs in set
        :param tx: Transaction
        :param block_index: int
        :return: None
        """
        for output in tx.outputs:
            utxo = UTXO(output, tx.date, tx.hash(), block_index)
            address = output.recipient
            if output.recipient in self.__set:
                self.__set[address].append(utxo)
            else:
                self.__set[address] = [utxo]

    def __new_inputs(self, tx):
        """
        Handles new inputs. An input is a spent output amd will remove its corresponded utxo from list
        :param tx: Transaction
        :return: None
        """
        for _input in tx.inputs:
            address = _input.address
            if address in self.__set:
                utxo_list = self.__set[address]
                # removes unspent outputs if match inputs exists
                for utxo in utxo_list:
                    if utxo.output.hash() == _input.hash:
                        self.__set[address].remove(utxo)

    def new_tx(self, tx, block_index):
        """
        Handles new Transaction's output and inputs
        :param tx: Transaction
        :param block_index: int
        :return:
        """
        self.__new_outputs(tx, block_index)
        self.__new_inputs(tx)

    def update(self, txs, block_index):
        """
        Updates set with new transactions
        :param txs: list
        :param block_index: int
        :return: None
        """
        for tx in txs:
            self.new_tx(tx, block_index)

    def fetch_existed(self, hashes):
        """
        Receives a dict of hashed outputs and returns their respective in the set and their total amount
        :param hashes: dict
        :return: list, int
        """
        addresses = hashes.keys()
        existed = []
        total_sum = 0
        for address in addresses:
            if address in self.__set:
                # fetch list for address
                utxo_list = self.__set[address]
                for utxo in utxo_list:
                    h = utxo.hash()
                    # if utxo hash exists, adds it to returning list and computes its amount
                    if utxo.hash() in hashes[address]:
                        existed.append(h)
                        total_sum += utxo.output.amount
        return existed, total_sum

    def get_by_address(self, addresses):
        """
        Returns all unspent outputs for the given addresses
        :param addresses: list
        :return: list
        """
        utxo_list = []
        for address in addresses:
            if address in self.__set:
                utxo_list.append(self.__set[address])
        return [item for sublist in utxo_list for item in sublist]

    def __len__(self):
        return len(self.__set)

class Node:
    """
    Handles a node. Designated to:
    Hold a block chain copy
    Validates data format
    confirm transactions
    confirm unspent transaction outputs
    confirm and add new block
    broadcast data to nodes network
    """
    def __init__(self, node_id, chain, network_peers):
        """
        :param node_id: str
        :param chain: BlockChain
        :param network_peers: list
        """
        self.identifier = node_id
        self.chain = chain.copy()
        self.utxo_set = UTXOSet(chain)
        self.network = NodeSocket(node_id, network_peers)
        self.network.income_request_emitter.subscribe(self.handle_request)
        self.recent_blocks = []

    # initial transactions block
    def initial_tx_block(self, block):
        self.utxo_set.new_tx(block.data[0], block.index)
        self.chain.add_block(block)

    def run(self, ip, port):
        """
        Runs node
        :param ip: str
        :param port: int
        :return: None
        """
        self.network.start(ip, port)

    def handle_request(self, request):
        """
        Handles income requests
        :param request: Request
        :return: None or respective response
        """
        action =  request.type
        request = request.data
        block = None
        # builds a block for related requests
        if action in ['new block', 'approved block']:
            try:
                block = Block()
                block.deserialize(request['block'])
            except Exception as e:
                # verifies block and transactions data format during deserialization process
                # if the process fails, that means data format is invalid and an exception is thrown
                print (e)

        if action == 'new block':
            return self.new_block(block)
        elif action == 'utxo':
            utxo = self.get_utxo_by_address(request['addresses'])
            return pickle.dumps(utxo)
        elif action == 'valid tx':
            return self.validate_transactions(request[request['txs']])
        elif action == "json_chain":
            return self.json_chain()

    def get_blocks(self, indexes):
        """
        Returns blocks by their respective index
        :param indexes: list
        :return: list
        """
        if indexes == -1:
            return self.chain.get_last()
        return [self.chain.get_block(index) for index in indexes]

    def get_utxo_by_address(self, addresses):
        """
        Returns unspent transaction outputs by their respective address
        :param addresses: list
        :return: list
        """
        return self.utxo_set.get_by_address(addresses)

    def validate_transactions(self, txs):
        """
        Validates given transactions:
        * Confirms and verifies their inputs
        * Validates inputs/outputs balance
        * verifies keys, addresses and signature
        :param txs: list
        :return: bool
        """
        # also validate coin base tx and change tx
        for tx in iter(txs):
            inputs_hashes = tx.inputs.get_hashes()
            confirmed_utxo, inputs_sum = self.utxo_set.fetch_existed(inputs_hashes)
            tx.inputs.filter_inputs(confirmed_utxo)
            if inputs_sum >= tx.amount() and tx.verify():
                return True
            else:
                return False

    def validate_block(self, block):
        """
        Validates block and its transactions
        :param block: Block
        :return: bool
        """
        # checks that block isn't already in chain
        # validates block hash and PoW
        # validates transaction and inputs signatures
        # validates chain with new block.
        if (not block.hash_block() in self.recent_blocks) and \
                block.is_valid() and \
                self.validate_transactions(block.data) and\
                self.chain.verify_chain(block):
            return True
        return False

    def new_block(self, block):
        """
        verifies and adds new block, then broadcasts it across the nodes network
        :param block:
        :return: bool
        """
        if self.validate_block(block):
            self.chain.add_block(block)
            self.utxo_set.update(block.data, block.index)
            self.recent_blocks.append(block.hash_block())
            block_bin = block.serialize()
            request = Request('new block', {'block': block_bin})
            # send result across network as part of consensus...
            self.network.broadcast(request)
            return True
        return False

    def get_chain_len(self):
        """
        Returns chain's length
        :return: int
        """
        return len(self.chain)

    def serialize_chain(self):
        """
        Serializes block chain's copy
        :return: bytes
        """
        return self.chain.serialize()

    def json_chain(self):
        return self.chain.json()
