from block import Block, MerkleTree, Txs
from net import NodeAPI
import socket, threading, struct
from transaction import Transaction, initial_tx

MAX_TX_IN_BLOCK = 1

LOCAL_NODE = 0
PEER_NODE = 1

class Miner:
    """
    Mines new blocks.
    Accepts new transactions, verifies them and inserts them into a blocks.
    Then mines the blocks and sends them to the Node.
    The miner can also functions as a server for network requests.
    """
    def __init__(self, miner_address, node, mode):
        """
        :param miner_address: str; Target address for fee transaction.
        :param node: Node or tuple (str, int). Node's data depends on the mode.
        :param mode: Node mode (int);
                Two mode options:
                1) Local node provided directly to the Miner.
                2) Network Node, provided by connection addresses (ip and port)
                Both are provided through the node parameter.
        """
        self.mode = mode
        if mode == LOCAL_NODE:
            self.node = node
        elif mode == PEER_NODE:
            self.node = NodeAPI(node[0], node[1])
        else:
            raise Exception('Invalid node mode')
        self.transactions = []
        self.recent_blocks = []
        self.miner_address = miner_address # should be signed too

        # transaction reward for the miner (accepts nonce) and miner address and public key and signature
        self.coin_base_tx = None
        self.server = None

    def run_server(self, ip, port):
        """
        Runs the miner as as server
        :param ip: str
        :param port: int
        :return: None
        """
        self.server = MinerServer(ip, port)
        threading.Thread(target=self.server.run, args=(self.handle_transaction,)).start()

    def mine(self):
        """
        Mines a new block when enough transactions are received and verified
        and sends it to the Node.
        :return: None
        """
        all_tx_hashes = [tx.hash() for tx in self.transactions]
        tree = MerkleTree(all_tx_hashes)
        merkle_root = tree.cal_root()
        last_block = self.node.get_blocks(-1)
        new_block = Block(self.miner_address,
                          last_block.index + 1,
                          last_block.hash_block(),
                          merkle_root,
                          Txs(self.transactions))
        new_block.cal_header_hash()
        new_block.hash_block()
        self.recent_blocks.append(new_block)

        # send new block abroad network ....
        self.node.new_block(new_block)

    def handle_transaction(self, tx):
        """
        Handles new transaction
        :param tx: Transaction
        :return: None
        """
        if tx.validate_format():
            if self.node.validate_transactions([tx]):
                self.transactions.append(tx)

        # when enough transactions are gathered
        if len(self.transactions) == MAX_TX_IN_BLOCK:
            self.mine()
            # only when block is approved
            self.transactions = []

def mine_initial_txs(prev_hash, recipients):
    """
    :param prev_hash: bytes; previous block's hash value
    :param recipients: list of tuples containing pairs of address and amount
    :return:Block
    """
    tx = initial_tx(recipients)
    root = MerkleTree([tx.hash()]).cal_root()
    block = Block(0, 1, prev_hash, root, Txs([tx]))
    block.cal_header_hash()
    block.hash_block()

    return block


# Network API
def _send(sock, data):
    size = struct.pack('!I', len(data))
    sock.sendall(size)
    sock.sendall(data)

def _receive(sock):
    data_size = sock.recv(4)
    data_size = struct.unpack('!I', data_size)[0]
    data = b''
    while len(data) < data_size:
        buffer = sock.recv(data_size - len(data))
        if buffer:
            data += buffer
    return data

class MinerServer:
    """
    Miner server. Used by the miner to accepts new transactions from network
    """
    def __init__(self, ip, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((ip, port))

    def run(self, callback):
        """
        Runs teh server
        :param callback: method reference
        :return: None
        """
        self.socket.listen(5)
        print ('Miner is listeing...')
        while True:
            conn, addr = self.socket.accept()
            print ('Miner accepted a new connection:' , addr, 'and instantiating a thread')
            threading.Thread(target=self.handle_client, args=(conn, callback,)).start()

    def handle_client(self, sock, miner_callback):
        """
        Handle new client. receives a Socket connection and a reference to the miner
        new transaction handler function.
        :param sock: Socket
        :param miner_callback: method reference
        :return:
        """
        while True:
            tx_bin = _receive(sock)
            tx = Transaction().deserialize(tx_bin)
            #tx.deserialize(tx_bin)
            miner_callback(tx)

class MinerClient:
    """
    Miner client. Used to connect a miner as send it new transactions
    """
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, ip, port):
        """
        Connect to a miner
        :param ip: str
        :param port: port
        :return:
        """
        self.socket.connect((ip, port))

    def send_tx(self, tx):
        """
        Sends new transaction request
        :param tx: transaction
        :return: None
        """
        _send(self.socket, tx.serialize())