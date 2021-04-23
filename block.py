"""
The module contains block chain's block and its related functions
"""

import time, hashlib, json, pickle
from transaction import Transaction

TOTAL_HASH_ATTEMPTS = 1000000

class MerkleTree:
    """
    Represents a Merkle Tree
    """
    def __init__(self, hash_list=None):
        """
        Receives list of hashes
        :param hash_list: list
        """
        self.hash_list = hash_list if hash_list else []

    def cal_root(self):
        """
        Computes Merkle tree root
        :return: bytes
        """
        if len( self.hash_list) == 1:
            return  self.hash_list[0]
        new_list = []
        for i in range(0, len( self.hash_list)-1, 2):
            hash_sum = self.hash_list[i] + self.hash_list[i+1]
            combined_hash = hashlib.sha256(hashlib.sha256(hash_sum).digest()).digest()
            new_list.append(combined_hash[::-1])
        if len( self.hash_list) % 2 == 1:
            hash_sum = self.hash_list[-1] + self.hash_list[-1]
            combined_hash = hashlib.sha256(hashlib.sha256(hash_sum).digest()).digest()
            new_list.append(combined_hash[::-1])

        self.hash_list = new_list
        return self.cal_root()

class Data:
    """
    Block's data template
    """
    def __init__(self, data=b''):
        self.data = data if data else b''

    def serialize(self): pass

    def deserialize(self, serial): pass

class Txs(Data):
    """
    Block's transactions list
    """
    def __init__(self, txs=b''):
        """
        :param txs: list or bytes
        """
        super().__init__(txs)

    def json_format(self):
        """
        Returns a list of transactions in Json format
        :return: list
        """
        return [tx.to_json() for tx in self.data]

    def serialize(self):
        """
        Serializes data
        :return: bytes
        """
        if self.data == b'':
            return None
        return pickle.dumps([tx.serialize() for tx in self.data])

    def deserialize(self, serial):
        """
        Reconstructs the data from bytes
        :param serial: bytes
        :return: None
        """
        self.data = []
        txs_list = pickle.loads(serial)
        for tx in txs_list:
            new_tx = Transaction()
            new_tx.deserialize(tx)
            self.data.append(new_tx)

    def __iter__(self):
        return iter(self.data)

    def __getitem__(self, item):
        return self.data[item]

# In order to keep the chain generic and not data-depended (transaction list for instance) the Merkle root
# is calculated by the miner and provided to the block
class Block:
    """
    Block chain's block. Stores block's header and data
    """
    def __init__(self, miner=b'', block_index=-1, prev_hash=b'', merkle_root=b'', data=None):
        """
        :param miner: str (miner's address)
        :param block_index: int
        :param prev_hash: bytes
        :param merkle_root: bytes
        :param data: Data or None
        """
        self.miner = miner # miner identifier. could be anything such as cryptocurrency address
        self.index = block_index
        self.timestamp = time.time()
        self.difficulty = 0 # PoW difficulty (number of total difficulty or number of zeros at the beginning)
        self.nonce = 0 # proof of work
        self.prev_block_hash = prev_hash
        # Merkle tree root
        self.root = merkle_root
        # actual data. could be any kind of data such as transaction list
        self.data = data

    def get_header_in_bytes(self):
        """
        Returns block's header in bytes
        :return: bytes
        """
        header =  '{}{}{}{}{}'.format(self.timestamp, self.root, self.prev_block_hash, self.difficulty, self.nonce)
        return header.encode()

    def hash_block(self):
        """
        Returns block's hash value in hex
        :return: bytes
        """
        header = self.get_header_in_bytes()
        return hashlib.sha256(hashlib.sha256(header).digest()).digest()

    def cal_header_hash(self):
        """
        Calculates header's hash value and sets it's nonce
        :return: None
        """
        self.timestamp = time.time()
        header = self.get_header_in_bytes()
        attempts = 0
        # run as long as nonce is int size (32 bit) and number of attempts is in its limit
        while self.nonce < 0x100000000 and attempts < TOTAL_HASH_ATTEMPTS:
            current_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
            target = self.calculate_target()
            if current_hash < target:
                self.header_hash = current_hash
                break
            else:
                attempts += 1
                self.nonce += 1

    def calculate_target(self):
        exp = self.difficulty >> 24
        mant = self.difficulty & 0xffffff
        target_hexstr = '%064x' % (mant * (1 << (8 * (exp - 3))))
        target_str = target_hexstr.decode('hex')

        return target_str

    def is_valid(self):
        """
        Validates block
        :return: bool
        """
        header_hash = self.hash_block()
        if header_hash:
            # return len(header_hash) == self.difficulty
            return header_hash[:1] == b'0'
        else:
            return False

    def object(self):
        """
        Returns block as object
        :return: dict
        """
        obj = {'miner': self.miner,
               'index': self.index,
               'time': self.timestamp,
               'nonce': self.nonce,
               'hash': self.cal_header_hash(),
               'difficulty': self.difficulty,
               'prev_hash': self.prev_block_hash,
               'root': self.root,
               'data': self.data.serialize() if isinstance(self.data, Txs) else None}

        return obj

    def to_json(self):
        """
        Returns block in Json format
        :return: JSON
        """
        obj = self.object()
        obj['prev_hash'] = self.prev_block_hash.hex()
        obj['root'] = self.root.hex()
        obj['data'] = self.data.json_format()
        return json.dumps(obj)

    def serialize(self):
        """
        Returns block in bytes
        :return: byte
        """
        return pickle.dumps(self.object())

    def deserialize(self, block_serial):
        """
        Reconstructs block from bytes
        :param block_serial: bytes
        :return: None
        """
        obj = pickle.loads(block_serial)

        self.miner = obj['miner']
        self.index = obj['index']
        self.timestamp = obj['time']
        self.nonce = obj['nonce']
        self.difficulty = obj['difficulty']
        self.prev_block_hash = obj['prev_hash']
        self.root = obj['root']
        if obj['data']:
            self.data = Txs()
            self.data.deserialize(obj['data'])
        else:
            self.data = None