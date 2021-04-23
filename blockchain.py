import pickle, json
from block import Block

class BlockChain:
    """
    Represents a block chain.
    """
    def __init__(self, chain=None):
        # wait few more block before fully trust new block if corresponded blocks arrived create a fork
        self.chain = chain if chain else [self.create_genesis()]

    def create_genesis(self):
        """
        Generates a Genesis Block
        :return: Block
        """
        return Block(0, 0, b'0', b'0', b'')

    def add_block(self, block):
        """
        Adds new block to the chain.
        :param block: Block
        :return: bool; returns whether the block was successfully added
        """
        # checks for errors in new block's position
        if block.index != 0 and len(self.chain) == 0:
            raise Exception('Chain was not initiated. Insert Genesis block first')
        elif len(self.chain) < block.index:
            raise Exception("New block's position doesn't fit chain's order")
        elif block.index == 0 and len(self.chain) == 1:
            raise Exception("Genesis block is already exist")
        elif block.index == 0:
            self.chain.append(block)
            return True
        # validates the block and verifies the chain with the new block
        elif block.is_valid() and self.verify_chain(block):
            self.chain.append(block)
            return True
        else:
            return False

    def verify_chain(self, new_block=None):
        """
        Verifies the block chain. Also verifies with a new block if provided.
        :param new_block: Block or None (default)
        :return: tuple (bool, int); returns a tuple containing verification's
                result and the position of an invalid block if an error occurred
                or -1 if there's no error.
        """
        if new_block and (not new_block.is_valid()
                          or self.get_last().hash_block() != new_block.prev_block_hash):
            return False, -2

        i = len(self.chain)-1
        for block in reversed(self.chain):
            prev_hash = self.chain[i-1].hash_block()
            if block.index == 0 or i == 0:
                break
            # block's header_hash property is already recalculated in is_valid() method
            elif block.is_valid() and prev_hash == block.prev_block_hash:
                i -= 1
            else:
                return False, block.index

        return True, -1

    def get_block(self, index):
        """
        Returns a block by index
        :param index: int
        :return: Block or None
        """
        if 0 <= index < len(self.chain):
            return self.chain[index]

    def get_last(self):
        """
        Returns last block in chain
        :return: Block
        """
        return self.get_block(len(self.chain)-1)

    def get_last_index(self):
        """
        Returns last index in chain
        :return: int
        """
        return len(self.chain) - 1

    def get_last_hash(self):
        """
        Returns last block's hash
        :return: bytes
        """
        return self.get_last().hash_block()

    def __iter__(self):
        """
        Iterates over teh chain
        :return: Iterator
        """
        return iter(self.chain)

    def __len__(self):
        """
        Returns chain's size
        :return: int
        """
        return len(self.chain)

    def fetch_all_tx(self):
        """
        Returns all the transactions in the chain
        :return: list
        """
        transactions = []
        for block in self.chain:
            transactions.append(block.data)
        return transactions

    def copy(self):
        """
        Returns a copy of teh block chian
        :return: BlockChain
        """
        new_chain = []
        for block in self.chain:
            if block.index == 0:
                new_chain.append(self.create_genesis())
            else:
                new_block = Block()
                new_block.deserialize(block.serialize())
                new_chain.append(new_block)

        return BlockChain(new_chain)

    def serialize(self):
        """
        Serializes the block chain
        :return: bytes
        """
        return pickle.dumps([block.serialize() for block in self.chain])

    def json(self):
        """
        Returns block chain in Json format
        :return: json
        """
        blocks = [block.to_json() for block in self.chain[1:]]
        return json.dumps({'blocks': blocks})