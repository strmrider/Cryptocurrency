import hashlib, pickle, json, struct
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, RIPEMD160
from datetime import datetime
from Crypto.PublicKey import RSA

DATE_STR = '%m/%d/%Y, %H:%M:%S'

class Authentication:
    """
    Handles authentications
    """
    def __init__(self, public_key):
        """
        :param public_key: RSA public key
        """
        self.public_key = public_key
        self.signature = None

    def bin(self):
        """
        Converts key to binary data
        :return: bytes
        """
        return self.public_key.export_key()

    def sign(self, private_key, bin_message):
        """
        Signs given data with private key and saves the signature.
        The private key must be related to the public key.
        :param private_key: RSA private key.
        :param bin_message: bytes
        """
        h = SHA256.new(bin_message)
        self.signature = pkcs1_15.new(private_key).sign(h)

    def verify_address(self, address):
        """
        Verifies if an address is related to the public key.
        :param address: bytes
        :return: bool
        """
        sha = SHA256.new(self.public_key.export_key()).digest()
        rip = RIPEMD160.new(sha).digest()
        return rip.hex() == address

    def verify_signature(self, bin_message):
        """
        Verifies signature. Checks if the binary message - which was originally used for the signature -
        was signed by the respective private key of the class's provided public key.
        :param bin_message: bytes
        :return: bool
        """
        h = SHA256.new(bin_message)
        try:
            pkcs1_15.new(self.public_key).verify(h, self.signature)
            return True
        except Exception as e:
            return False

    def validate_format(self):
        """
        Verifies public key and signature formatting
        :return: bool
        """
        if self.public_key and self.signature and len(self.signature) > 0:
            return True
        else:
            return False

    def to_json(self):
        """
        Converts to json
        :return: Json object
        """
        return json.dumps(self.object())

    def object(self):
        """
        Converts class to object
        :return: dict
        """
        return {'public_key': self.public_key.export_key(), 'signature': self.signature}

    def deserialize(self, obj):
        """
        Set class's properties from dict
        :param obj: dict
        :return: None
        """
        self.public_key = RSA.importKey(obj['public_key'])
        self.signature = obj['signature']

class Output:
    """
    A transaction output
    """
    def __init__(self, sender=b'', recipient=b'', amount=0):
        """
        Initiates the output
        :param sender: bytes
        :param recipient: bytes
        :param amount: int
        """
        self.sender = sender
        self.recipient = recipient
        self.amount = amount

    def bin(self):
        """
        Converts output's properties into binary data
        :return: binary
        """
        return '{}{}{}'.format(self.sender, self.recipient, self.amount).encode()

    def hash(self):
        """
        Hashes the output
        :return: bytes
        """
        return hashlib.sha256(self.bin()).digest()

    def validate_format(self):
        """
        Validates that output's properties are valid and in the correct format
        :return: bool
        """
        if (len(self.sender) > 0 or len(self.recipient) > 0 or self.amount > 0) \
                and self.sender != self.recipient:
            return True
        else:
            return False

    #################
    # Serializations
    #################

    def object(self):
        return self.__dict__

    def serialize(self):
        """
        Returns the output in bytes
        :return: bytes
        """
        return pickle.dumps(self.object())

    def deserialize(self, serial):
        """
        Reconstructs the output from bytes
        :param serial: bytes
        :return: Output
        """
        obj = pickle.loads(serial)
        self.sender = obj['sender']
        self.recipient = obj['recipient']
        self.amount = obj['amount']
        return self

    def __repr__(self):
        return '{} => {} : {}'.format(self.sender, self.recipient, self.amount)

class Input:
    """
    Transaction's input. Unspent output, signed by the owner of the recipient address.
    For an input to be valid it must meet two conditions:
    * The input must be present in the block chain as an output
    * It's address must be signed by the respective private key and then be verified
    """
    def __init__(self, output=None, public_key=None):
        """
        :param output: Output or None by default
        :param public_key: RSA public or None by default
        """
        self.address = output.recipient if output else ''
        self.amount = output.amount if output else 0
        self.hash = output.hash() if output else b''
        self.auth = Authentication(public_key)

    def bin(self):
        """
        Converts all properties into an array of bytes
        :return: bytes
        """
        if isinstance(self.amount, float):
            amount = bytearray(struct.pack("f", self.amount))
        else:
            amount = bytes(self.amount)
        return self.hash + self.address.encode() + amount + self.auth.bin()

    def verify(self):
        """
        Verifies input's address and signature
        :return:bool
        """
        return self.auth.verify_address(self.address) and self.auth.verify_signature(self.bin())

    def sign(self, private_key):
        """
        Signs input
        :param private_key: RSA private key
        :return: None
        """
        self.auth.sign(private_key, self.bin())

    def validate_format(self):
        """
        Validates that input is in correct data format
        :return: bool
        """
        if self.address and len(self.address) > 0 and \
                self.hash and len(self.hash) > 0 and \
                self.auth.validate_format():
            return True
        return False

    def json_format(self):
        """
        Json object
        :return: dict
        """
        return {'hash': self.hash.hex(), 'address': self.address, 'amount': self.amount}

    def object(self):
        """
        Converts input to odict
        :return: dict
        """
        return {'hash': self.hash,
                'address': self.address,
                'amount': self.amount,
                'auth': self.auth.object()}

    def serialize(self):
        """
        Serializes input
        :return: bytes
        """
        return pickle.dumps(self.object())

    def deserialize(self, serial):
        """
        Deserialize bytes and set properties
        :param serial: bytes
        :return: Input
        """
        obj = pickle.loads(serial)
        self.hash = obj['hash']
        self.address = obj['address']
        self.amount = obj['amount']
        self.auth.deserialize(obj['auth'])
        return self

class Inputs:
    """
    List of inputs
    """
    def __init__(self, inputs_list=None, total_amount=0):
        """
        Default values are for empty inputs list
        :param inputs_list:  list None by default
        :param total_amount: int
        """
        self.__inputs = inputs_list if inputs_list else []
        self.total_amount = total_amount

    def get_hashes(self):
        """
        Returns all inputs hashes
        :return: list
        """
        hashes = {}
        for utxo in self.__inputs:
            if utxo.address in hashes:
                hashes[utxo.address].append(utxo.hash)
            else:
                hashes[utxo.address] = [utxo.hash]
        return hashes

    def bin(self):
        """
        Converts all inputs to bytes
        :return: bytes
        """
        input_bins = b''
        for utxo in self.__inputs:
            input_bins += utxo.bin()
        return input_bins

    def verify_inputs(self):
        """
        Verifies all inputs
        :return: bool
        """
        for utxo in self.__inputs:
            if not utxo.verify():
                return False
        return True

    def filter_inputs(self, confirmed_utxo):
        """
        Filters inputs according to a confirmed unspent outputs list (usually provided by a node).
        :param confirmed_utxo: list; confirmed utxo's
        :return: None
        """
        new_inputs = []
        for utxo in self.__inputs:
            if utxo.hash in confirmed_utxo:
                new_inputs.append(utxo)
        self.__inputs = new_inputs

    def json_format(self):
        """
        Returns all inputs in json format
        :return: list
        """
        return [_input.json_format() for _input in self.__inputs]

    def serialize(self):
        """
        Serializes all inputs
        :return: list
        """
        return [utxo.serialize() for utxo in self.__inputs]

    def validate_format(self):
        """
        Validates that all inputs are in the correct data format
        :return: bool
        """
        if len(self.__inputs) > 0:
            for unspent in self.__inputs:
                if not unspent.validate_format():
                    return False
            return True
        else:
            return False

    def __contains__(self, tx_hash):
        """
        Checks if an input is in list
        :param tx_hash: bytes
        :return: bool
        """
        for tx in self.__inputs:
            if tx.hash_transaction() == tx_hash:
                return True
        return False

    def __getitem__(self, item):
        """
        Returns input by index
        :param item: int
        :return: Input
        """
        return self.__inputs[item]

    def __iter__(self):
        """
        Returns iterable inputs list
        :return: iterator
        """
        return iter(self.__inputs)

    def __len__(self):
        """
        returns number of inputs
        :return: int
        """
        return len(self.__inputs)

class Transaction:
    """
    Transaction data
    """
    def __init__(self, inputs=None, outputs=None, fee=0, public_key= b''):
        """
        Default values are used for an empty transaction, commonly used for serialization.
        For instance:
        tx = Transaction()
        tx.deserialize(serialized)

        :param inputs: Inputs
        :param outputs: list
        :param fee: int
        :param public_key: bytes
        """
        self.inputs = inputs if inputs else Inputs()
        self.outputs = outputs if outputs else []
        self.miner_fee = fee
        self.date = datetime.now()
        self.auth = Authentication(public_key)

    def str_date(self):
        """
        Converts datetime to string
        :return: str
        """
        return self.date.strftime(DATE_STR)

    def bin(self):
        """
        Returns transaction in byes. Used for hashing.
        :return: bytes
        """
        header = '{}{}'.format(self.miner_fee, self.str_date()).encode()
        outputs_bin = b''.join([output.bin() for output in self.outputs])
        return header + outputs_bin + self.inputs.bin() + self.auth.bin()

    def amount(self):
        """
        Returns total spent amount from output
        :return: int
        """
        amount = 0
        for output in self.outputs:
            amount += output.amount
        return amount

    def hash(self):
        """
        Hashes transaction
        :return: bytes
        """
        return hashlib.sha256(self.bin()).digest()

    def sign(self, private_key):
        """
        Singns Transaction. Private key must ne related to the given public.
        :param private_key: RSA private key
        :return: None
        """
        self.auth.sign(private_key, self.bin())

    def verify(self):
        """
        Verifies transaction by verifying its signature and inputs signatures
        :return: bool
        """
        return self.auth.verify_signature(self.bin()) \
               and self.inputs.verify_inputs()

    def validate_format(self):
        """
        Validates that the transaction is in the correct data format:
        at least one valid output, valid inputs, fees, signature and date
        :return: bool
        """
        # at least one valid output exists
        if len(self.outputs) > 0:
            for output in self.outputs:
                if not output.validate_format():
                    return False
        # valid inputs
        if not self.inputs.validate_format():
            return False
        # invalid fees and signature
        if self.miner_fee <= 0 and not self.auth.validate_format():
            return False
        try:
            # date in correct string format
            self.str_date()
        except Exception:
            return False

        return True

    def to_json(self):
        """
        Converts to json object
        :return: json
        """
        obj = {'inputs': self.inputs.json_format(),
               'outputs': [output.object() for output in self.outputs],
               'hash': self.hash().hex(),
               'date': self.str_date(),
               'fee': self.miner_fee,
               'size': len(self.bin())}
        return json.dumps(obj)

    def serialize(self):
        """
        Returns transaction in bytes
        :return: bytes
        """
        outputs = [output.serialize() for output in self.outputs]
        obj = {'inputs': self.inputs.serialize(),
               'outputs': outputs,
               'auth': self.auth.object(),
               'fee': self.miner_fee,
               'date': self.str_date()}
        return pickle.dumps(obj)

    def deserialize(self, serialized):
        """
        Set transaction from bytes, commonly used with default init
        :param serialized: bytes
        :return: None
        """
        obj = pickle.loads(serialized)
        self.outputs = [Output().deserialize(output_obj) for output_obj in obj['outputs']]
        inputs = [Input().deserialize(input_obj) for input_obj in obj['inputs']]
        self.inputs = Inputs(inputs)
        self.auth.deserialize(obj['auth'])
        self.miner_fee = obj['fee']
        self.date = datetime.strptime(obj['date'], DATE_STR)

        return self

    def __repr__(self):
        """
        Prints transaction's details
        :return: str
        """
        caption = 'Transaction: Inputs: {}' \
                  ' Outputs: {} Amount: {} ' \
                  'Fee: {} ' \
                  'Date: {}'.format(len(self.inputs),
                                    len(self.outputs)
                                    ,self.amount(),
                                    self.miner_fee,
                                    self.str_date())
        outputs = ''
        for output in self.outputs:
            outputs += output.__repr__() + '\n\t'

        return caption + '\n\t' +outputs

def initial_tx(recipients):
    """
    Returns an initial transaction for new a blockchain
    :param recipients: list; list of tuples containing addresses and amounts
    :return: Transaction
    """
    rsa_key = RSA.generate(1024)
    tx = Transaction(None, recipients, 0, rsa_key.publickey())
    tx.sign(rsa_key)
    return tx