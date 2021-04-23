import socket, struct, json, threading
from Crypto.Hash import SHA256, RIPEMD160
from Crypto.PublicKey import RSA
from transaction import Transaction, Input, Inputs, Output
from fullnode import NodeAPI
from miner import MinerClient

DEFAULT_RSA_KEY_SIZE = 1024

ADDR_REGULAR = 0
ADDR_CHANGE = 1

class KeyAddress:
    """
    Holds asymmetric keys pair and their relative address
    """
    def __init__(self, rsa_key, addr_type=ADDR_REGULAR):
        """
        :param rsa_key: RSA key
        :param addr_type: regular address or change address
        """
        self.__key = rsa_key
        self.__address = self.__generate_address()
        self.__type = addr_type

    def __generate_address(self):
        """
        Generates new address
        :return: binary
        """
        sha = SHA256.new(self.public_key.export_key()).digest()
        rip = RIPEMD160.new(sha).digest()
        return rip.hex()

    @property
    def type(self):
        return self.__type

    @property
    def private_key(self):
        return  self.__key

    @property
    def public_key(self):
        return self.__key.publickey()

    @property
    def address(self):
        return self.__address

class Keys:
    """
    Holds KeyAddress list
    """
    def __init__(self):
        self.keys = []

    def generate_new_keys(self, addr_type=ADDR_REGULAR):
        """
        Generates new RSA keys and returns their relative address and returns them in a tuple
        :param addr_type: address type
        :return: tuple
        """
        private_key = RSA.generate(DEFAULT_RSA_KEY_SIZE)
        new_keys = KeyAddress(private_key, addr_type)
        self.keys.append(KeyAddress(private_key, addr_type))

        return new_keys

    def get_keys(self, **kwargs):
        """
        Returns a KeyAddress per given parameter (private ket, public key or address)
        :param kwargs: str
        :return: KeyAddress
        """
        for key in self.keys:
            if 'private_key' in kwargs and key.private_key == kwargs['private_key'] or \
               'public_key' in kwargs and key.public_key == kwargs['public_key'] or \
               'address' in kwargs and key.address == kwargs['address']:
                return key

    def get_all(self):
        """
        Return all keys
        :return: list
        """
        return self.keys

    def get_addresses(self):
        """
        Returns all addresses
        :return: list
        """
        return [key.address for key in self.keys]

class TxHistory:
    """
    Wallet's transactions history
    """
    def __init__(self):
        self.income = []
        self.spent = []

    def add_income(self, utxo): # utxo is a UTXO object
        """
        Adds new income transaction
        :param utxo: UTXO
        :return: None
        """
        self.income.append({'hash': utxo.output.hash().hex(),
                            "address": utxo.output.recipient,
                           "date": utxo.str_date(),
                            'amount': utxo.output.amount})

    def add_spent(self, tx):
        """
        Adds new spent transaction
        :param tx: Transaction
        :return: None
        """
        tx_hash = tx.hash().hex()
        for output in tx.outputs:
            self.spent.append({'hash': tx_hash,
                               'address': output.recipient,
                               'date': tx.str_date(),
                               'amount': output.amount})
    def export(self):
        return {"income": self.income, "spent": self.spent}

class Wallet:
    """
    Crypto wallet.
    * Creates and manages keys and addresses
    * Creates and sends new transactions
    * Receives transactions
    * Stores data of local addresses (utxo) and balance
    * Saves income/spent transactions history

    The wallet must be connected to a Node, from which it extracts data about the block chain.
    It may also connect to a miner (or any server that connects to a miner), to which it will send
    new transactions to be verified and inserted into a block. This option is optional, and in such
    case new transaction will have to be sent manually to the miner.
    """
    def __init__(self, node_address, miner_address=None):
        """
        Initializes Wallet
        :param node_address: tuple (node ip and port)
        :param miner_address: tuple (optional)
        """
        self.node = NodeAPI(node_address[0], node_address[1])
        self.node.connect()
        self.miner = None
        # creates a miner if miner addresses are provided
        if miner_address:
            self.miner = MinerClient()
            self.miner.connect(miner_address[0], miner_address[1])

        self.keys = Keys()
        self.history = TxHistory()
        self.unspent = []
        self.balance = 0
        # the last block index which the wallet is up to date to
        self.last_updated_block = 0

    def new_address(self):
        """
        Creates new address
        :return: None
        """
        new_key = self.keys.generate_new_keys()
        return new_key.address

    def get_unspent(self, addresses):
        """
        Returns utxo for given addresses. If no addresses are provided, the method returns
        for all the addresses in the wallet
        :param addresses: list
        :return: list
        """
        if not addresses:
            addresses = self.keys.get_addresses()
        return self.node.get_utxo(addresses)

    def set_balance(self): pass

    def create_transaction(self, address, recipients:list, amount, miner_fee):
        """
        Creates new transaction and send it to the miner (if provided) or returns
        the new transaction. Receives list of recipients containing tuples of
        recipient's address and amount.
        If total amount is bigger than the actual spent amount, the wallet will
        create a new change address and transfer the difference to that new address.
        :param address: bytes
        :param recipients: list
        :param amount: float
        :param miner_fee: float
        :return: Transaction or None
        """
        # fetch all available
        # should ask for full node for all available addresses
        if not address:
            address = self.keys.get_addresses()
        else:
            address = [address]
        utxo_list = self.node.get_utxo(address)
        spent = []
        total = 0
        for utxo in utxo_list:
            total += utxo.output.amount
            spent.append(utxo.output)
            if total >= (amount + miner_fee):
                break

        # create inputs
        inputs = []
        for utxo in spent:
            key = self.keys.get_keys(address=utxo.recipient)
            i = Input(utxo, key.public_key)
            i.sign(key.private_key)
            inputs.append(i)
        inputs = Inputs(inputs)

        # create outputs
        outputs = []
        for recipient, amount in recipients:
            outputs.append(Output(address, recipient, amount))
        # creates change output if needed
        if total > (amount + miner_fee):
            change = total - (amount + miner_fee)
            change_address = self.keys.generate_new_keys(ADDR_CHANGE)
            outputs.append(Output(address, change_address.address, change))

        # create transaction
        # takes the first utxo address for additional signing
        key = self.keys.get_keys(address=address[0])
        tx = Transaction(Inputs(inputs, total), outputs, 0.01, key.public_key)
        tx.sign(key.private_key)
        self.history.add_spent(tx)
        # Sends the new transaction to a miner or returns it
        if self.miner:
            self.miner.send_tx(tx)
        else:
            return tx

    def receive_transaction(self, addresses):
        """
        Fetch new transactions for given addresses from Node and adds it to history
        :param addresses: list
        :return: None
        """
        utxo_list = self.get_unspent(addresses)
        for utxo in utxo_list:
            self.history.add_income(utxo)

########################
# Wallet server wrapper
#######################

# Request types constants
UTXO = 0 # request includes addresses
ADDRESSES = 1 # no parameters. returns key addresses
NEW_TX = 2 # utxo's, recipient addresses and their amount
RECEIVE = 3 # addresses or none to receive for all addresses
WALLET_DETAILS = 4
NEW_ADDRESS = 5 # no parameters. returns new address from wallet

class Request:
    """
    Wallet request
    """
    def __init__(self, _type, **kwargs):
        """
        :param _type: int
        :param kwargs: dict keywords
        """
        self.type = _type
        self.args = kwargs

    def json(self):
        """
        Returns in JSON format
        :return: JSON object
        """
        return json.dumps({'type':self.type, 'args': self.args})

class WalletServer:
    """
    Wallet network wrap. Used for network communication with a wallet.
    Serialization is in JSON format to allow more flexibility and used
    with non python-written client.
    """
    def __init__(self, wallet):
        """
        :param wallet: Wallet
        """
        self.wallet = wallet
        # receive for all wallet's addresses
        self.wallet.receive_transaction(None)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client = None

    def start(self, ip, port):
        """
        Start listening and accepting connections
        :param ip: str
        :param port: int
        :return: None
        """
        self.socket.bind((ip, port))
        self.socket.listen(5)
        print ("Wallet client listening for a connection...")
        while True:
            conn, address = self.socket.accept()
            print ("wallet accepted connection from:" , address)
            self.client = conn
            threading.Thread(target=self.handle_client).start()

    def handle_client(self):
        """
        Receives and handle requests from clients.
        :return: None
        """
        while True:
            request = self.__receive()
            try:
                request = json.loads(request)
                # param = request['param'] if 'args' in request else None
                # request = Request(request['type'], param=param)
            except Exception as e:
                raise Exception("Failed to parse request. Make sure the request matches JSON format")
            response = self.handle_request(request)
            print(response)
            self.__send(response.encode())

    def __send(self, data):
        """
        Send data
        :param data: bytes
        :return: None
        """
        size = struct.pack('!I', len(data))
        self.client.sendall(size)
        self.client.sendall(data)

    def __receive(self):
        """
        Receives data from clients
        :return: bytes
        """
        data_size = self.client.recv(4)
        data_size = struct.unpack('!I', data_size)[0]
        data = b''
        while len(data) < data_size:
            buffer = self.client.recv(data_size - len(data))
            if buffer:
                data += buffer
        return data

    def handle_request(self, request):
        """
        Handles requests through the wallet and returns teh response
        :param request: Request
        :return: Request
        """
        _type = request['type']
        if _type == WALLET_DETAILS:
            addresses = self.wallet.keys.get_addresses()
            utxo = self.wallet.get_unspent(addresses)
            utxo = [unspent.summary() for unspent in utxo]
            history = self.wallet.history.export()
            return Request(WALLET_DETAILS, addresses=addresses, utxo=utxo, history=history).json()
        elif _type == ADDRESSES:
            return self.wallet.keys.get_addresses()
        elif _type == NEW_ADDRESS:
            return Request(NEW_ADDRESS, address=self.wallet.new_address()).json()
        elif _type == NEW_TX:
            tx = request['tx']
            # changing dict to tuple
            tx['recipients'] = \
                [(recipient['recipient'], recipient['amount']) for recipient in tx['recipients']]
            self.wallet.create_transaction(None, tx['recipients'], tx['amount'], tx['fee'])
            return Request(NEW_TX).json()

        elif request.type == RECEIVE:
            return self.wallet.receive_transaction(request.args['addresses'])
