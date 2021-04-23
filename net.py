"""
The module handles nodes networking functions
"""

import socket, threading, struct, pickle, uuid

def _send(sock, data):
    """
    Sends data and its size via socket
    :param sock: socket
    :param data: bytes
    :return: None
    """
    size = struct.pack('!I', len(data))
    sock.sendall(size)
    sock.sendall(data)

def _receive(data_size, conn):
    """
    Receives all data from connection
    :param data_size: int
    :param conn: socket
    :return: bytes
    """
    data = b''
    while len(data) < data_size:
        buffer = conn.recv(data_size - len(data))
        if buffer:
            data += buffer
    return data

class Event:
    """
    Simple event emitter
    """
    def __init__(self):
        self.callback = None

    def emit(self, data):
        """
        Emits event
        :param data: any
        :return: any (callback return value)
        """
        if self.callback:
            return self.callback(data)

    def subscribe(self, callback):
        """
        Subscribes a function nto the event
        :param callback:
        :return: None
        """
        self.callback = callback

class Request:
    """
    Request container for a Node
    """
    def __init__(self, request_type, data, request_id=None):
        """
        :param request_type: int
        :param data: object
        :param request_id: str
        """
        self.id = request_id if request_id else str(uuid.uuid4()).replace('-', '')
        self.type = request_type
        self.data = data

    def serialize(self):
        """
        Serializes request
        :return:  None
        """
        return pickle.dumps(self.__dict__)

    @staticmethod
    def deserialize(serial):
        """
        Deserialize request
        :param serial: bytes
        :return: Request
        """
        obj = pickle.loads(serial)
        return Request(obj['type'], obj['data'], obj['id'])

class NodeSocket:
    """
    Handles Node's network communication with other nodes.
    Used only by a Node instance.
    """
    def __init__(self, local_peer, peers):
        """
        receives peer's ip (str) and port (int) and peers list
        :param local_peer: tuple
        :param peers: list
        """
        self.local_peer = local_peer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peers = peers
        self.income_request_emitter = Event()
        self.ip = self.port = None

        self.sent_requests = []
        self.received_requests = []

    def start(self, ip, port):
        """
        creates a server socket
        :param ip: str
        :param port: int
        :return: None
        """
        self.ip = ip
        self.port = port
        self.socket.bind((ip, port))
        self.socket.listen(5)

        # accepts connection
        while True:
            conn, address = self.socket.accept()
            threading.Thread(target=self.handle_request, args=(conn,)).start()

    def num_of_peers(self):
        """
        Returns number of peers
        :return: int
        """
        return len(self.peers)

    def handle_request(self, conn):
        """
        Handles income request and transfer to the node
        :param conn:
        :return:
        """
        while True:
            try:
                size = conn.recv(4)
                request_size = struct.unpack('!I',size)[0]
                request = _receive(request_size, conn)
                request = pickle.loads(request)
                # prevents from receiving the same request again
                if request.id not in self.received_requests:
                    self.received_requests.append(request.id)
                    # emits an event for the node and receives a response
                    response = self.income_request_emitter.emit(request)
                    # sends back the response if exist
                    if response:
                        if isinstance(response, str):
                            response = response.encode()
                        _send(conn, response)
            # throws exception in case connection failure occurs
            except Exception as e:
                #print (e)
                break

    def broadcast(self, data):
        """
        Broadcast data through peers network
        :param data: Request
        :return: None
        """
        if not self.peers:
            raise Exception("Node socket error: can't broadcast. Peers network not provided")
        # prevents request resend
        if data.id in self.sent_requests:
            return
        self.sent_requests.append(data.id)
        for peer in self.peers:
            # prevents node from sending to itself
            if peer.id != self.local_peer:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((peer.ip, peer.port))
                _send(s, pickle.dumps(data))
                s.close()

class NodeAPI:
    """
    API for network communication between a Node and non-Node (such as miners or a wallet)
    """
    def __init__(self, ip, port):
        """
        :param ip: str
        :param port: int
        """
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        """
        Connect to node
        :return: None
        """
        self.socket.connect((self.ip, self.port))

    def __send(self, data):
        size = struct.pack('!I', len(data))
        self.socket.sendall(size)
        self.socket.sendall(data)

    def __receive_response(self):
        """
        receives response from node
        :return: None
        """
        response_size = self.socket.recv(4)
        response_size = struct.unpack('!I', response_size)[0]
        response = _receive(response_size, self.socket)
        return response

    def get_chain(self):
        request = Request('json_chain', None)
        request = pickle.dumps(request)
        self.__send(request)
        response = self.__receive_response()
        return response.decode()

    def new_block(self, block):
        """
        New block request
        :param block: Block
        :return: None
        """
        request = Request('new block', {'block': block.serialize()})
        request = pickle.dumps(request)
        self.__send(request)

    def get_utxo(self, addresses):
        """
        get unspent transaction outputs list for given addresses
        :param addresses: list
        :return: list
        """
        request = Request('utxo', {'addresses': addresses})
        request = pickle.dumps(request)
        self.__send(request)
        response = self.__receive_response()
        return pickle.loads(response)

    def validate_transactions(self, txs):
        """
        request node to validate transactions
        :param txs: list
        :return: bool
        """
        request = Request('valid txs', {'txs': txs})
        request = pickle.dumps(request)
        self.__send(request)
        response = self.__receive_response()
        return pickle.loads(response)

    def get_blocks(self, indexes):
        """
        request blocks per index from node
        :param indexes: list
        :return: list
        """
        request = Request('get blocks', {'indexes': indexes})
        request = pickle.dumps(request)
        self.__send(request)
        return self.__receive_response()

class BlockChainExplorer:
    """
    A server that connects to a Node and fetch all the block chain for clients
    """
    def __init__(self, server_address, node_address):
        """
        :param server_address: tuple (ip, port)
        :param node_address: tuple (ip, port)
        """
        self.node_ip, self.node_port = node_address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(server_address)
        self.socket.listen(5)

    def run(self):
        """
        Runs the server
        :return: None
        """
        print('Explorer is listening...')
        while True:
            conn, addr = self.socket.accept()
            print ('Explorer accepted new connection from:', addr)
            node = NodeAPI(self.node_ip, self.node_port)
            node.connect()
            chain = node.get_chain()
            _send(conn, chain.encode())