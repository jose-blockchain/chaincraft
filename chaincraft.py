# chaincraft.py

import json
import random
import socket
import threading
import time
import zlib
import hashlib
import dbm.ndbm
import os
from dataclasses import dataclass
from typing import Any, List, Tuple, Dict, Union


@dataclass
class SharedObject:
    data: Any

    PEER_DISCOVERY = "PEER_DISCOVERY"
    REQUEST_LOCAL_PEERS = "REQUEST_LOCAL_PEERS"
    LOCAL_PEERS = "LOCAL_PEERS"

    def to_json(self):
        return json.dumps(self.data)

    @classmethod
    def from_json(cls, json_str):
        return cls(data=json.loads(json_str))
    

class ChaincraftNode:
    PEERS = "PEERS"

    def __init__(self, max_peers=5, reset_db=False, persistent=False, use_fixed_address=False, debug=False, local_discovery=True):
        self.max_peers = max_peers
        self.use_fixed_address = use_fixed_address

        if use_fixed_address:
            self.host = 'localhost'
            self.port = 7331
        else:
            self.host = '127.0.0.1'
            self.port = random.randint(5000, 9000)

        self.db_name = f"node_{self.port}.db"
        self.persistent = persistent

        if not persistent:
            self.db: Dict[str, str] = {}
        else:
            if reset_db and os.path.exists(self.db_name):
                os.remove(self.db_name)
            self.db: Union[dbm.ndbm._dbm, Dict[str, str]] = dbm.ndbm.open(self.db_name, 'c')

        self.peers: List[Tuple[str, int]] = self.load_peers()

        self.socket = None
        self.is_running = False
        self.gossip_interval = 0.5 # seconds
        self.debug = debug
        self.local_discovery = local_discovery
        self.waiting_local_peer = {}

    def start(self):
        if self.is_running:
            return

        max_retries = 10
        for _ in range(max_retries):
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.bind((self.host, self.port))
                print(f"Node started on {self.host}:{self.port}")
                break
            except OSError:
                if self.use_fixed_address:
                    raise
                self.port = random.randint(5000, 9000)
        else:
            raise OSError("Failed to bind to a port after multiple attempts")

        self.is_running = True
        threading.Thread(target=self.listen_for_messages, daemon=True).start()
        threading.Thread(target=self.gossip, daemon=True).start()

    def close(self):
        self.is_running = False
        if self.socket:
            self.socket.close()
        if self.persistent:
            self.db.close()

    def listen_for_messages(self):
        while self.is_running:
            try:
                compressed_data, addr = self.socket.recvfrom(1500)
                message_hash = self.hash_message(compressed_data)
                if message_hash not in self.db:
                    message = self.decompress_message(compressed_data)
                    self.handle_message(message, message_hash, addr)
            except OSError:
                if not self.is_running:
                    break
                else:
                    raise

    def gossip(self):
        while self.is_running:
            try:
                if self.db:
                    # Create a list of keys to iterate over
                    keys_to_share = [key for key in self.db.keys() if key != self.PEERS.encode()]
                    for key in keys_to_share:
                        object_to_share = self.db[key]
                        if self.persistent:
                            object_to_share = object_to_share.decode()
                        self.broadcast(object_to_share)
                time.sleep(self.gossip_interval)
            except Exception as e:
                print(f"Error in gossip: {e}")

    def connect_to_peer(self, host, port, discovery=False):
        if (host, port) != (self.host, self.port) and (host, port) not in self.peers:
            if len(self.peers) >= self.max_peers:
                replaced_peer = self.peers.pop()
                print(f"Max peers reached. Replacing peer {replaced_peer[0]}:{replaced_peer[1]} with {host}:{port}")
            self.peers.append((host, port))
            self.save_peers()
            print(f"Connected to peer {host}:{port}")
            if discovery:
                self.send_peer_discovery(host, port)

    def send_peer_discovery(self, host, port):
        discovery_message = json.dumps({SharedObject.PEER_DISCOVERY: f"{self.host}:{self.port}"})
        compressed_message = self.compress_message(discovery_message)
        self.socket.sendto(compressed_message, (host, port))

    def connect_to_peer_locally(self, host, port):
        if (host, port) != (self.host, self.port):
            self.waiting_local_peer[(host, port)] = True
            self.send_local_peer_request(host, port)

    def send_local_peer_request(self, host, port):
        request_message = json.dumps({SharedObject.REQUEST_LOCAL_PEERS: f"{self.host}:{self.port}"})
        compressed_message = self.compress_message(request_message)
        self.socket.sendto(compressed_message, (host, port))

    def compress_message(self, message: str) -> bytes:
        return zlib.compress(message.encode())

    def decompress_message(self, compressed_message: bytes) -> str:
        return zlib.decompress(compressed_message).decode()

    def hash_message(self, compressed_message: bytes) -> str:
        return hashlib.sha256(compressed_message).hexdigest()

    def broadcast(self, message: str):
        compressed_message = self.compress_message(message)
        message_hash = self.hash_message(compressed_message)
        failed_peers = []
        for peer in self.peers:
            try:
                self.socket.sendto(compressed_message, peer)
                if self.debug:
                    print(f"Node {self.port}: Sent message to peer {peer}")
            except Exception as e:
                if self.debug:
                    print(f"Node {self.port}: Failed to send message to peer {peer}. Error: {e}")
                failed_peers.append(peer)
        for peer in failed_peers:
            self.peers.remove(peer)
            self.save_peers()
        return message_hash

    def handle_message(self, message, message_hash, addr):
        try:
            if message_hash not in self.db:
                self.db[message_hash] = message
                if self.debug:
                    print(f"Node {self.port}: Received new object with hash {message_hash} Object: {message}")
                self.broadcast(message)

                shared_object = SharedObject.from_json(message)
                if isinstance(shared_object.data, dict):
                    if SharedObject.PEER_DISCOVERY in shared_object.data:
                        peer_address = shared_object.data[SharedObject.PEER_DISCOVERY]
                        host, port = peer_address.split(":")
                        self.connect_to_peer(host, int(port), discovery=True)
                    elif SharedObject.REQUEST_LOCAL_PEERS in shared_object.data and self.local_discovery:
                        requesting_peer = shared_object.data[SharedObject.REQUEST_LOCAL_PEERS]
                        host, port = requesting_peer.split(":")
                        local_peer_list = [f"{peer[0]}:{peer[1]}" for peer in self.peers]
                        response_object = SharedObject(data={SharedObject.LOCAL_PEERS: local_peer_list})
                        response_message = response_object.to_json()
                        compressed_message = self.compress_message(response_message)
                        self.socket.sendto(compressed_message, (host, int(port)))
                    elif SharedObject.LOCAL_PEERS in shared_object.data:
                        peer = addr[0], addr[1]
                        if peer in self.waiting_local_peer and self.waiting_local_peer[peer]:
                            local_peers = shared_object.data[SharedObject.LOCAL_PEERS]
                            for local_peer in local_peers:
                                host, port = local_peer.split(":")
                                self.connect_to_peer(host, int(port))
                            self.waiting_local_peer[peer] = False
                            del self.waiting_local_peer[peer]
            else:
                if self.debug:
                    print(f"Node {self.port}: Received duplicate object with hash {message_hash}")
        except json.JSONDecodeError:
            if self.debug:
                print(f"Node {self.port}: Received invalid message from {addr}")

    def create_shared_object(self, data):
        new_object = SharedObject(data=data)
        message = new_object.to_json()
        message_hash = self.broadcast(message)
        self.db[message_hash] = message
        if self.persistent:
            self.db_sync()
        if self.debug:
            print(f"Node {self.port}: Created new object with hash {message_hash}")
        return message_hash, new_object

    def db_sync(self):
        if self.persistent:
            self.db.close()
            self.db = dbm.ndbm.open(self.db_name, 'c')

    def save_peers(self):
        if self.persistent:
            self.db[self.PEERS.encode()] = json.dumps(self.peers).encode()
            self.db_sync()

    def load_peers(self) -> List[Tuple[str, int]]:
        if self.persistent and self.PEERS.encode() in self.db:
            return json.loads(self.db[self.PEERS.encode()].decode())
        else:
            return []