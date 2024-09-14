##############################################
# Chaincraft: A simple blockchain simulator
##############################################
# chaincraft.py

import json
import random
import socket
import threading
import time
import zlib
import hashlib
import dbm
import os
from dataclasses import dataclass, asdict
from typing import List, Tuple, Dict, Union

@dataclass
class SharedObject:
    data: str
    timestamp: float

    def to_json(self):
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, json_str):
        return cls(**json.loads(json_str))

class ChaincraftNode:
    def __init__(self, max_peers=3, reset_db=False, use_dict=True, use_fixed_address=False):
        self.max_peers = max_peers
        self.peers: List[Tuple[str, int]] = []
        self.use_fixed_address = use_fixed_address

        if use_fixed_address:
            self.host = 'localhost'
            self.port = 7331
        else:
            self.host = '127.0.0.1'
            self.port = random.randint(5000, 9000)

        self.db_name = f"node_{self.port}.db"
        self.use_dict = use_dict

        if use_dict:
            self.db: Dict[str, str] = {}
        else:
            if reset_db and os.path.exists(self.db_name):
                os.remove(self.db_name)
            self.db: Union[dbm._Database, Dict[str, str]] = dbm.open(self.db_name, 'c')

        self.socket = None
        self.is_running = False
        self.gossip_interval = 0.5 # seconds
        self.debug = True

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
        if not self.use_dict:
            self.db.close()

    def listen_for_messages(self):
        while self.is_running:
            try:
                compressed_data, addr = self.socket.recvfrom(1024)
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
                    for key in self.db.keys():
                        object_to_share = self.db[key]
                        if not self.use_dict:
                            object_to_share = object_to_share.decode()
                        self.broadcast(object_to_share)
                time.sleep(self.gossip_interval)
            except Exception as e:
                print(f"Error in gossip: {e}")

    def connect_to_peer(self, host, port):
        if len(self.peers) < self.max_peers and (host, port) not in self.peers:
            self.peers.append((host, port))
            print(f"Connected to peer {host}:{port}")

    def compress_message(self, message: str) -> bytes:
        return zlib.compress(message.encode())

    def decompress_message(self, compressed_message: bytes) -> str:
        return zlib.decompress(compressed_message).decode()

    def hash_message(self, compressed_message: bytes) -> str:
        return hashlib.sha256(compressed_message).hexdigest()

    def broadcast(self, message: str):
        compressed_message = self.compress_message(message)
        message_hash = self.hash_message(compressed_message)
        for peer in self.peers:
            try:
                self.socket.sendto(compressed_message, peer)
                if self.debug:
                    print(f"Node {self.port}: Sent message to peer {peer}")
            except Exception as e:
                if self.debug:
                    print(f"Node {self.port}: Failed to send message to peer {peer}. Error: {e}")
        return message_hash

    def handle_message(self, message, message_hash, addr):
        try:
            shared_object = SharedObject.from_json(message)
            if message_hash not in self.db:
                self.db[message_hash] = message
                if self.debug:
                    print(f"Node {self.port}: Received new object with hash {message_hash}")
                self.broadcast(message)
            else:
                if self.debug:
                    print(f"Node {self.port}: Received duplicate object with hash {message_hash}")
        except json.JSONDecodeError:
            if self.debug:
                print(f"Node {self.port}: Received invalid message from {addr}")

    def create_shared_object(self, data):
        new_object = SharedObject(data=data, timestamp=time.time())
        message = new_object.to_json()
        message_hash = self.broadcast(message)
        self.db[message_hash] = message
        if not self.use_dict:
            self.db_sync()
        if self.debug:
            print(f"Node {self.port}: Created new object with hash {message_hash}")
        return message_hash, new_object

    def db_sync(self):
        if not self.use_dict:
            self.db.close()
            self.db = dbm.open(self.db_name, 'c')