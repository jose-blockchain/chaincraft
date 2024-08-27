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
from typing import List, Tuple

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
    def __init__(self, max_peers=2, reset_db=False):
        self.max_peers = max_peers
        self.peers: List[Tuple[str, int]] = []
        self.port = random.randint(5000, 9000)
        self.host = '127.0.0.1'
        self.db_name = f"node_{self.port}.db"
        
        if reset_db and os.path.exists(self.db_name):
            os.remove(self.db_name)
        
        self.db = dbm.open(self.db_name, 'c')

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        print(f"Node started on {self.host}:{self.port}")

        threading.Thread(target=self.listen_for_messages, daemon=True).start()
        threading.Thread(target=self.gossip, daemon=True).start()

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
            self.socket.sendto(compressed_message, peer)
        return message_hash

    def listen_for_messages(self):
        while True:
            compressed_data, addr = self.socket.recvfrom(1024)
            message_hash = self.hash_message(compressed_data)
            if message_hash not in self.db:
                message = self.decompress_message(compressed_data)
                self.handle_message(message, message_hash, addr)

    def handle_message(self, message, message_hash, addr):
        try:
            shared_object = SharedObject.from_json(message)
            self.db[message_hash] = message
            print(f"Received new object with hash {message_hash}: {shared_object}")
            self.broadcast(message)
        except json.JSONDecodeError:
            print(f"Received invalid message from {addr}")

    def gossip(self):
        while True:
            try:
                _ = len(self.db)
                if len(self.db) > 0:
                    random_key = random.choice(list(self.db.keys()))
                    object_to_share = self.db[random_key].decode()
                    self.broadcast(object_to_share)
                time.sleep(5)
            except:
                return

    def create_shared_object(self, data):
        new_object = SharedObject(
            data=data,
            timestamp=time.time()
        )
        message = new_object.to_json()
        message_hash = self.broadcast(message)
        self.db[message_hash] = message
        self.db_sync()
        return message_hash, new_object

    def db_sync(self):
        self.db.close()
        self.db = dbm.open(self.db_name, 'c')

    def close(self):
        self.db.close()
