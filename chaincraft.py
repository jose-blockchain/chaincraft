import json
import random
import socket
import threading
import time
import zlib
import hashlib
from dataclasses import dataclass, asdict
from typing import List, Dict

# Persistent Python Key-value
# https://remusao.github.io/posts/python-dbm-module.html

@dataclass
class SharedObject:
    data: str
    timestamp: float

    def to_json(self):
        return json.dumps(asdict(self), sort_keys = True)

    @classmethod
    def from_json(cls, json_str):
        return cls(**json.loads(json_str))

class ChaincraftNode:
    def __init__(self, max_peers=2):
        self.max_peers = max_peers
        self.peers: List[tuple] = []
        self.shared_objects: Dict[str, SharedObject] = {}
        self.port = random.randint(5000, 9000)
        self.host = '127.0.0.1'

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
            if message_hash not in self.shared_objects:
                message = self.decompress_message(compressed_data)
                self.handle_message(message, message_hash, addr)

    def handle_message(self, message, message_hash, addr):
        try:
            shared_object = SharedObject.from_json(message)
            self.shared_objects[message_hash] = shared_object
            print(f"Received new object with hash {message_hash}: {shared_object}")
            self.broadcast(message)
        except json.JSONDecodeError:
            print(f"Received invalid message from {addr}")

    def gossip(self):
        while True:
            if self.shared_objects:
                object_to_share = random.choice(list(self.shared_objects.values()))
                self.broadcast(object_to_share.to_json())
            time.sleep(5)

    def create_shared_object(self, data):
        new_object = SharedObject(
            data=data,
            timestamp=time.time()
        )
        message = new_object.to_json()
        message_hash = self.broadcast(message)
        self.shared_objects[message_hash] = new_object
        return message_hash, new_object
