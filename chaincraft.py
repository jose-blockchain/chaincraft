import json
import random
import socket
import threading
import time
import zlib
import hashlib
import dbm.ndbm
import os
from typing import List, Tuple, Dict, Union

from shared_object import SharedObject, SharedObjectException
from shared_message import SharedMessage


class ChaincraftNode:
    PEERS = "PEERS"
    BANNED_PEERS = "BANNED_PEERS"

    def load_peers(self) -> List[Tuple[str, int]]:
        if self.persistent and self.PEERS.encode() in self.db:
            return json.loads(self.db[self.PEERS.encode()].decode())
        else:
            return []

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
        self.gossip_interval = 0.5  # seconds
        self.debug = debug
        self.local_discovery = local_discovery
        self.waiting_local_peer = {}

        self.accepted_message_types = []
        self.banned_peers = self.load_banned_peers()
        self.invalid_message_counts = {}

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
                    keys_to_share = [key for key in self.db.keys() if key != self.PEERS.encode() and key != self.BANNED_PEERS.encode()]
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
        discovery_message = json.dumps({SharedMessage.PEER_DISCOVERY: f"{self.host}:{self.port}"})
        compressed_message = self.compress_message(discovery_message)
        self.socket.sendto(compressed_message, (host, port))

    def connect_to_peer_locally(self, host, port):
        if (host, port) != (self.host, self.port):
            self.waiting_local_peer[(host, port)] = True
            self.send_local_peer_request(host, port)

    def send_local_peer_request(self, host, port):
        request_message = json.dumps({SharedMessage.REQUEST_LOCAL_PEERS: f"{self.host}:{self.port}"})
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
                if self.is_message_accepted(message):
                    self.db[message_hash] = message
                    if self.debug:
                        print(f"Node {self.port}: Received new object with hash {message_hash} Object: {message}")
                    self.broadcast(message)

                    shared_object = SharedMessage.from_json(message)
                    if isinstance(shared_object.data, dict):
                        if SharedMessage.PEER_DISCOVERY in shared_object.data:
                            peer_address = shared_object.data[SharedMessage.PEER_DISCOVERY]
                            host, port = peer_address.split(":")
                            self.connect_to_peer(host, int(port), discovery=True)
                        elif SharedMessage.REQUEST_LOCAL_PEERS in shared_object.data and self.local_discovery:
                            requesting_peer = shared_object.data[SharedMessage.REQUEST_LOCAL_PEERS]
                            host, port = requesting_peer.split(":")
                            local_peer_list = [f"{peer[0]}:{peer[1]}" for peer in self.peers]
                            response_object = SharedMessage(data={SharedMessage.LOCAL_PEERS: local_peer_list})
                            response_message = response_object.to_json()
                            compressed_message = self.compress_message(response_message)
                            self.socket.sendto(compressed_message, (host, int(port)))
                        elif SharedMessage.LOCAL_PEERS in shared_object.data:
                            peer = addr[0], addr[1]
                            if peer in self.waiting_local_peer and self.waiting_local_peer[peer]:
                                local_peers = shared_object.data[SharedMessage.LOCAL_PEERS]
                                for local_peer in local_peers:
                                    host, port = local_peer.split(":")
                                    self.connect_to_peer(host, int(port))
                                self.waiting_local_peer[peer] = False
                                del self.waiting_local_peer[peer]
                else:
                    self.handle_invalid_message(addr)
            else:
                if self.debug:
                    print(f"Node {self.port}: Received duplicate object with hash {message_hash}")
        except json.JSONDecodeError:
            if self.debug:
                print(f"Node {self.port}: Received invalid message from {addr}")
            self.handle_invalid_message(addr)

    def is_message_accepted(self, message):
        if not self.accepted_message_types:
            return True

        try:
            shared_object = SharedMessage.from_json(message)
            message_type = type(shared_object.data)

            for accepted_type in self.accepted_message_types:
                if message_type == dict and self.is_valid_dict_message(shared_object.data, accepted_type):
                    return True
                elif message_type in (str, int, float, bool, list, tuple) and message_type == accepted_type:
                    return True

            return False
        except json.JSONDecodeError:
            return False

    def is_valid_dict_message(self, message_data, accepted_type):
        if "message_type" not in message_data or message_data["message_type"] != accepted_type["message_type"]:
            return False

        for field, field_type in accepted_type["mandatory_fields"].items():
            if field not in message_data:
                return False
            if not self.is_valid_field_type(message_data[field], field_type):
                return False

        for field, field_type in accepted_type["optional_fields"].items():
            if field in message_data and not self.is_valid_field_type(message_data[field], field_type):
                return False

        return True

    def is_valid_field_type(self, field_value, field_type, visited_types=None):
        if visited_types is None:
            visited_types = set()

        if isinstance(field_type, list):
            if not isinstance(field_value, list):
                return False
            if field_type[0] in visited_types:
                return False  # Recursive type detected
            visited_types.add(field_type[0])
            for item in field_value:
                if not self.is_valid_field_type(item, field_type[0], visited_types):
                    return False
            visited_types.remove(field_type[0])
            return True
        elif field_type == "hash":
            return isinstance(field_value, str) and len(field_value) == 64
        elif field_type == "signature":
            return isinstance(field_value, str) and len(field_value) in (130, 132, 134, 136, 140, 142)
        else:
            return isinstance(field_value, field_type)
    
    def handle_invalid_message(self, addr):
        peer = addr[0], addr[1]
        if peer not in self.banned_peers:
            if peer not in self.invalid_message_counts:
                self.invalid_message_counts[peer] = 1
            else:
                self.invalid_message_counts[peer] += 1

            if self.invalid_message_counts[peer] >= 3:
                self.ban_peer(peer)
                del self.invalid_message_counts[peer]

    def ban_peer(self, peer):
        self.banned_peers[peer] = time.time() + 48 * 60 * 60  # Ban for 48 hours
        if peer in self.peers:
            self.peers.remove(peer)
        self.save_banned_peers()

    def load_banned_peers(self):
        if self.persistent and self.BANNED_PEERS.encode() in self.db:
            banned_peers_data = json.loads(self.db[self.BANNED_PEERS.encode()].decode())
            return {tuple(peer): expiration for peer, expiration in banned_peers_data.items()}
        else:
            return {}

    def save_banned_peers(self):
        if self.persistent:
            banned_peers_data = {",".join(map(str, peer)): expiration for peer, expiration in self.banned_peers.items()}
            self.db[self.BANNED_PEERS.encode()] = json.dumps(banned_peers_data).encode()
            self.db_sync()

    def create_shared_message(self, data):
        new_object = SharedMessage(data=data)
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
