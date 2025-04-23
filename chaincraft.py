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
from typing import List, Tuple, Dict, Union, Optional, Any, Set

from shared_object import SharedObject, SharedObjectException
from shared_message import SharedMessage


class ChaincraftNode:
    PEERS: str = "PEERS"
    BANNED_PEERS: str = "BANNED_PEERS"

    def __init__(
        self,
        max_peers: int = 5,
        reset_db: bool = False,
        persistent: bool = False,
        use_fixed_address: bool = False,
        debug: bool = False,
        local_discovery: bool = True,
        shared_objects: Optional[List[SharedObject]] = None,
        port: Optional[int] = None
    ) -> None:
        """
        Initialize the ChaincraftNode with optional parameters.
        """
        self.max_peers: int = max_peers
        self.use_fixed_address: bool = use_fixed_address

        if port is not None:
            self.host: str = '127.0.0.1'
            self.port: int = port
        elif use_fixed_address:
            self.host: str = 'localhost'
            self.port: int = 21000
        else:
            self.host: str = '127.0.0.1'
            self.port: int = random.randint(5000, 9000)

        self.db_name: str = f"node_{self.port}.db"
        self.persistent: bool = persistent

        # Initialize storage (in-memory or dbm)
        if not persistent:
            self.db: Dict[str, str] = {}
        else:
            if reset_db and os.path.exists(self.db_name):
                os.remove(self.db_name)
            self.db: Union[dbm.ndbm._dbm, Dict[str, str]] = dbm.ndbm.open(self.db_name, 'c')

        # Load peers/banned from DB
        self.peers: List[Tuple[str, int]] = self.load_peers()
        self.banned_peers: Dict[Tuple[str, int], float] = self.load_banned_peers()

        self.socket: Optional[socket.socket] = None
        self.is_running: bool = False
        self.gossip_interval: float = 0.5  # seconds
        self.debug: bool = debug
        self.local_discovery: bool = local_discovery
        self.waiting_local_peer: Dict[Tuple[str, int], bool] = {}

        self.accepted_message_types: List[str] = []
        self.invalid_message_counts: Dict[Tuple[str, int], int] = {}
        self.shared_objects: List[SharedObject] = shared_objects or []

    def load_peers(self) -> List[Tuple[str, int]]:
        """
        Load the peer list from the database if persistent, otherwise return an empty list.
        """
        if self.persistent and self.PEERS.encode() in self.db:
            return json.loads(self.db[self.PEERS.encode()].decode())
        else:
            return []

    def load_banned_peers(self) -> Dict[Tuple[str, int], float]:
        """
        Load the banned peers from persistent storage if available.
        """
        if self.persistent and self.BANNED_PEERS.encode() in self.db:
            banned_peers_data: Dict[str, float] = json.loads(self.db[self.BANNED_PEERS.encode()].decode())
            return {tuple(peer_str.split(',')): expiration for peer_str, expiration in banned_peers_data.items()}
        else:
            return {}

    def add_shared_object(self, shared_object: SharedObject) -> None:
        """
        Add a SharedObject for the node to validate/integrate messages.
        """
        self.shared_objects.append(shared_object)

    def start(self) -> None:
        """
        Start the node by binding to a socket and launching the listener and gossip threads.
        """
        if self.is_running:
            return

        self._bind_socket()
        self.is_running = True

        threading.Thread(target=self.listen_for_messages, daemon=True).start()
        threading.Thread(target=self.gossip, daemon=True).start()
        threading.Thread(target=self.check_for_merkelized_objects, daemon=True).start()

    def _bind_socket(self) -> None:
        """
        Attempt to bind a UDP socket to the specified host/port (retry if needed).
        """
        max_retries: int = 10
        for _ in range(max_retries):
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.bind((self.host, self.port))
                print(f"Node started on {self.host}:{self.port}")
                return
            except OSError:
                if self.use_fixed_address:
                    raise
                self.port = random.randint(5000, 9000)

        raise OSError("Failed to bind to a port after multiple attempts")

    def close(self) -> None:
        """
        Cleanly stop the node and close database/socket resources.
        """
        self.is_running = False
        if self.socket:
            self.socket.close()
        if self.persistent:
            self.db.close()

    def listen_for_messages(self) -> None:
        """
        Listen for incoming datagrams, decompress them, and handle new messages.
        """
        while self.is_running:
            try:
                compressed_data: bytes
                addr: Tuple[str, int]
                compressed_data, addr = self.socket.recvfrom(1500)
                message_hash: str = self.hash_message(compressed_data)
                # Only handle if we've never seen this message
                if message_hash not in self.db:
                    message: str = self.decompress_message(compressed_data)
                    self.handle_message(message, message_hash, addr)
            except OSError:
                if not self.is_running:
                    break
                else:
                    raise

    def gossip(self) -> None:
        """
        Periodically broadcast all known messages to all peers.
        """
        while self.is_running:
            try:
                if self.db:
                    keys_to_share: List[bytes] = [
                        key for key in self.db.keys()
                        if key != self.PEERS.encode() and key != self.BANNED_PEERS.encode()
                    ]
                    for key in keys_to_share:
                        object_to_share: str = self._load_db_value(key)
                        self.broadcast(object_to_share)
                time.sleep(self.gossip_interval)
            except Exception as e:
                print(f"Error in gossip: {e}")

    def connect_to_peer(self, host: str, port: int, discovery: bool = False) -> None:
        """
        Connect to a peer (host, port), optionally sending a discovery message.
        Will remove and replace peers if max_peers is reached.
        """
        if (host, port) == (self.host, self.port):
            return
        if (host, port) in self.peers:
            return

        self._replace_peer_if_max_reached()
        self.peers.append((host, port))
        self.save_peers()

        print(f"Connected to peer {host}:{port}")
        if discovery:
            self.send_peer_discovery(host, port)

    def _replace_peer_if_max_reached(self) -> None:
        """
        If the node already has max_peers, remove one before adding a new one.
        """
        if len(self.peers) >= self.max_peers:
            replaced_peer = self.peers.pop()
            print(
                f"Max peers reached. Replacing peer {replaced_peer[0]}:{replaced_peer[1]} "
                f"with a new peer."
            )

    def send_peer_discovery(self, host: str, port: int) -> None:
        """
        Send a discovery message to the specified peer.
        """
        discovery_message = json.dumps({
            SharedMessage.PEER_DISCOVERY: f"{self.host}:{self.port}"
        })
        compressed_message = self.compress_message(discovery_message)
        self.socket.sendto(compressed_message, (host, port))

    def connect_to_peer_locally(self, host: str, port: int) -> None:
        """
        Connect to a peer locally (if different from self) and request local peer list.
        """
        if (host, port) != (self.host, self.port):
            self.waiting_local_peer[(host, port)] = True
            self.send_local_peer_request(host, port)

    def send_local_peer_request(self, host: str, port: int) -> None:
        """
        Request local peers from the specified host/port.
        """
        request_message = json.dumps({
            SharedMessage.REQUEST_LOCAL_PEERS: f"{self.host}:{self.port}"
        })
        compressed_message = self.compress_message(request_message)
        self.socket.sendto(compressed_message, (host, port))

    def decompress_message(self, compressed_message: bytes) -> str:
        """
        Decompress bytes into a string using zlib.
        """
        return zlib.decompress(compressed_message).decode()

    def hash_message(self, compressed_message: bytes) -> str:
        """
        Create a SHA-256 hash from the compressed message bytes.
        """
        return hashlib.sha256(compressed_message).hexdigest()

    def broadcast(self, message: str) -> str:
        """
        Broadcast a message (string) to all known peers.
        """
        compressed_message = self.compress_message(message)
        message_hash = self.hash_message(compressed_message)
        failed_peers = []

        for peer in self.peers:
            try:
                self.socket.sendto(compressed_message, peer)
                #if self.debug:
                #    print(f"Node {self.port}: Sent message to peer {peer}")
            except Exception as e:
                if self.debug:
                    print(f"Node {self.port}: Failed to send message to peer {peer}. Error: {e}")
                failed_peers.append(peer)

        # Clean up failed peers from the list
        for peer in failed_peers:
            self.peers.remove(peer)
            self.save_peers()

        return message_hash

    def handle_message(self, message: str, message_hash: str, addr: Tuple[str, int]) -> None:
        """Handle a new incoming message. Validate, store, broadcast if valid."""        
        try:
            # Avoid reprocessing if already in DB
            if message_hash.encode() in self.db:  # Fix: encode hash for DB key
                return
            
            if not self.is_message_accepted(message):
                self.handle_invalid_message(addr)
                return
            else:
                shared_message = SharedMessage.from_json(message)
                
            # Additional data-based actions (peer discovery, local peers, etc.)
            if isinstance(shared_message.data, dict):
                if SharedMessage.PEER_DISCOVERY in shared_message.data:
                    self._handle_peer_discovery(shared_message)
                elif (
                    SharedMessage.REQUEST_LOCAL_PEERS in shared_message.data
                    and self.local_discovery
                ):
                    self._handle_local_peer_request(shared_message)
                elif SharedMessage.LOCAL_PEERS in shared_message.data:
                    self._handle_local_peer_response(shared_message, addr)
                elif SharedMessage.REQUEST_SHARED_OBJECT_UPDATE in shared_message.data:
                    self._handle_shared_object_update_request(shared_message, addr)

            # if valid types, process
            self._handle_shared_message(shared_message, message, message_hash, addr)

        except json.JSONDecodeError:
            self.handle_invalid_message(addr)
        except Exception as e:
            print(f"❌ Error handling message: {str(e)}")
            self.handle_invalid_message(addr)

    def _handle_shared_message(self, shared_message: SharedMessage, original_message: str, message_hash: str, addr: Tuple[str, int]) -> None:
        """
        Handle logic for a valid SharedMessage, including storage, broadcasting, and
        special message fields (peer discovery, local peers).
        """
        # Check if the message is valid for our shared objects
        if self.shared_objects:
            if all(obj.is_valid(shared_message) for obj in self.shared_objects):
                self._process_shared_objects(shared_message)
                self._store_and_broadcast(message_hash, original_message)
            else:
                # Apply strike for messages not accepted by SharedObjects
                self.handle_invalid_message(addr)
        else:
            self._store_and_broadcast(message_hash, original_message)

    def _process_shared_objects(self, shared_message: SharedMessage) -> None:
        """
        Add the shared message to each SharedObject.
        """
        for obj in self.shared_objects:
            obj.add_message(shared_message)
            if self.debug:
                print(f"Node {self.port}: Added message to shared object {type(obj).__name__}")

    def _store_and_broadcast(self, message_hash: str, message_str: str) -> None:
        """
        Store the message in the node's DB and broadcast it.
        """
        self.db[message_hash] = message_str
        if self.debug:
            print(f"Node {self.port}: Received new object with hash {message_hash} Object: {message_str}")
        self.broadcast(message_str)

    def _handle_peer_discovery(self, shared_message: SharedMessage) -> None:
        """
        Handle a PEER_DISCOVERY message by connecting to the discovered peer.
        """
        peer_address: str = shared_message.data[SharedMessage.PEER_DISCOVERY]
        host: str
        port: str
        host, port = peer_address.split(":")
        self.connect_to_peer(host, int(port), discovery=True)

    def _handle_local_peer_request(self, shared_message: SharedMessage) -> None:
        """
        Respond to a REQUEST_LOCAL_PEERS message with the current peer list if local_discovery is enabled.
        """
        requesting_peer: str = shared_message.data[SharedMessage.REQUEST_LOCAL_PEERS]
        host: str
        port: str
        host, port = requesting_peer.split(":")
        local_peer_list: List[str] = [f"{peer[0]}:{peer[1]}" for peer in self.peers]
        response_object: SharedMessage = SharedMessage(data={SharedMessage.LOCAL_PEERS: local_peer_list})
        response_message: str = response_object.to_json()
        compressed_message: bytes = self.compress_message(response_message)
        self.socket.sendto(compressed_message, (host, int(port)))

    def _handle_local_peer_response(self, shared_message: SharedMessage, addr: Tuple[str, int]) -> None:
        """
        Handle a LOCAL_PEERS message, possibly connecting to the newly received peers.
        """
        peer: Tuple[str, int] = (addr[0], addr[1])
        if peer in self.waiting_local_peer and self.waiting_local_peer[peer]:
            local_peers: List[str] = shared_message.data[SharedMessage.LOCAL_PEERS]
            for local_peer in local_peers:
                host: str
                port: str
                host, port = local_peer.split(":")
                self.connect_to_peer(host, int(port))
            self.waiting_local_peer[peer] = False
            del self.waiting_local_peer[peer]

    def is_message_accepted(self, message: str) -> bool:
        """
        Check if the message matches any accepted type schema (if defined), or if all are accepted.
        """
        if not self.accepted_message_types:
            return True

        try:
            shared_object: SharedMessage = SharedMessage.from_json(message)
            message_type: type = type(shared_object.data)

            # If the data is a dictionary, attempt to match the 'message_type' key.
            for accepted_type in self.accepted_message_types:
                if message_type == dict and self.is_valid_dict_message(shared_object.data, accepted_type):
                    return True
                elif message_type in (str, int, float, bool, list, tuple) and message_type == accepted_type:
                    return True

            return False
        except json.JSONDecodeError:
            return False

    def is_valid_dict_message(self, message_data: Dict[str, Any], accepted_type: Dict[str, Any]) -> bool:
        """
        Verify that a dictionary-type message matches the specified type schema.
        """
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

    def is_valid_field_type(self, field_value: Any, field_type: Any, visited_types: Optional[Set[Any]] = None) -> bool:
        """
        Recursively validate message fields, including nested lists and custom type rules (e.g. "hash").
        """
        if visited_types is None:
            visited_types = set()

        # Handle list type
        if isinstance(field_type, list):
            if not isinstance(field_value, list):
                return False
            if field_type[0] in visited_types:
                return False  # Prevent infinite recursion on self-referential structures
            visited_types.add(field_type[0])
            for item in field_value:
                if not self.is_valid_field_type(item, field_type[0], visited_types):
                    return False
            visited_types.remove(field_type[0])
            return True

        # Handle custom strings like "hash" or "signature"
        elif field_type == "hash":
            return isinstance(field_value, str) and len(field_value) == 64
        elif field_type == "signature":
            return isinstance(field_value, str) and len(field_value) in (130, 132, 134, 136, 140, 142)
        else:
            return isinstance(field_value, field_type)

    def handle_invalid_message(self, addr: Tuple[str, int]) -> None:
        """
        Handle invalid messages (increment counters, ban if too many).
        """
        peer: Tuple[str, int] = (addr[0], addr[1])
        if peer not in self.banned_peers:
            self.invalid_message_counts[peer] = self.invalid_message_counts.get(peer, 0) + 1

            if self.invalid_message_counts[peer] >= 3:
                self.ban_peer(peer)
                del self.invalid_message_counts[peer]

    def ban_peer(self, peer: Tuple[str, int]) -> None:
        """
        Ban a peer for 48 hours and remove it from our peer list.
        """
        self.banned_peers[peer] = time.time() + 48 * 60 * 60
        if peer in self.peers:
            self.peers.remove(peer)
        self.save_banned_peers()

    def save_banned_peers(self) -> None:
        """
        Persist the banned peers to the DB.
        """
        if self.persistent:
            banned_peers_data: Dict[str, float] = {
                ",".join(map(str, peer)): expiration
                for peer, expiration in self.banned_peers.items()
            }
            self.db[self.BANNED_PEERS.encode()] = json.dumps(banned_peers_data).encode()
            self.db_sync()

    def create_shared_message(self, data: Any) -> Tuple[str, SharedMessage]:
        """
        Create a new SharedMessage, validate it with SharedObjects (if any),
        broadcast it, and store in the DB.
        """
        new_object: SharedMessage = SharedMessage(data=data)
        if self.shared_objects:
            if all(obj.is_valid(new_object) for obj in self.shared_objects):
                for obj in self.shared_objects:
                    obj.add_message(new_object)
                    if self.debug:
                        print(f"Node {self.port}: Added message to shared object {type(obj).__name__}")
            else:
                raise SharedObjectException("Invalid message for shared objects")

        message: str = new_object.to_json()
        message_hash: str = self.broadcast(message)
        self.db[message_hash] = message

        if self.persistent:
            self.db_sync()

        if self.debug:
            print(f"Node {self.port}: Created new object with hash {message_hash} and data {data}")

        return message_hash, new_object

    def db_sync(self) -> None:
        """
        Close and reopen the DB if we're using dbm to ensure data is written.
        """
        if self.persistent:
            self.db.close()
            self.db = dbm.ndbm.open(self.db_name, 'c')

    def save_peers(self) -> None:
        """
        Persist the current peer list to DB (if persistent).
        """
        if self.persistent:
            self.db[self.PEERS.encode()] = json.dumps(self.peers).encode()
            self.db_sync()

    def _load_db_value(self, key: bytes) -> str:
        """
        Helper to load a string value from DB (decoding if persistent).
        """
        value: Union[str, bytes] = self.db[key]
        if self.persistent:
            value = value.decode()
        return value

    def compress_message(self, message: str) -> bytes:
        """
        Compress a string message using zlib.
        """
        if isinstance(message, str):
            return zlib.compress(message.encode())
        else:
            raise TypeError(f"Expected str, got {type(message)}")
    
    def check_for_merkelized_objects(self) -> None:
        """
        Periodically check for merkelized objects and request updates if needed.
        """
        if self.debug:
            print("🔄 Starting check_for_merkelized_objects loop")
        while self.is_running:
            if self.debug:
                print(f"🔍 Checking {len(self.shared_objects)} shared objects")
            for obj in self.shared_objects:
                if self.debug:
                    print(f"📦 Examining object of type: {type(obj).__name__}")
                if obj.is_merkelized():
                    latest_digest: str = obj.get_latest_digest()
                    class_name: str = type(obj).__name__
                    if self.debug:
                        print(f"✨ Found merkelized object - class: {class_name}, digest: {latest_digest[:8]}...")
                    self.request_shared_object_update(class_name, latest_digest)
                elif self.debug:
                    print(f"⏭️ Object {type(obj).__name__} is not merkelized")
            if self.debug:
                print(f"💤 Sleeping for {self.gossip_interval} seconds")
            time.sleep(self.gossip_interval)  # Adjust the interval as needed

    def request_shared_object_update(self, class_name: str, digest: str) -> None:
        """
        Request an update for a shared object with the given class name and digest.
        """
        if self.debug:
            print(f"\n📤 Requesting update for {class_name} with digest {digest[:8]}...")
        message: SharedMessage = SharedMessage(data={
            SharedMessage.REQUEST_SHARED_OBJECT_UPDATE: {
                "class_name": class_name,
                "digest": digest
            }
        })
        message_json: str = message.to_json()
        if self.debug:
            print(f"📝 Created message - type: {type(message_json)}")
            print(f"📄 Content: {message_json}")
        
        try:
            self.broadcast(message_json)  # Pass the JSON string directly to broadcast
            if self.debug:
                print(f"✅ Successfully broadcast update request for {class_name}")
        except Exception as e:
            if self.debug:
                print(f"❌ Failed to broadcast update request: {str(e)}")

    def _handle_shared_object_update_request(self, shared_message: SharedMessage, addr: Tuple[str, int]) -> None:
        """
        Handle a request for a shared object update from another node.
        """
        if self.debug:
            print("\n📥 Received update request from", addr)
        request_data: Dict[str, str] = shared_message.data[SharedMessage.REQUEST_SHARED_OBJECT_UPDATE]
        class_name: str = request_data["class_name"]
        digest: str = request_data["digest"]
        
        if self.debug:
            print(f"🔍 Processing request - class: {class_name}, digest: {digest[:8]}...")
            print(f"📊 Number of shared objects to check: {len(self.shared_objects)}")
        
        matching_objects: int = 0
        for obj in self.shared_objects:
            current_class: str = type(obj).__name__
            if self.debug:
                print(f"🔎 Checking object type {current_class}")
                print(f"📋 Object chain: {[h[:8] + '...' for h in obj.chain]}")
            
            if current_class == class_name:
                matching_objects += 1
                if obj.is_valid_digest(digest):
                    if self.debug:
                        print(f"✅ Found matching object with valid digest")
                    messages_to_gossip: List[SharedMessage] = obj.gossip_object(digest)
                    if self.debug:
                        print(f"📨 Got {len(messages_to_gossip)} messages to gossip")
                    
                    for idx, message in enumerate(messages_to_gossip):
                        try:
                            json_msg: str = message.to_json()
                            if self.debug:
                                print(f"📤 Sending next hash {idx + 1}/{len(messages_to_gossip)} to {addr}: {message.data[:8]}...")
                            compressed_message: bytes = self.compress_message(json_msg)
                            self.socket.sendto(compressed_message, addr)
                            if self.debug:
                                print(f"✅ Send to {addr} successful")
                        except Exception as e:
                            if self.debug:
                                print(f"❌ Failed to send message {idx + 1} to {addr}: {str(e)}")
                elif self.debug:
                    print(f"❌ Invalid digest {digest[:8]}...")
        
        if matching_objects == 0 and self.debug:
            print(f"⚠️ No matching objects found for class {class_name}")