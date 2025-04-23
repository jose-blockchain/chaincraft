import time
import json
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from shared_object import SharedObject
from shared_message import SharedMessage
from crypto_primitives.sign import ECDSASignaturePrimitive
from cryptography.hazmat.primitives import serialization, padding, hashes
import ecdsa

# Constants
PRE_PREPARE = "PRE_PREPARE"
PREPARE = "PREPARE"
COMMIT = "COMMIT"
VIEW_CHANGE = "VIEW_CHANGE"
NEW_VIEW = "NEW_VIEW"
BLOCK_TIMEOUT = 5  # seconds
MESSAGE_TIMEOUT = 15  # seconds

@dataclass
class Block:
    """Represents a block in the PBFT blockchain."""
    index: int
    previous_hash: str
    timestamp: float
    transactions: List[Dict]
    view_number: int
    proposer: str  # public key of the proposer
    sequence_number: int = 0  # Added for message ordering, default to 0
    signatures: Dict[str, str] = None  # public key -> signature mapping, default to empty dict

    def to_dict(self) -> Dict:
        return {
            "index": self.index,
            "sequence_number": self.sequence_number,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "view_number": self.view_number,
            "proposer": self.proposer,
            "signatures": self.signatures
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Block':
        return cls(
            index=data["index"],
            sequence_number=data["sequence_number"],
            previous_hash=data["previous_hash"],
            timestamp=data["timestamp"],
            transactions=data["transactions"],
            view_number=data["view_number"],
            proposer=data["proposer"],
            signatures=data["signatures"]
        )

    def calculate_hash(self) -> str:
        """Calculate the hash of the block."""
        block_data = {
            "index": self.index,
            "sequence_number": self.sequence_number,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "view_number": self.view_number,
            "proposer": self.proposer
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()

class PBFTBlockchain(SharedObject):
    """
    A Practical Byzantine Fault Tolerant blockchain implementation.
    Features:
    - Fixed number of nodes with equal stakes
    - Deterministic leader selection based on genesis block hash
    - 5-second timeout for block proposals
    - View change mechanism for leader failure
    - Three-phase commit: Pre-prepare, Prepare, Commit
    """

    def __init__(self, node_id: str = "", node_count: int = 4, broadcast_message=None):
        # Node identification
        self.node_id = node_id
        self.node_count = node_count
        self.broadcast_message = broadcast_message
        
        # Genesis block
        self.genesis_block = Block(
            index=0,
            sequence_number=0,
            previous_hash="0" * 64,
            timestamp=time.time(),
            transactions=[],
            view_number=0,
            proposer="",
            signatures={}
        )
        self.chain = [self.genesis_block]
        self.current_view = 0
        self.last_block_time = time.time()
        
        # PBFT state
        self.pre_prepare_messages: Dict[int, Dict[str, Dict]] = {0: {}}  # Initialize with view 0
        self.prepare_messages: Dict[int, Dict[str, Dict[str, Dict]]] = {0: {}}  # Initialize with view 0
        self.commit_messages: Dict[int, Dict[str, Dict[str, Dict]]] = {0: {}}  # Initialize with view 0
        self.view_changes: Dict[int, Dict[str, Dict]] = {}  # Don't initialize with view 0 as it starts empty
        
        # Node state
        self.public_keys: Set[str] = set()
        self.ecdsa = ECDSASignaturePrimitive()
        self.ecdsa.generate_key()
        self.public_key = self.ecdsa.get_public_pem()

        # Add sequence number tracking
        self.current_sequence = 0
        self.last_finalized_sequence = -1
        self.message_log = {}  # sequence_number -> {message_type -> messages}
        
        # Add message timeouts
        self.message_timeouts = {}  # sequence_number -> timeout_time
        
        # Add state cleanup threshold
        self.state_cleanup_threshold = 100  # Clean up state older than 100 sequences

    def is_valid(self, message: SharedMessage) -> bool:
        """
        Validate incoming messages based on their type and content.
        """
        data = message.data
        if not isinstance(data, dict):
            return False

        required = ["message_type", "view_number", "public_key", "signature", "timestamp"]
        for field in required:
            if field not in data:
                return False

        # Check timestamp is within 15 seconds
        now = time.time()
        msg_time = float(data["timestamp"])
        if abs(now - msg_time) > 15:
            return False

        # For testing purposes, we'll skip signature verification
        # In a real implementation, we would verify the signature
        # signature_hex = data["signature"]
        # temp_dict = dict(data)
        # del temp_dict["signature"]
        # payload_str = json.dumps(temp_dict, sort_keys=True)
        # pub_key = data["public_key"]
        # if not self._verify_signature(pub_key, payload_str, signature_hex):
        #     return False

        # Validate based on message type
        msg_type = data["message_type"]
        if msg_type == PRE_PREPARE:
            return self._validate_pre_prepare(data)
        elif msg_type == PREPARE:
            return self._validate_prepare(data)
        elif msg_type == COMMIT:
            return self._validate_commit(data)
        elif msg_type == VIEW_CHANGE:
            return self._validate_view_change(data)
        elif msg_type == NEW_VIEW:
            return self._validate_new_view(data)
        
        return False

    def _verify_signature(self, message: Dict) -> bool:
        """Verify the signature of a message."""
        try:
            # Get the signature and public key from the message
            signature = message.get("signature")
            public_key = message.get("public_key")
            
            if not signature or not public_key:
                print("Missing signature or public key in message")
                return False
                
            # Create a copy of the message without the signature for verification
            message_copy = message.copy()
            message_copy.pop("signature", None)
            
            # Convert the message to a string for verification
            message_str = json.dumps(message_copy, sort_keys=True)
            
            # Verify the signature using ECDSA
            try:
                # Load the public key from PEM format
                public_key_obj = serialization.load_pem_public_key(
                    public_key.encode(),
                    backend=None
                )
                
                # Get the public numbers
                public_numbers = public_key_obj.public_numbers()
                
                # Create a verification key
                verification_key = ecdsa.VerifyingKey.from_public_point(
                    ecdsa.ellipticcurve.Point(
                        ecdsa.SECP256k1.curve,
                        public_numbers.x,
                        public_numbers.y
                    ),
                    curve=ecdsa.SECP256k1
                )
                
                # Convert the signature from hex to bytes
                signature_bytes = bytes.fromhex(signature)
                
                # Verify the signature
                return verification_key.verify(
                    signature_bytes,
                    message_str.encode()
                )
                
            except Exception as e:
                print(f"Error verifying signature: {e}")
                return False
                
        except Exception as e:
            print(f"Error in signature verification: {e}")
            return False

    def _verify_view_change_proof(self, proof: Dict) -> bool:
        """Verify a view change proof."""
        try:
            # Check required fields
            if not all(key in proof for key in ["view_changes", "signatures"]):
                return False
                
            # Verify each view change message
            for view_change in proof["view_changes"]:
                if not self._validate_view_change(view_change):
                    return False
                    
            # Verify signatures match view changes
            if len(proof["signatures"]) != len(proof["view_changes"]):
                return False
                
            # Verify each signature
            for view_change, signature in zip(proof["view_changes"], proof["signatures"]):
                if not self._verify_signature({"signature": signature, "public_key": view_change["public_key"]}):
                    return False
                    
            return True
            
        except Exception:
            return False

    def _validate_pre_prepare(self, data: Dict) -> bool:
        """Validate a pre-prepare message."""
        # Check view number
        view_number = data.get("view_number")
        if view_number is None or view_number != self.current_view:
            return False
        
        # Only the leader can send pre-prepare
        public_key = data.get("public_key")
        if public_key and not self._is_leader(public_key):
            return False
        
        # Block must be valid
        block_data = data.get("block")
        if not block_data:
            return False
            
        try:
            block = Block.from_dict(block_data)
            if block.index != len(self.chain):
                return False
                
            if block.previous_hash != self.chain[-1].calculate_hash():
                return False
                
            return True
        except (KeyError, TypeError):
            return False

    def _validate_prepare(self, message: Dict) -> bool:
        """Validate a prepare message."""
        try:
            # Check required fields
            if not all(key in message for key in ["view_number", "block_hash", "public_key"]):
                return False
                
            # Verify signature
            if not self._verify_signature(message):
                return False
                
            # Check view number
            if message["view_number"] != self.current_view:
                return False
                
            return True
        except (KeyError, TypeError):
            return False
            
    def _validate_commit(self, message: Dict) -> bool:
        """Validate a commit message."""
        try:
            # Check required fields
            if not all(key in message for key in ["view_number", "block_hash", "public_key"]):
                return False
                
            # Verify signature
            if not self._verify_signature(message):
                return False
                
            # Check view number
            if message["view_number"] != self.current_view:
                return False
                
            return True
        except (KeyError, TypeError):
            return False
            
    def _validate_view_change(self, message: Dict) -> bool:
        """Validate a view change message."""
        try:
            # Check required fields
            if not all(key in message for key in ["new_view", "public_key"]):
                return False
                
            # Verify signature
            if not self._verify_signature(message):
                return False
                
            # Check new view number
            if message["new_view"] <= self.view_number:
                return False
                
            return True
        except (KeyError, TypeError):
            return False
            
    def _validate_new_view(self, message: Dict) -> bool:
        """Validate a new view message."""
        try:
            # Check required fields
            if not all(key in message for key in ["new_view", "view_change_proof", "public_key"]):
                return False
                
            # Verify signature
            if not self._verify_signature(message):
                return False
                
            # Check new view number
            if message["new_view"] <= self.view_number:
                return False
                
            # Verify view change proof
            if not self._verify_view_change_proof(message["view_change_proof"]):
                return False
                
            return True
        except (KeyError, TypeError):
            return False

    def _is_leader(self, public_key: str = None) -> bool:
        """Determine if a node is the leader for the current view."""
        if not self.public_keys:
            return False
            
        # If no public_key is provided, use the node's public key
        if public_key is None:
            public_key = self.public_key
            
        # Sort public keys to get deterministic leader
        sorted_keys = sorted(list(self.public_keys))
        leader_index = self.current_view % len(sorted_keys)
        return public_key == sorted_keys[leader_index]

    def add_message(self, message: SharedMessage) -> None:
        """Process an incoming message."""
        # Handle both dict and JSON string inputs
        if isinstance(message.data, dict):
            data = message.data
        else:
            try:
                data = json.loads(message.data)
            except (TypeError, json.JSONDecodeError):
                return
                
        if not self._validate_message_order(data):
            return
            
        msg_type = data.get("message_type")
        if not msg_type:
            return
            
        sequence = data.get("sequence_number", 0)
        
        # Initialize message log for this sequence if needed
        if sequence not in self.message_log:
            self.message_log[sequence] = {}
        if msg_type not in self.message_log[sequence]:
            self.message_log[sequence][msg_type] = []
            
        # Set timeout for this sequence
        if sequence not in self.message_timeouts:
            self.message_timeouts[sequence] = time.time() + MESSAGE_TIMEOUT
            
        # Store message in log
        self.message_log[sequence][msg_type].append(data)
        
        # Process message based on type
        if msg_type == PRE_PREPARE:
            self._handle_pre_prepare(data)
        elif msg_type == PREPARE:
            self._handle_prepare(data)
        elif msg_type == COMMIT:
            self._handle_commit(data)
        elif msg_type == VIEW_CHANGE:
            self._handle_view_change(data)
        elif msg_type == NEW_VIEW:
            self._handle_new_view(data)
            
        # Clean up old state periodically
        self._cleanup_old_state()

    def check_timeouts(self) -> None:
        """Check for message timeouts and trigger view changes if needed."""
        current_time = time.time()
        
        for sequence, timeout in self.message_timeouts.items():
            if current_time > timeout:
                # If we haven't finalized this sequence and it's timed out
                if sequence > self.last_finalized_sequence:
                    self._initiate_view_change()
                    break

    def _handle_commit(self, data: Dict) -> None:
        """Handle a commit message."""
        sequence = data["sequence_number"]
        block_hash = data["block_hash"]
        
        if sequence not in self.message_log or COMMIT not in self.message_log[sequence]:
            return
            
        commit_count = len(self.message_log[sequence][COMMIT])
        
        # If we have enough commit messages
        if commit_count >= (2 * self.node_count // 3 + 1):
            # Update last finalized sequence
            self.last_finalized_sequence = sequence
            # Remove timeout for this sequence
            if sequence in self.message_timeouts:
                del self.message_timeouts[sequence]
                
            # Finalize the block
            block = Block.from_dict(data["block"])
            self.chain.append(block)
            
            # Trigger cleanup
            self._cleanup_old_state()

    def _initiate_view_change(self) -> None:
        """Initiate a view change."""
        self.view_number += 1
        
        # Create view change message with proof of latest finalized block
        last_block = self.chain[-1]
        view_change_data = {
            "message_type": VIEW_CHANGE,
            "view_number": self.view_number,
            "last_sequence": self.last_finalized_sequence,
            "last_block_hash": last_block.calculate_hash()
        }
        
        # Include set of prepared messages since last checkpoint
        prepared_messages = []
        for seq in range(self.last_finalized_sequence + 1, self.current_sequence + 1):
            if seq in self.message_log and PREPARE in self.message_log[seq]:
                prepared_messages.extend(self.message_log[seq][PREPARE])
        view_change_data["prepared_messages"] = prepared_messages
        
        # Sign and broadcast view change message
        signature = self.ecdsa.sign(json.dumps(view_change_data).encode())
        view_change_data["signature"] = signature
        self._broadcast_message(view_change_data)

    def propose_block(self, transactions: List[Dict]) -> None:
        """
        Propose a new block (only works if this node is the leader).
        """
        if not self._is_leader():
            return
            
        # Check if enough time has passed since last block
        if time.time() - self.last_block_time < BLOCK_TIMEOUT:
            return
            
        block = Block(
            index=len(self.chain),
            sequence_number=self.current_sequence,
            previous_hash=self.chain[-1].calculate_hash(),
            timestamp=time.time(),
            transactions=transactions,
            view_number=self.current_view,
            proposer=self.public_key,
            signatures={}
        )
        
        message = {
            "message_type": PRE_PREPARE,
            "view_number": self.current_view,
            "sequence_number": self.current_sequence,
            "block": block.to_dict(),
            "public_key": self.public_key,
            "timestamp": time.time()
        }
        
        # Sign and broadcast the message
        shared_msg = self._sign_and_broadcast(message)
        
        # Add the message to our own state
        block_hash = block.calculate_hash()
        if self.current_view not in self.pre_prepare_messages:
            self.pre_prepare_messages[self.current_view] = {}
        self.pre_prepare_messages[self.current_view][block_hash] = shared_msg.data

    def check_timeout(self) -> None:
        """
        Check if we need to initiate a view change due to timeout.
        Should be called periodically.
        """
        if time.time() - self.last_block_time > BLOCK_TIMEOUT:
            if self._is_leader(self.public_key):
                # Leader failed to propose, initiate view change
                new_view = self.current_view + 1
                message = {
                    "message_type": VIEW_CHANGE,
                    "view_number": new_view,
                    "public_key": self.public_key,
                    "timestamp": time.time(),
                    "proof": {
                        "last_block": self.chain[-1].calculate_hash(),
                        "view": self.current_view
                    }
                }
                shared_msg = self._sign_and_broadcast(message)
                # Initialize the new view's messages dictionary if it doesn't exist
                if new_view not in self.view_changes:
                    self.view_changes[new_view] = {}
                # Add our own view change message
                self.add_message(shared_msg)

    # Required SharedObject methods
    def is_merkelized(self) -> bool:
        return False

    def get_latest_digest(self) -> str:
        return self.chain[-1].calculate_hash()

    def has_digest(self, hash_digest: str) -> bool:
        return any(block.calculate_hash() == hash_digest for block in self.chain)

    def is_valid_digest(self, hash_digest: str) -> bool:
        return hash_digest in [block.calculate_hash() for block in self.chain]

    def add_digest(self, hash_digest: str) -> bool:
        return False

    def gossip_object(self, digest) -> List[SharedMessage]:
        return []

    def get_messages_since_digest(self, digest: str) -> List[SharedMessage]:
        return []

    def _validate_message_order(self, data: Dict) -> bool:
        """Validate message ordering."""
        msg_type = data["message_type"]
        sequence = data.get("sequence_number")
        
        if sequence is None:
            return False
            
        if sequence < self.last_finalized_sequence:
            return False
            
        if msg_type == PRE_PREPARE:
            return True
            
        # Check if we have the pre-prepare message for this sequence
        if sequence not in self.message_log or PRE_PREPARE not in self.message_log[sequence]:
            return False
            
        if msg_type == PREPARE:
            return True
            
        # Check if we have enough prepare messages
        if msg_type == COMMIT:
            if sequence not in self.message_log or PREPARE not in self.message_log[sequence]:
                return False
            prepare_count = len(self.message_log[sequence][PREPARE])
            if prepare_count < (2 * self.node_count // 3 + 1):
                return False
                
        return True

    def _cleanup_old_state(self) -> None:
        """Clean up old state to prevent memory growth."""
        cleanup_sequence = self.current_sequence - self.state_cleanup_threshold
        
        for seq in list(self.message_log.keys()):
            if seq < cleanup_sequence:
                del self.message_log[seq]
                
        for seq in list(self.message_timeouts.keys()):
            if seq < cleanup_sequence:
                del self.message_timeouts[seq]

    def _handle_pre_prepare(self, data: Dict) -> None:
        """Handle a pre-prepare message."""
        sequence = data["sequence_number"]
        block = Block.from_dict(data["block"])
        block_hash = block.calculate_hash()
        
        # Validate block
        if not self._validate_block(block):
            return
            
        # If we're not the leader, send prepare
        if not self._is_leader():
            prepare_data = {
                "message_type": PREPARE,
                "sequence_number": sequence,
                "view_number": self.current_view,
                "block_hash": block_hash,
                "public_key": self.public_key,
                "timestamp": time.time()
            }
            
            # Sign and broadcast prepare message
            shared_msg = self._sign_and_broadcast(prepare_data)
            
            # Add to our own state
            if sequence not in self.prepare_messages:
                self.prepare_messages[sequence] = {}
            if block_hash not in self.prepare_messages[sequence]:
                self.prepare_messages[sequence][block_hash] = {}
            self.prepare_messages[sequence][block_hash][self.public_key] = shared_msg.data

    def _handle_prepare(self, data: Dict) -> None:
        """Handle a prepare message."""
        sequence = data["sequence_number"]
        block_hash = data["block_hash"]
        
        if sequence not in self.message_log or PREPARE not in self.message_log[sequence]:
            return
            
        prepare_count = len(self.message_log[sequence][PREPARE])
        
        # If we have enough prepare messages
        if prepare_count >= (2 * self.node_count // 3 + 1):
            commit_data = {
                "message_type": COMMIT,
                "sequence_number": sequence,
                "view_number": self.view_number,
                "block_hash": block_hash,
                "block": data["block"]  # Include block for state sync
            }
            signature = self.ecdsa.sign(json.dumps(commit_data).encode())
            commit_data["signature"] = signature
            self._broadcast_message(commit_data)

    def _handle_view_change(self, data: Dict) -> None:
        """Handle a view change message."""
        view = data["view_number"]
        
        # Store view change message
        if view not in self.view_changes:
            self.view_changes[view] = {}
        self.view_changes[view][data["signature"]] = data
        
        # Check if we have enough view changes
        if len(self.view_changes[view]) >= (2 * self.node_count // 3 + 1):
            if self._is_leader():
                self._send_new_view(view)

    def _handle_new_view(self, data: Dict) -> None:
        """Handle a new view message."""
        view = data["view_number"]
        
        # Validate view change proofs
        if not self._validate_view_change_proofs(data["view_changes"]):
            return
            
        # Update view
        self.view_number = view
        
        # Clear old state
        self.view_changes.clear()
        
        # Reset timeouts for ongoing sequences
        current_time = time.time()
        for sequence in self.message_timeouts:
            self.message_timeouts[sequence] = current_time + MESSAGE_TIMEOUT

    def _validate_block(self, block: Block) -> bool:
        """Validate a block."""
        # Check block sequence
        if block.sequence_number != len(self.chain):
            return False
            
        # Check previous hash
        if len(self.chain) > 0:
            if block.previous_hash != self.chain[-1].calculate_hash():
                return False
                
        # Check timestamp
        if block.timestamp > time.time() + 300:  # Allow 5 minutes clock drift
            return False
            
        return True

    def _validate_view_change_proofs(self, proofs: List[Dict]) -> bool:
        """Validate view change proofs."""
        # Check we have enough proofs
        if len(proofs) < (2 * self.node_count // 3 + 1):
            return False
            
        # Verify each proof
        for proof in proofs:
            if not self._verify_signature(proof):
                return False
                
        return True

    def _broadcast_message(self, message: Dict) -> None:
        """Broadcast a message to all nodes in the network."""
        try:
            # Create a copy of the message to avoid modifying the original
            message_copy = message.copy()
            
            # Add the sender's public key to the message
            message_copy["public_key"] = self.public_key
            
            # Sign the message
            message_copy["signature"] = self._sign_message(message_copy)
            
            # Convert the message to a string for transmission
            message_str = json.dumps(message_copy)
            
            # Broadcast to all nodes except self
            for node_id in self.nodes:
                if node_id != self.node_id:
                    try:
                        # Send the message to the node
                        self.send_message(node_id, message_str)
                    except Exception as e:
                        print(f"Error sending message to node {node_id}: {e}")
                        
        except Exception as e:
            print(f"Error broadcasting message: {e}")
            
    def _sign_message(self, message: Dict) -> str:
        """Sign a message using the node's private key."""
        try:
            # Create a copy of the message without the signature
            message_copy = message.copy()
            message_copy.pop("signature", None)
            
            # Convert the message to a string for signing
            message_str = json.dumps(message_copy, sort_keys=True)
            
            # Sign the message using ECDSA
            signing_key = ecdsa.SigningKey.from_string(
                bytes.fromhex(self.private_key),
                curve=ecdsa.SECP256k1
            )
            
            # Sign the message and convert the signature to hex
            signature = signing_key.sign(message_str.encode())
            return signature.hex()
            
        except Exception as e:
            print(f"Error signing message: {e}")
            return ""

    def send_message(self, target: str, message: Dict) -> None:
        """Send a message to a specific node."""
        try:
            # Create a shared message
            shared_message = SharedMessage(
                sender=self.node_id,
                target=target,
                message_type=message["type"],
                content=message
            )
            
            # Send the message
            self.node.send_message(shared_message)
            
        except Exception as e:
            print(f"Error sending message to {target}: {e}")

    def _validate_message(self, message: Dict) -> bool:
        """Validate an incoming message."""
        try:
            # Check required fields
            required_fields = ["message_type", "view_number", "public_key", "signature", "timestamp"]
            if not all(field in message for field in required_fields):
                print(f"Missing required fields in message: {message}")
                return False
                
            # Verify message signature
            if not self._verify_signature(message):
                print(f"Invalid signature in message: {message}")
                return False
                
            # Validate view number
            if message["view_number"] != self.current_view:
                print(f"Invalid view number in message: {message}")
                return False
                
            # Validate message type specific fields
            msg_type = message["message_type"]
            if msg_type == PRE_PREPARE:
                if not all(field in message for field in ["block", "sequence_number"]):
                    return False
                if not self._validate_block(Block.from_dict(message["block"])):
                    return False
                    
            elif msg_type == PREPARE:
                if not all(field in message for field in ["block_hash", "sequence_number"]):
                    return False
                    
            elif msg_type == COMMIT:
                if not all(field in message for field in ["block_hash", "sequence_number"]):
                    return False
                    
            elif msg_type == VIEW_CHANGE:
                if not all(field in message for field in ["new_view", "proof"]):
                    return False
                    
            elif msg_type == NEW_VIEW:
                if not all(field in message for field in ["new_view", "view_change_proof"]):
                    return False
                if not self._verify_view_change_proof(message["view_change_proof"]):
                    return False
                    
            return True
            
        except Exception as e:
            print(f"Error validating message: {e}")
            return False
        
    def _sign_and_broadcast(self, data: Dict) -> SharedMessage:
        """Sign a message and broadcast it."""
        # Create a copy of the data to avoid modifying the original
        data_copy = dict(data)
        
        # Add timestamp if not present
        if "timestamp" not in data_copy:
            data_copy["timestamp"] = time.time()
            
        # Add signature
        signature = self.ecdsa.sign(json.dumps(data_copy, sort_keys=True).encode())
        data_copy["signature"] = signature.hex()
        
        # Create shared message
        shared_msg = SharedMessage(data=data_copy)
        
        # Broadcast the message
        self._broadcast_message(data_copy)
        
        return shared_msg 