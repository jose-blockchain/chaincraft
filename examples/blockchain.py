# examples/blockchain.py

import hashlib
import json
import time
import random
from typing import List, Dict, Any, Optional
import secrets
from dataclasses import dataclass
import ecdsa
import base64
from shared_object import SharedObject, SharedObjectException
from shared_message import SharedMessage


class BlockchainUtils:
    """Utility functions for blockchain operations"""
    
    @staticmethod
    def calculate_hash(data: Any) -> str:
        """Calculate SHA-256 hash of JSON-serialized data"""
        if isinstance(data, dict) or isinstance(data, list):
            data_str = json.dumps(data, sort_keys=True)
        elif not isinstance(data, str):
            data_str = str(data)
        else:
            data_str = data
        
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    @staticmethod
    def verify_proof_of_work(block_data: Dict, nonce: int, difficulty: int) -> bool:
        """Verify if a given nonce meets the proof-of-work requirement"""
        # Create copy of block data without the nonce to create the challenge
        challenge = {k: v for k, v in block_data.items() if k != 'nonce'}
        challenge_hash = BlockchainUtils.calculate_hash(challenge)
        
        # Combine challenge hash with nonce to get final hash
        final_hash = BlockchainUtils.calculate_hash(challenge_hash + str(nonce))
        
        # Check if hash meets difficulty (has required number of leading zeros)
        return final_hash.startswith('0' * difficulty)
    
    @staticmethod
    def find_proof_of_work(block_data: Dict, difficulty: int) -> tuple:
        """Find a nonce that satisfies the proof-of-work requirement"""
        # Create copy of block data without the nonce to create the challenge
        challenge = {k: v for k, v in block_data.items() if k != 'nonce'}
        challenge_hash = BlockchainUtils.calculate_hash(challenge)
        
        nonce = 0
        max_nonce = 2**32  # Prevent infinite loops
        
        while nonce < max_nonce:
            # Combine challenge hash with nonce to get final hash
            final_hash = BlockchainUtils.calculate_hash(challenge_hash + str(nonce))
            
            # Check if hash meets difficulty
            if final_hash.startswith('0' * difficulty):
                return nonce, final_hash
            
            nonce += 1
        
        raise Exception(f"Couldn't find valid proof after {max_nonce} attempts")
    
    @staticmethod
    def generate_keypair() -> tuple:
        """Generate ECDSA keypair for transaction signing"""
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        
        # Convert to strings for storage/transmission
        private_key_str = private_key.to_string().hex()
        public_key_str = public_key.to_string().hex()
        
        return private_key_str, public_key_str
    
    @staticmethod
    def get_address_from_public_key(public_key: str) -> str:
        """Generate Ethereum-like address from public key"""
        # Convert hex string to bytes if needed
        if isinstance(public_key, str):
            public_key_bytes = bytes.fromhex(public_key)
        else:
            public_key_bytes = public_key
            
        # Hash the public key and take last 20 bytes (like Ethereum)
        address = hashlib.sha256(public_key_bytes).digest()[-20:].hex()
        return f"0x{address}"
    
    @staticmethod
    def sign_transaction(tx_data: Dict, private_key_hex: str) -> str:
        """Sign transaction data with private key"""
        # Remove signature field if present when signing
        tx_copy = {k: v for k, v in tx_data.items() if k != 'signature'}
        message = json.dumps(tx_copy, sort_keys=True).encode()
        
        # Convert hex string to bytes
        private_key_bytes = bytes.fromhex(private_key_hex)
        private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        
        # Sign the message and convert to hex
        signature = private_key.sign(message)
        return signature.hex()
    
    @staticmethod
    def verify_signature(tx_data: Dict, signature: str, public_key_hex: str) -> bool:
        """Verify transaction signature with public key"""
        # Remove signature field if present when verifying
        tx_copy = {k: v for k, v in tx_data.items() if k != 'signature'}
        message = json.dumps(tx_copy, sort_keys=True).encode()
        
        try:
            # Convert hex strings to bytes
            signature_bytes = bytes.fromhex(signature)
            public_key_bytes = bytes.fromhex(public_key_hex)
            
            verifying_key = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)
            return verifying_key.verify(signature_bytes, message)
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False


@dataclass
class Transaction:
    """Represents a signed transaction transferring value between addresses"""
    sender: str          # Sender's address
    recipient: str       # Recipient's address
    amount: float        # Amount to transfer
    fee: float           # Transaction fee
    timestamp: float     # Transaction creation time
    public_key: str      # Sender's public key (for verification)
    signature: str       # Transaction signature
    tx_id: str           # Transaction ID (hash)
    
    @classmethod
    def create(cls, sender: str, recipient: str, amount: float, fee: float, 
               private_key: str, public_key: str) -> 'Transaction':
        """Create and sign a new transaction"""
        # Basic transaction data
        tx_data = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'fee': fee,
            'timestamp': time.time()
        }
        
        # Sign the transaction
        signature = BlockchainUtils.sign_transaction(tx_data, private_key)
        
        # Add signature and public key
        tx_data['signature'] = signature
        tx_data['public_key'] = public_key
        
        # Generate transaction ID
        tx_id = BlockchainUtils.calculate_hash(tx_data)
        tx_data['tx_id'] = tx_id
        
        return cls(**tx_data)
    
    def to_dict(self) -> Dict:
        """Convert transaction to dictionary"""
        return {
            'tx_id': self.tx_id,
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'fee': self.fee,
            'timestamp': self.timestamp,
            'public_key': self.public_key,
            'signature': self.signature
        }
    
    @classmethod
    def from_dict(cls, tx_dict: Dict) -> 'Transaction':
        """Create Transaction object from dictionary"""
        return cls(
            tx_id=tx_dict['tx_id'],
            sender=tx_dict['sender'],
            recipient=tx_dict['recipient'],
            amount=tx_dict['amount'],
            fee=tx_dict['fee'],
            timestamp=tx_dict['timestamp'],
            public_key=tx_dict['public_key'],
            signature=tx_dict['signature']
        )
    
    def is_valid(self) -> bool:
        """Verify transaction integrity and signature"""
        # Check transaction has valid structure
        if not all(hasattr(self, attr) for attr in 
                  ['sender', 'recipient', 'amount', 'fee', 'timestamp', 
                   'public_key', 'signature', 'tx_id']):
            return False
        
        # Check that amount and fee are positive
        if self.amount <= 0 or self.fee < 0:
            return False
            
        # Check that sender address matches public key
        derived_address = BlockchainUtils.get_address_from_public_key(self.public_key)
        if derived_address != self.sender:
            return False
            
        # Verify the signature
        tx_data = self.to_dict()
        return BlockchainUtils.verify_signature(tx_data, self.signature, self.public_key)


@dataclass
class Block:
    """Represents a block in the blockchain"""
    index: int                # Block height in the chain
    timestamp: float          # Block creation time
    transactions: List[Dict]  # List of transactions included in this block
    previous_hash: str        # Hash of the previous block
    miner: str                # Address of the miner (for reward)
    nonce: int                # Proof-of-work nonce
    hash: str                 # Block hash
    
    @classmethod
    def create(cls, index: int, transactions: List[Dict], previous_hash: str, 
               miner: str, difficulty: int) -> 'Block':
        """Create and mine a new block"""
        block_data = {
            'index': index,
            'timestamp': time.time(),
            'transactions': transactions,
            'previous_hash': previous_hash,
            'miner': miner
        }
        
        # Find proof of work
        nonce, block_hash = BlockchainUtils.find_proof_of_work(block_data, difficulty)
        
        # Add nonce and hash
        block_data['nonce'] = nonce
        block_data['hash'] = block_hash
        
        return cls(**block_data)
    
    def to_dict(self) -> Dict:
        """Convert block to dictionary"""
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'previous_hash': self.previous_hash,
            'miner': self.miner,
            'nonce': self.nonce,
            'hash': self.hash
        }
    
    @classmethod
    def from_dict(cls, block_dict: Dict) -> 'Block':
        """Create Block object from dictionary"""
        return cls(
            index=block_dict['index'],
            timestamp=block_dict['timestamp'],
            transactions=block_dict['transactions'],
            previous_hash=block_dict['previous_hash'],
            miner=block_dict['miner'],
            nonce=block_dict['nonce'],
            hash=block_dict['hash']
        )
    
    def is_valid(self, difficulty: int) -> bool:
        """Verify block integrity and proof-of-work"""
        # Check block has valid structure
        if not all(hasattr(self, attr) for attr in 
                  ['index', 'timestamp', 'transactions', 'previous_hash', 
                   'miner', 'nonce', 'hash']):
            return False
            
        # Check proof of work
        block_data = self.to_dict()
        return BlockchainUtils.verify_proof_of_work(block_data, self.nonce, difficulty)


class Mempool(SharedObject):
    """
    Mempool for holding pending transactions before they're included in blocks.
    Not merklelized since it's a temporary storage.
    """
    
    def __init__(self, difficulty: int = 4):
        """Initialize mempool with empty transactions dict"""
        self.transactions: Dict[str, Transaction] = {}  # tx_id -> Transaction
        self.difficulty = difficulty
        
    def is_valid(self, message: SharedMessage) -> bool:
        """
        Check if message contains a valid transaction or block
        """
        try:
            data = message.data
            
            # Handle transaction message
            if isinstance(data, dict) and 'type' in data and data['type'] == 'transaction':
                tx_data = data['payload']
                tx = Transaction.from_dict(tx_data)
                return tx.is_valid()
                
            # Handle block message (which will clear transactions from mempool)
            elif isinstance(data, dict) and 'type' in data and data['type'] == 'block':
                block_data = data['payload']
                block = Block.from_dict(block_data)
                return block.is_valid(self.difficulty)
                
            return False
        except Exception as e:
            print(f"Error validating message: {e}")
            return False
    
    def add_message(self, message: SharedMessage) -> None:
        """
        Process a new message - either a transaction to add to mempool
        or a block that will clear transactions from the mempool
        """
        data = message.data
        
        # Handle transaction message
        if isinstance(data, dict) and 'type' in data and data['type'] == 'transaction':
            tx_data = data['payload']
            tx = Transaction.from_dict(tx_data)
            
            # Add to mempool if not already there
            if tx.tx_id not in self.transactions:
                self.transactions[tx.tx_id] = tx
                print(f"Added transaction {tx.tx_id[:8]} to mempool")
                
        # Handle block message
        elif isinstance(data, dict) and 'type' in data and data['type'] == 'block':
            block_data = data['payload']
            block = Block.from_dict(block_data)
            
            # Remove transactions included in the block from mempool
            for tx_dict in block.transactions:
                tx_id = tx_dict['tx_id']
                if tx_id in self.transactions:
                    del self.transactions[tx_id]
                    
            print(f"Cleared {len(block.transactions)} transactions from mempool after block {block.index}")
    
    # These methods aren't needed for Mempool since it's non-merklelized,
    # but SharedObject requires them to be implemented
    def is_merkelized(self) -> bool:
        return False
        
    def get_latest_digest(self) -> str:
        return ""
        
    def has_digest(self, hash_digest: str) -> bool:
        return False
        
    def is_valid_digest(self, hash_digest: str) -> bool:
        return False
        
    def add_digest(self, hash_digest: str) -> bool:
        return False
        
    def gossip_object(self, digest) -> List[SharedMessage]:
        return []
        
    def get_messages_since_digest(self, digest: str) -> List[SharedMessage]:
        return []
    
    def get_transactions_by_fee(self, max_count: int = 10) -> List[Transaction]:
        """Get transactions sorted by fee (highest first), up to max_count"""
        sorted_txs = sorted(
            self.transactions.values(),
            key=lambda tx: tx.fee,
            reverse=True
        )
        return sorted_txs[:max_count]


class Ledger(SharedObject):
    """
    Blockchain ledger implementation that maintains the chain of blocks
    and tracks account balances. Merklelized for efficient state sync.
    """
    
    def __init__(self, difficulty: int = 4, reward: float = 10.0):
        """Initialize blockchain with genesis block"""
        self.chain: List[Block] = []
        self.balances: Dict[str, float] = {}  # address -> balance
        self.difficulty = difficulty
        self.mining_reward = reward
        
        # Create genesis block
        self._create_genesis_block()
        
        # Save chain hashes for merklelization
        self.chain_hashes: List[str] = [self.chain[0].hash]
    
    def _create_genesis_block(self) -> None:
        """Create the genesis (first) block in the chain"""
        genesis_address = "0x0000000000000000000000000000000000000000"
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            transactions=[],
            previous_hash="0" * 64,
            miner=genesis_address,
            nonce=0,
            hash=BlockchainUtils.calculate_hash({
                'index': 0,
                'timestamp': time.time(),
                'transactions': [],
                'previous_hash': "0" * 64,
                'miner': genesis_address
            })
        )
        self.chain.append(genesis_block)
        
        # Give genesis address some coins
        self.balances[genesis_address] = 1000.0
    
    def is_valid(self, message: SharedMessage) -> bool:
        """
        Check if message contains a valid block that can be added to the chain
        """
        try:
            data = message.data
            
            # Only accept block messages
            if isinstance(data, dict) and 'type' in data and data['type'] == 'block':
                block_data = data['payload']
                block = Block.from_dict(block_data)
                
                # Check block integrity and proof-of-work
                if not block.is_valid(self.difficulty):
                    print(f"Invalid block: Failed proof-of-work check")
                    return False
                
                # Check block index
                if block.index != len(self.chain):
                    print(f"Invalid block: Expected index {len(self.chain)}, got {block.index}")
                    return False
                
                # Check previous hash
                if block.previous_hash != self.chain[-1].hash:
                    print(f"Invalid block: Previous hash doesn't match")
                    return False
                
                # Validate each transaction in the block
                for tx_dict in block.transactions:
                    tx = Transaction.from_dict(tx_dict)
                    
                    # Check transaction signature
                    if not tx.is_valid():
                        print(f"Invalid transaction {tx.tx_id[:8]} in block")
                        return False
                    
                    # Check sender has enough balance
                    sender_balance = self.balances.get(tx.sender, 0)
                    if sender_balance < tx.amount + tx.fee:
                        print(f"Insufficient balance for tx {tx.tx_id[:8]}")
                        return False
                
                return True
            
            return False
        except Exception as e:
            print(f"Error validating block message: {e}")
            return False
    
    def add_message(self, message: SharedMessage) -> None:
        """
        Process a new block and update the chain and balances
        """
        data = message.data
        
        # Only process block messages
        if isinstance(data, dict) and 'type' in data and data['type'] == 'block':
            block_data = data['payload']
            block = Block.from_dict(block_data)
            
            # Process the block
            self._add_block(block)
            
            # Update merklelized chain hashes
            self.chain_hashes.append(block.hash)
            
            print(f"Added block {block.index} to chain, hash: {block.hash[:8]}")
    
    def _add_block(self, block: Block) -> None:
        """Add a validated block to the chain and update balances"""
        # Add the block to the chain
        self.chain.append(block)
        
        # Process mining reward
        self.balances[block.miner] = self.balances.get(block.miner, 0) + self.mining_reward
        
        # Process transactions
        for tx_dict in block.transactions:
            tx = Transaction.from_dict(tx_dict)
            
            # Deduct amount from sender
            self.balances[tx.sender] = self.balances.get(tx.sender, 0) - tx.amount - tx.fee
            
            # Add amount to recipient
            self.balances[tx.recipient] = self.balances.get(tx.recipient, 0) + tx.amount
            
            # Add fee to miner
            self.balances[block.miner] = self.balances.get(block.miner, 0) + tx.fee
    
    # Merklelized methods for state synchronization
    def is_merkelized(self) -> bool:
        return True
        
    def get_latest_digest(self) -> str:
        """Return the hash of the latest block"""
        return self.chain[-1].hash
        
    def has_digest(self, hash_digest: str) -> bool:
        """Check if a block with the given hash exists in the chain"""
        return hash_digest in self.chain_hashes
        
    def is_valid_digest(self, hash_digest: str) -> bool:
        """Check if a block hash is valid for sync"""
        return hash_digest in self.chain_hashes
        
    def add_digest(self, hash_digest: str) -> bool:
        """Not used in this implementation"""
        return False
        
    def gossip_object(self, digest) -> List[SharedMessage]:
        """
        Return blocks since the given digest hash for synchronization
        """
        try:
            # Find index of the digest in the chain
            if digest not in self.chain_hashes:
                return []
                
            index = self.chain_hashes.index(digest)
            
            # Return all blocks after this index
            messages = []
            for i in range(index + 1, len(self.chain)):
                block_dict = self.chain[i].to_dict()
                message_data = {
                    'type': 'block',
                    'payload': block_dict
                }
                messages.append(SharedMessage(data=message_data))
            
            return messages
        except Exception as e:
            print(f"Error in gossip_object: {e}")
            return []
        
    def get_messages_since_digest(self, digest: str) -> List[SharedMessage]:
        """Same as gossip_object for this implementation"""
        return self.gossip_object(digest)
    
    def create_block(self, transactions: List[Transaction], miner_address: str) -> Block:
        """
        Create a new block with the given transactions and miner
        """
        # Convert transactions to dictionaries for block
        tx_dicts = [tx.to_dict() for tx in transactions]
        
        # Create and return a new block
        return Block.create(
            index=len(self.chain),
            transactions=tx_dicts,
            previous_hash=self.chain[-1].hash,
            miner=miner_address,
            difficulty=self.difficulty
        )


class BlockchainNode:
    """
    Helper class to manage blockchain operations for a node
    """
    
    def __init__(self, chaincraft_node, difficulty: int = 4, reward: float = 10.0):
        """Initialize with ChainCraft node and blockchain configuration"""
        self.node = chaincraft_node
        self.mempool = Mempool(difficulty)
        self.ledger = Ledger(difficulty, reward)
        
        # Add shared objects to the node
        self.node.add_shared_object(self.mempool)
        self.node.add_shared_object(self.ledger)
        
        # Generate key pair for this node
        self.private_key, self.public_key = BlockchainUtils.generate_keypair()
        self.address = BlockchainUtils.get_address_from_public_key(self.public_key)
        
        print(f"Node initialized with address: {self.address}")
    
    def create_transaction(self, recipient: str, amount: float, fee: float = 0.01) -> str:
        """Create and broadcast a transaction"""
        # Create transaction
        tx = Transaction.create(
            sender=self.address,
            recipient=recipient,
            amount=amount,
            fee=fee,
            private_key=self.private_key,
            public_key=self.public_key
        )
        
        # Prepare message
        message_data = {
            'type': 'transaction',
            'payload': tx.to_dict()
        }
        
        # Broadcast transaction
        tx_hash, _ = self.node.create_shared_message(message_data)
        print(f"Transaction created and broadcast: {tx.tx_id[:8]}")
        
        return tx.tx_id
    
    def mine_block(self) -> Optional[str]:
        """Mine a new block with transactions from mempool"""
        # Get transactions from mempool
        transactions = self.mempool.get_transactions_by_fee(max_count=10)
        
        if not transactions:
            print("No transactions in mempool to mine")
            return None
        
        print(f"Mining block with {len(transactions)} transactions")
        
        # Create new block
        block = self.ledger.create_block(transactions, self.address)
        
        # Prepare message
        message_data = {
            'type': 'block',
            'payload': block.to_dict()
        }
        
        # Broadcast block
        block_hash, _ = self.node.create_shared_message(message_data)
        print(f"Block mined and broadcast: {block.hash[:8]}")
        
        return block.hash
    
    def get_balance(self, address: Optional[str] = None) -> float:
        """Get balance for an address or self if None"""
        if address is None:
            address = self.address
        return self.ledger.balances.get(address, 0)
    
    def get_blockchain_info(self) -> Dict:
        """Get general information about the blockchain"""
        return {
            'chain_length': len(self.ledger.chain),
            'latest_block_hash': self.ledger.chain[-1].hash,
            'difficulty': self.ledger.difficulty,
            'mempool_size': len(self.mempool.transactions),
            'node_address': self.address,
            'node_balance': self.get_balance()
        }


# Helper functions for tutorial
def generate_wallet():
    """Generate and return a new wallet with keys and address"""
    private_key, public_key = BlockchainUtils.generate_keypair()
    address = BlockchainUtils.get_address_from_public_key(public_key)
    
    return {
        'private_key': private_key,
        'public_key': public_key,
        'address': address
    }


def format_balance(balance: float) -> str:
    """Format balance with 2 decimal places"""
    return f"{balance:.2f}"


if __name__ == "__main__":
    print("Blockchain module loaded. Import this module in your application.")