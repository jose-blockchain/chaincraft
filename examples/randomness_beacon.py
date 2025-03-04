import json
import time
import hashlib
import random
from typing import List, Dict, Optional, Tuple, Any
import os
import secrets
import threading

from shared_object import SharedObject, SharedObjectException
from shared_message import SharedMessage
from chaincraft import ChaincraftNode
from crypto_primitives.pow import ProofOfWorkPrimitive


# Generate a random Ethereum-like address (20 bytes)
def generate_eth_address() -> str:
    address_bytes = secrets.token_bytes(20)
    return "0x" + address_bytes.hex()


class Block:
    """Represents a block in the randomness beacon chain"""
    
    def __init__(
        self,
        coinbase_address: str,
        prev_block_hash: str,
        block_height: int,
        timestamp: float,
        nonce: int,
        difficulty_bits: int
    ):
        self.coinbase_address = coinbase_address
        self.prev_block_hash = prev_block_hash
        self.block_height = block_height
        self.timestamp = timestamp
        self.nonce = nonce
        self.difficulty_bits = difficulty_bits
        # Calculate the hash after all attributes are set
        self.block_hash = self._calculate_hash()
    
    def _calculate_hash(self) -> str:
        """Calculate the hash of this block"""
        block_data = self.to_dict()
        # Remove the hash field itself before hashing
        if 'block_hash' in block_data:
            del block_data['block_hash']
        block_str = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_str.encode()).hexdigest()
    
    def to_dict(self) -> Dict:
        """Convert the block to a dictionary"""
        return {
            'coinbase_address': self.coinbase_address,
            'prev_block_hash': self.prev_block_hash,
            'block_height': self.block_height,
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'difficulty_bits': self.difficulty_bits
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Block':
        """Create a Block instance from a dictionary"""
        block = cls(
            coinbase_address=data['coinbase_address'],
            prev_block_hash=data['prev_block_hash'],
            block_height=data['block_height'],
            timestamp=data['timestamp'],
            nonce=data['nonce'],
            difficulty_bits=data['difficulty_bits']
        )
        # Verify the hash if provided
        if 'block_hash' in data and data['block_hash'] != block.block_hash:
            raise ValueError(f"Block hash mismatch: {data['block_hash']} != {block.block_hash}")
        return block


class RandomnessBeacon(SharedObject):
    """
    A randomness beacon implemented as a blockchain without transactions.
    Each block is linked to the previous block and contains a random value
    derived from the block hash.
    """
    
    # Genesis block hash - known to everyone and hardcoded
    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
    TARGET_BLOCK_TIME = 10  # seconds
    
    def __init__(self, coinbase_address: Optional[str] = None, initial_difficulty_bits: int = 16):
        """
        Initialize the randomness beacon.
        
        Args:
            coinbase_address: The address of the node that will mine blocks. If None,
                              a new random address will be generated.
            initial_difficulty_bits: Initial difficulty for mining.
        """
        # Generate a random coinbase address if none provided
        self.coinbase_address = coinbase_address or generate_eth_address()
        
        # Initialize the blockchain with a genesis block
        self.chain: List[Block] = []
        
        # Ledger to track block rewards per address
        self.ledger: Dict[str, int] = {}
        
        # For merklelized sync
        self.chain_hashes: List[str] = []
        
        # Add genesis block
        self._add_genesis_block(initial_difficulty_bits)
    
    def _add_genesis_block(self, initial_difficulty_bits: int) -> None:
        """Add the genesis block to the chain"""
        genesis_block = Block(
            coinbase_address="0x0000000000000000000000000000000000000000",
            prev_block_hash=self.GENESIS_HASH,
            block_height=0,
            timestamp=0.0,
            nonce=0,
            difficulty_bits=initial_difficulty_bits
        )
        self.chain.append(genesis_block)
        self.chain_hashes.append(genesis_block.block_hash)
    
    def get_latest_block(self) -> Block:
        """Get the latest block in the chain"""
        return self.chain[-1]
    
    def is_valid(self, message: SharedMessage) -> bool:
        """
        Check if a message contains a valid block proposal.
        
        Args:
            message: The SharedMessage potentially containing a block proposal.
            
        Returns:
            bool: True if the message contains a valid block proposal, False otherwise.
        """
        try:
            # Try to parse as a block proposal
            block_data = message.data
            if not isinstance(block_data, dict):
                return False
            
            # Check if it's a valid block
            return self._is_valid_block_proposal(block_data)
        except Exception as e:
            print(f"Error validating block proposal: {e}")
            return False
    
    def _is_valid_block_proposal(self, block_data: Dict) -> bool:
        """
        Check if a block proposal is valid.
        
        Args:
            block_data: The block data to validate.
            
        Returns:
            bool: True if the block proposal is valid, False otherwise.
        """
        try:
            # Check if the block data contains all required fields
            required_fields = [
                'coinbase_address', 'prev_block_hash', 'block_height',
                'timestamp', 'nonce', 'difficulty_bits', 'block_hash'
            ]
            if not all(field in block_data for field in required_fields):
                print(f"Missing required fields: {required_fields}")
                return False
            
            # Create a Block object to validate it
            block = Block.from_dict(block_data)
            
            # Check if the block height is valid (should be 1 higher than the latest block or same for collisions)
            latest_block = self.get_latest_block()
            if block.block_height != latest_block.block_height + 1 and block.block_height != latest_block.block_height:
                print(f"Invalid block height: {block.block_height}, expected {latest_block.block_height + 1} or {latest_block.block_height}")
                return False
            
            # For height+1 blocks, check if the previous block hash matches the latest block hash
            if block.block_height == latest_block.block_height + 1 and block.prev_block_hash != latest_block.block_hash:
                print(f"Invalid previous block hash: {block.prev_block_hash} != {latest_block.block_hash}")
                return False
            
            # For same-height blocks (collisions), validate against the same previous block
            if block.block_height == latest_block.block_height and block.prev_block_hash != latest_block.prev_block_hash:
                print(f"Invalid previous block hash for collision block: {block.prev_block_hash} != {latest_block.prev_block_hash}")
                return False
            
            # Check if the timestamp is not too far in the future (< 5 seconds)
            current_time = time.time() * 1000  # Convert to milliseconds
            if block.timestamp > current_time + 5000:
                print(f"Block timestamp too far in the future: {block.timestamp} > {current_time + 5000}")
                return False
            
            # For blocks after height 1, verify the difficulty bits are consistent with the rule
            if block.block_height > 1:
                # Get the previous block
                prev_block_index = -1
                if block.block_height == latest_block.block_height:
                    # For collision blocks, we need to find the block that came before
                    # We can use block.prev_block_hash to find it
                    for i, chain_block in enumerate(self.chain):
                        if chain_block.block_hash == block.prev_block_hash:
                            prev_block_index = i
                            break
                else:
                    # For next height blocks, previous block is the latest
                    prev_block_index = -1
                
                prev_block = self.chain[prev_block_index]
                
                # Calculate block time in seconds
                block_time = (block.timestamp - prev_block.timestamp) / 1000.0
                
                # Check if difficulty adjustment is consistent with block time
                expected_difficulty = prev_block.difficulty_bits
                if block_time < self.TARGET_BLOCK_TIME:
                    # Block was mined too quickly, should increase difficulty
                    expected_difficulty += 1
                else:
                    # Block was mined too slowly, should decrease difficulty (but keep it positive)
                    expected_difficulty = max(1, expected_difficulty - 1)
                
                if block.difficulty_bits != expected_difficulty:
                    print(f"Invalid difficulty adjustment: {block.difficulty_bits} != {expected_difficulty}")
                    print(f"Block time: {block_time} seconds, Target: {self.TARGET_BLOCK_TIME} seconds")
                    return False
            
            # Verify the PoW
            challenge = block.coinbase_address + block.prev_block_hash
            pow_primitive = ProofOfWorkPrimitive(difficulty_bits=block.difficulty_bits)
            if not pow_primitive.verify_proof(challenge, block.nonce):
                print(f"Invalid PoW for block: {block.block_hash}")
                return False
            
            # All checks passed
            return True
        except Exception as e:
            print(f"Error validating block proposal: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _resolve_collision(self, existing_block: Block, new_block: Block) -> Block:
        """
        Resolve a collision between two blocks at the same height.
        
        Args:
            existing_block: The existing block in the chain.
            new_block: The new block being proposed.
            
        Returns:
            Block: The block that should be used.
        """
        # Compare lexicographically the block hashes
        if new_block.block_hash < existing_block.block_hash:
            # New block wins
            return new_block
        else:
            # Existing block wins
            return existing_block
        
    def add_message(self, message: SharedMessage) -> None:
        """
        Add a new block to the chain from a message.
        
        Args:
            message: The SharedMessage containing a block proposal.
        """
        try:
            block_data = message.data
            proposed_block = Block.from_dict(block_data)
            
            # Get the current latest block
            latest_block = self.get_latest_block()
            
            # If the proposed block is for the same height as the latest block,
            # we have a collision to resolve
            if proposed_block.block_height == latest_block.block_height:
                # Resolve the collision
                winner_block = self._resolve_collision(latest_block, proposed_block)
                
                # If the new block won, replace the last block
                if winner_block.block_hash == proposed_block.block_hash:
                    # Rollback the ledger increase for the previous block miner
                    self.ledger[latest_block.coinbase_address] = self.ledger.get(latest_block.coinbase_address, 0) - 1
                    
                    # Replace the last block
                    self.chain[-1] = proposed_block
                    self.chain_hashes[-1] = proposed_block.block_hash
                    
                    # Update the ledger for the new block miner
                    self.ledger[proposed_block.coinbase_address] = self.ledger.get(proposed_block.coinbase_address, 0) + 1
            
            # If the proposed block is for the next height, add it to the chain
            elif proposed_block.block_height == latest_block.block_height + 1:
                # Add the block to the chain
                self.chain.append(proposed_block)
                self.chain_hashes.append(proposed_block.block_hash)
                
                # Update the ledger
                self.ledger[proposed_block.coinbase_address] = self.ledger.get(proposed_block.coinbase_address, 0) + 1
            
            # Otherwise, ignore the block
            else:
                print(f"Ignoring block with invalid height: {proposed_block.block_height}")
        except Exception as e:
            print(f"Error adding block from message: {e}")
            import traceback
            traceback.print_exc()
    
    def _calculate_new_difficulty_bits(self, prev_block: Block, current_timestamp: float) -> int:
        """
        Calculate the new difficulty bits based on the previous block and current timestamp.
        
        Args:
            prev_block: The previous block.
            current_timestamp: The current timestamp in milliseconds.
            
        Returns:
            int: The new difficulty bits.
        """
        # For the first block after genesis, use the same difficulty
        if prev_block.block_height == 0:
            return prev_block.difficulty_bits
            
        # Calculate the block time in seconds
        block_time = (current_timestamp - prev_block.timestamp) / 1000.0
        
        # Adjust difficulty to target a mean of TARGET_BLOCK_TIME seconds
        if block_time < self.TARGET_BLOCK_TIME:
            # Block was mined too quickly, increase difficulty
            return prev_block.difficulty_bits + 1
        else:
            # Block was mined too slowly, decrease difficulty (but keep it positive)
            return max(1, prev_block.difficulty_bits - 1)
    
    def mine_block(self) -> Block:
        """
        Mine a new block for this beacon.
        
        Returns:
            Block: The newly mined block.
        """
        latest_block = self.get_latest_block()
        block_height = latest_block.block_height + 1
        prev_block_hash = latest_block.block_hash
        start_timestamp = time.time() * 1000  # milliseconds when mining started
        
        # Calculate the difficulty bits for the new block based on previous block
        difficulty_bits = self._calculate_new_difficulty_bits(latest_block, start_timestamp)
        
        # Create the challenge for mining
        challenge = self.coinbase_address + prev_block_hash
        
        # Create a PoW instance with the calculated difficulty
        pow_primitive = ProofOfWorkPrimitive(difficulty_bits=difficulty_bits)
        
        # Mine a new block - this will give us a nonce that produces a hash with the required number of leading zeros
        nonce = pow_primitive.create_proof(challenge)
        
        # Get current timestamp after mining is complete
        end_timestamp = time.time() * 1000
        
        # Create a new block with the found nonce
        new_block = Block(
            coinbase_address=self.coinbase_address,
            prev_block_hash=prev_block_hash,
            block_height=block_height,
            timestamp=end_timestamp,  # Use timestamp after mining
            nonce=nonce,
            difficulty_bits=difficulty_bits
        )
        
        return new_block
    
    def get_randomness(self, block_height: Optional[int] = None) -> str:
        """
        Get the randomness for a specific block height.
        If block_height is None, the latest block is used.
        
        Args:
            block_height: The block height to get the randomness for.
            
        Returns:
            str: The randomness value (a hex string).
        """
        if block_height is None:
            block = self.get_latest_block()
        elif 0 <= block_height < len(self.chain):
            block = self.chain[block_height]
        else:
            raise ValueError(f"Invalid block height: {block_height}")
        
        # The randomness is the block hash, which is already a hex string
        return block.block_hash
    
    def get_binary_randomness(self, block_height: Optional[int] = None, length: int = 256) -> str:
        """
        Get a binary string of randomness from a block.
        
        Args:
            block_height: The block height to get the randomness for.
            length: The length of the binary string to return (default: 256 bits).
            
        Returns:
            str: A binary string of random bits.
        """
        hex_randomness = self.get_randomness(block_height)
        # Convert hex to binary
        binary = bin(int(hex_randomness, 16))[2:]
        # Pad to full length
        padded_binary = binary.zfill(256)
        # Return the requested length
        return padded_binary[:length]
    
    # Methods required for merklelized storage
    
    def is_merkelized(self) -> bool:
        """
        Check if this shared object is merklelized.
        
        Returns:
            bool: True, as this object is merklelized.
        """
        return True
    
    def get_latest_digest(self) -> str:
        """
        Get the latest digest for this shared object.
        
        Returns:
            str: The hash of the latest block.
        """
        return self.get_latest_block().block_hash
    
    def has_digest(self, hash_digest: str) -> bool:
        """
        Check if this shared object has a specific digest.
        
        Args:
            hash_digest: The digest to check for.
            
        Returns:
            bool: True if the digest exists in the chain, False otherwise.
        """
        return hash_digest in self.chain_hashes
    
    def is_valid_digest(self, hash_digest: str) -> bool:
        """
        Check if a digest is valid for this shared object.
        
        Args:
            hash_digest: The digest to check.
            
        Returns:
            bool: True if the digest is valid, False otherwise.
        """
        return self.has_digest(hash_digest)
    
    def add_digest(self, hash_digest: str) -> bool:
        """
        Add a digest to the chain.
        
        Args:
            hash_digest: The digest to add.
            
        Returns:
            bool: True if the digest was added, False otherwise.
        """
        if hash_digest not in self.chain_hashes:
            # This is just for merklelized sync - actual blocks are added via add_message
            self.chain_hashes.append(hash_digest)
            return True
        return False
    
    def gossip_object(self, digest: str) -> List[SharedMessage]:
        """
        Get all block messages since a specific digest for gossiping.
        
        Args:
            digest: The digest to start from.
            
        Returns:
            List[SharedMessage]: The messages to gossip.
        """
        if not self.has_digest(digest):
            return []
        
        # Find the index of the digest
        index = self.chain_hashes.index(digest)
        
        # Get all blocks after the digest
        blocks_to_gossip = self.chain[index+1:]
        
        # Convert blocks to messages
        messages = []
        for block in blocks_to_gossip:
            messages.append(SharedMessage(data=block.to_dict()))
        
        return messages
    
    def get_messages_since_digest(self, digest: str) -> List[SharedMessage]:
        """
        Get all block messages since a specific digest.
        
        Args:
            digest: The digest to start from.
            
        Returns:
            List[SharedMessage]: The messages since the digest.
        """
        return self.gossip_object(digest)


class RandomnessBeaconNode(ChaincraftNode):
    """
    A node in the randomness beacon network.
    """
    
    def __init__(
        self,
        coinbase_address: Optional[str] = None,
        initial_difficulty_bits: int = 16,
        **kwargs
    ):
        """
        Initialize a randomness beacon node.
        
        Args:
            coinbase_address: The address of this node. If None, a random address will be generated.
            initial_difficulty_bits: Initial difficulty for mining.
            **kwargs: Additional arguments to pass to the ChaincraftNode constructor.
        """
        super().__init__(**kwargs)
        
        # Create a randomness beacon shared object
        self.beacon = RandomnessBeacon(
            coinbase_address=coinbase_address,
            initial_difficulty_bits=initial_difficulty_bits
        )
        
        # Add the beacon as a shared object
        self.add_shared_object(self.beacon)
        
        # Mining thread
        self.mining_thread = None
        self.is_mining = False
    
    def start_mining(self) -> None:
        """Start the mining thread"""
        if not self.mining_thread:
            self.is_mining = True
            self.mining_thread = threading.Thread(target=self._mine_blocks, daemon=True)
            self.mining_thread.start()
    
    def stop_mining(self) -> None:
        """Stop the mining thread"""
        self.is_mining = False
        if self.mining_thread:
            self.mining_thread.join(timeout=1)
            self.mining_thread = None
    
    def _mine_blocks(self) -> None:
        """Mine blocks continuously"""
        print(f"Starting mining with address {self.beacon.coinbase_address}")
        while self.is_mining and self.is_running:
            try:
                # Mine a new block
                new_block = self.beacon.mine_block()
                
                # Create a message with the block
                block_message = SharedMessage(data=new_block.to_dict())
                
                # Send the block to all peers
                self.broadcast(block_message.to_json())
                
                # Also add it locally
                self.handle_message(
                    block_message.to_json(),
                    hashlib.sha256(block_message.to_json().encode()).hexdigest(),
                    ("127.0.0.1", 0)
                )
                
                print(f"Mined block {new_block.block_height} with hash {new_block.block_hash[:8]} " + 
                      f"at difficulty {new_block.difficulty_bits}")
                
                # Sleep a little to prevent flooding the network
                time.sleep(0.1)
            except Exception as e:
                print(f"Error mining block: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(1)
    
    def get_randomness(self, block_height: Optional[int] = None) -> str:
        """
        Get the randomness for a specific block height.
        
        Args:
            block_height: The block height to get the randomness for.
            
        Returns:
            str: The randomness value (a hex string).
        """
        return self.beacon.get_randomness(block_height)
    
    def get_binary_randomness(self, block_height: Optional[int] = None, length: int = 256) -> str:
        """
        Get a binary string of randomness from a block.
        
        Args:
            block_height: The block height to get the randomness for.
            length: The length of the binary string to return (default: 256 bits).
            
        Returns:
            str: A binary string of random bits.
        """
        return self.beacon.get_binary_randomness(block_height, length)
    
    def get_difficulty(self) -> int:
        """
        Get the current difficulty bits from the latest block.
        
        Returns:
            int: The current difficulty bits
        """
        return self.beacon.get_latest_block().difficulty_bits


# Additional utility functions for running a randomness beacon network

def create_randomness_beacon_network(num_nodes: int, initial_difficulty_bits: int = 16) -> List[RandomnessBeaconNode]:
    """
    Create a network of randomness beacon nodes.
    
    Args:
        num_nodes: The number of nodes to create.
        initial_difficulty_bits: Initial difficulty for mining.
        
    Returns:
        List[RandomnessBeaconNode]: The list of nodes in the network.
    """
    nodes = []
    for _ in range(num_nodes):
        node = RandomnessBeaconNode(
            persistent=False,
            initial_difficulty_bits=initial_difficulty_bits
        )
        node.start()
        nodes.append(node)
    
    # Connect the nodes in a ring
    for i in range(num_nodes):
        node1 = nodes[i]
        node2 = nodes[(i+1) % num_nodes]
        node1.connect_to_peer(node2.host, node2.port)
        node2.connect_to_peer(node1.host, node1.port)
    
    return nodes


def start_mining_in_network(nodes: List[RandomnessBeaconNode]) -> None:
    """
    Start mining in all nodes in the network.
    
    Args:
        nodes: The list of nodes in the network.
    """
    for node in nodes:
        node.start_mining()


def stop_mining_in_network(nodes: List[RandomnessBeaconNode]) -> None:
    """
    Stop mining in all nodes in the network.
    
    Args:
        nodes: The list of nodes in the network.
    """
    for node in nodes:
        node.stop_mining()


def close_network(nodes: List[RandomnessBeaconNode]) -> None:
    """
    Close all nodes in the network.
    
    Args:
        nodes: The list of nodes in the network.
    """
    stop_mining_in_network(nodes)
    for node in nodes:
        node.close()


def test_network(num_nodes: int = 3, mining_time: int = 30, initial_difficulty_bits: int = 16) -> None:
    """
    Test the randomness beacon network.
    
    Args:
        num_nodes: The number of nodes to create.
        mining_time: The number of seconds to mine for.
        initial_difficulty_bits: Initial difficulty for mining.
    """
    print(f"Creating a network of {num_nodes} nodes...")
    nodes = create_randomness_beacon_network(num_nodes, initial_difficulty_bits)
    
    print(f"Starting mining for {mining_time} seconds...")
    start_mining_in_network(nodes)
    
    # Wait for mining to happen
    try:
        for _ in range(mining_time):
            time.sleep(1)
            
            # Print the current state of the network
            print("\nCurrent network state:")
            for i, node in enumerate(nodes):
                latest_block = node.beacon.get_latest_block()
                print(f"Node {i} (address: {node.beacon.coinbase_address[:10]}...): " +
                      f"Chain height: {latest_block.block_height}, " +
                      f"Difficulty: {latest_block.difficulty_bits}, " +
                      f"Mined blocks: {node.beacon.ledger.get(node.beacon.coinbase_address, 0)}")
                print(f"  Latest randomness: {node.get_randomness()[:16]}...")
                
                # Count of 0s and 1s in binary randomness
                binary = node.get_binary_randomness()
                zeros = binary.count('0')
                ones = binary.count('1')
                print(f"  Binary randomness: {zeros} zeros, {ones} ones ({zeros/(zeros+ones)*100:.1f}% zeros)")
    finally:
        print("Stopping mining and closing network...")
        close_network(nodes)


# Entry point
if __name__ == "__main__":
    import threading
    import argparse
    
    parser = argparse.ArgumentParser(description='Randomness Beacon Network')
    parser.add_argument('--nodes', type=int, default=3, help='Number of nodes in the network')
    parser.add_argument('--time', type=int, default=60, help='Time to run in seconds')
    parser.add_argument('--difficulty', type=int, default=12, help='Initial mining difficulty bits')
    
    args = parser.parse_args()
    
    test_network(args.nodes, args.time, args.difficulty)