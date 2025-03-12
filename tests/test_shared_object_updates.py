# tests/test_shared_object_updates.py

from typing import List
import unittest
import time
import hashlib
from chaincraft import ChaincraftNode
from shared_object import SharedObject, SharedObjectException
from shared_message import SharedMessage

class SimpleChainObject(SharedObject):
    def __init__(self):
        genesis = "genesis"
        genesis_hash = hashlib.sha256(genesis.encode()).hexdigest()
        self.chain = [genesis_hash]
        
    def calculate_next_hash(self, prev_hash: str) -> str:
        return hashlib.sha256(prev_hash.encode()).hexdigest()
        
    def is_valid(self, message: SharedMessage) -> bool:
        """Always valid since we're dealing with string messages"""
        if message.data in self.chain:
            return True
        
        return self.calculate_next_hash(self.chain[-1]) == message.data

    def is_valid_digest(self, hash_digest: str) -> bool:
        """A digest is valid if it's already in our chain - used for sync"""
        return hash_digest in self.chain

    def add_message(self, message: SharedMessage) -> None:
        """Add a new hash to the chain"""
        if message.data in self.chain:
            return
        
        if len(self.chain) == 0:
            genesis_hash = hashlib.sha256("genesis".encode()).hexdigest()
            if message.data == genesis_hash:
                self.chain.append(message.data)
            return

        # Accept any hash that follows correctly from any hash in our chain
        for i in range(len(self.chain)):
            next_hash = self.calculate_next_hash(self.chain[i])
            if message.data == next_hash:
                self.chain.append(message.data)
                return

    def gossip_object(self, digest) -> List[SharedMessage]:
        """Return ALL subsequent hashes after the given digest"""
        try:
            index = self.chain.index(digest)
            
            next_hashes = []
            for i in range(index, len(self.chain) - 1):
                next_hash = self.chain[i + 1]
                next_hashes.append(next_hash)
            
            return [SharedMessage(data=hash) for hash in next_hashes]
                
        except ValueError:
            return []
                
    def add_digest(self, hash_digest: str) -> bool:
        if not self.chain:
            return False
            
        prev_hash = self.chain[-1]
        expected_hash = self.calculate_next_hash(prev_hash)
        
        if hash_digest == expected_hash:
            self.chain.append(hash_digest)
            return True
            
        return False
        
    def is_merkelized(self) -> bool:
        return True
    
    def get_latest_digest(self) -> str:
        return self.chain[-1]
    
    def has_digest(self, hash_digest: str) -> bool:
        return hash_digest in self.chain
        
    def add_next_hash(self) -> str:
        next_hash = self.calculate_next_hash(self.chain[-1])
        self.chain.append(next_hash)
        return next_hash
    
    def get_messages_since_digest(self, digest: str) -> List[SharedMessage]:
        try:
            index = self.chain.index(digest)
            valid_hashes = []
            
            for i in range(index + 1, len(self.chain)):
                prev_hash = self.chain[i - 1]
                current_hash = self.chain[i]
                expected_hash = self.calculate_next_hash(prev_hash)
                if current_hash == expected_hash:
                    valid_hashes.append(current_hash)
                else:
                    break
            
            return [SharedMessage(data=hash) for hash in valid_hashes]
            
        except ValueError:
            return []        

# Test code
        
def create_network(num_nodes):
    nodes = [ChaincraftNode(persistent=False) for _ in range(num_nodes)]
    for node in nodes:
        node.add_shared_object(SimpleChainObject())
        node.start()
    return nodes

def connect_nodes(nodes):
    """Connect nodes bidirectionally in a ring"""
    num_nodes = len(nodes)
    for i in range(num_nodes):
        # Connect to next node
        next_node = (i + 1) % num_nodes
        nodes[i].connect_to_peer(nodes[next_node].host, nodes[next_node].port)
        nodes[next_node].connect_to_peer(nodes[i].host, nodes[i].port)
        
        # Optional: also connect previous node for redundancy
        prev_node = (i - 1) % num_nodes
        nodes[i].connect_to_peer(nodes[prev_node].host, nodes[prev_node].port)
        nodes[prev_node].connect_to_peer(nodes[i].host, nodes[i].port)

        # Log connections
        print(f"Connected nodes: {i} <-> {next_node} and {i} <-> {prev_node}")

def wait_for_chain_sync(nodes, expected_chain_length, timeout=30):
    start_time = time.time()
    last_print_time = start_time
    
    while time.time() - start_time < timeout:
        current_time = time.time()
        
        # Check more frequently
        time.sleep(0.1)  # Reduced from 0.5 to 0.1
        
        # Check for sync
        chain_lengths = [len(node.shared_objects[0].chain) for node in nodes]
        if all(length == expected_chain_length for length in chain_lengths):
            chains = [node.shared_objects[0].chain for node in nodes]
            if all(chain == chains[0] for chain in chains):
                return True
                
        # Print diagnostics more frequently when running as part of suite
        if current_time - last_print_time >= 2:  # Reduced from 5 to 2 seconds
            for i, node in enumerate(nodes):
                chain = node.shared_objects[0].chain
                print(f"Node {i} chain length: {len(chain)}")
                print(f"Node {i} chain: {[h[:8] for h in chain]}")
            last_print_time = current_time
    
    # Print final state on timeout
    print("Sync timeout reached. Final chain states:")
    for i, node in enumerate(nodes):
        chain = node.shared_objects[0].chain
        print(f"Node {i} final chain length: {len(chain)}")
        print(f"Node {i} final chain: {[h[:8] for h in chain]}")
    
    return False

class TestSharedObjectUpdates(unittest.TestCase):
    def setUp(self):
        self.num_nodes = 5
        self.nodes = create_network(self.num_nodes)
        connect_nodes(self.nodes)
        time.sleep(1)
        
    def tearDown(self):
        for node in self.nodes:
            node.close()
            
    def test_shared_object_updates(self):
        # Add three new hashes to the chain on node 0
        chain_obj = self.nodes[0].shared_objects[0]
        
        # Add three new blocks
        for _ in range(3):
            next_hash = chain_obj.add_next_hash()
            print(f"Added new hash: {next_hash}")
            self.nodes[0].create_shared_message(next_hash)
        
        # Wait for the chain to sync across all nodes
        self.assertTrue(wait_for_chain_sync(self.nodes, 4))
        
        # Check that all nodes have the same chain
        expected_chain = self.nodes[0].shared_objects[0].chain
        for node in self.nodes:
            self.assertEqual(node.shared_objects[0].chain, expected_chain)
            
        # Verify the hash chain integrity
        for node in self.nodes:
            chain = node.shared_objects[0].chain
            for i in range(1, len(chain)):
                expected_hash = hashlib.sha256(chain[i-1].encode()).hexdigest()
                self.assertEqual(chain[i], expected_hash, 
                               f"Hash chain broken at index {i}")
                
    def test_concurrent_updates(self):
        """Test multiple nodes adding hashes concurrently"""
        # Have nodes 0, 2, and 4 add a hash each
        added_hashes = []
        for i in [0, 2, 4]:
            chain_obj = self.nodes[i].shared_objects[0]
            next_hash = chain_obj.add_next_hash()
            added_hashes.append(next_hash)
        
        # Wait for sync, should include all valid hashes
        self.assertTrue(wait_for_chain_sync(self.nodes, 2))
        
        # Verify all nodes have the same chain and include the valid hash
        first_chain = self.nodes[0].shared_objects[0].chain
        for node in self.nodes:
            self.assertEqual(node.shared_objects[0].chain, first_chain)
            # Should at least include first added hash
            self.assertIn(added_hashes[0], node.shared_objects[0].chain)

    def test_node_disconnection(self):
        # Add initial hash to node 0
        chain_obj = self.nodes[0].shared_objects[0]
        first_hash = chain_obj.add_next_hash()
        
        # Wait for first sync
        self.assertTrue(wait_for_chain_sync(self.nodes, 2))
        
        # Disconnect node 4 and wait longer for network to stabilize
        self.nodes[4].close()
        time.sleep(2)  # Increased from 1 to 2 seconds
        
        # Add more hashes and wait for propagation
        for _ in range(2):
            chain_obj.add_next_hash()
        time.sleep(1)  # Add delay for hash propagation
        
        # Recreate node 4 with more careful connection handling
        self.nodes[4] = ChaincraftNode(persistent=False)
        self.nodes[4].add_shared_object(SimpleChainObject())
        self.nodes[4].start()
        time.sleep(1)  # Wait for node to initialize
        
        # Reconnect bidirectionally with delays
        self.nodes[3].connect_to_peer(self.nodes[4].host, self.nodes[4].port)
        time.sleep(0.5)
        self.nodes[4].connect_to_peer(self.nodes[3].host, self.nodes[3].port)
        time.sleep(0.5)
        self.nodes[0].connect_to_peer(self.nodes[4].host, self.nodes[4].port)
        time.sleep(0.5)
        self.nodes[4].connect_to_peer(self.nodes[0].host, self.nodes[0].port)
        time.sleep(0.5)
        
        # Wait for resync with increased timeout
        self.assertTrue(wait_for_chain_sync(self.nodes, 4, timeout=30))

    def test_chain_integrity(self):
        """Test that invalid hashes are rejected"""
        chain_obj = self.nodes[0].shared_objects[0]
        
        # Add a valid hash
        valid_hash = chain_obj.add_next_hash()
        self.assertTrue(wait_for_chain_sync(self.nodes, 2, timeout=60))
        
        # Try to add invalid hash (not derived from previous)
        invalid_hash = hashlib.sha256("invalid".encode()).hexdigest()
        
        # Create and broadcast invalid message - should raise exception
        with self.assertRaises(SharedObjectException) as context:
            self.nodes[0].create_shared_message(invalid_hash)
        
        self.assertEqual(str(context.exception), "Invalid message for shared objects")
        
        # Verify no node accepted the invalid hash
        time.sleep(2)  # Give time for any potential sync
        for node in self.nodes:
            self.assertNotIn(invalid_hash, node.shared_objects[0].chain)

    def test_long_chain_sync(self):
        """Test syncing a longer chain across all nodes"""
        chain_obj = self.nodes[0].shared_objects[0]
        
        # Add 10 hashes
        for i in range(10):
            chain_obj.add_next_hash()
        
        # Should sync all 11 blocks (genesis + 10 new)
        self.assertTrue(wait_for_chain_sync(self.nodes, 11))
        
        # Verify all chains match
        expected_chain = self.nodes[0].shared_objects[0].chain
        for node in self.nodes:
            self.assertEqual(len(node.shared_objects[0].chain), 11)
            self.assertEqual(node.shared_objects[0].chain, expected_chain)

if __name__ == '__main__':
    unittest.main()