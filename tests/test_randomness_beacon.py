# tests/test_randomness_beacon.py

import sys, os
import unittest
import time
import hashlib
import json
import statistics
from typing import List
import threading

# Make sure the examples module is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from examples.randomness_beacon import (
    RandomnessBeacon, RandomnessBeaconNode, Block,
    create_randomness_beacon_network, start_mining_in_network,
    stop_mining_in_network, close_network
)
from shared_message import SharedMessage
from crypto_primitives.pow import ProofOfWorkPrimitive


class TestBlock(unittest.TestCase):
    """Test the Block class functionality"""
    
    def test_block_creation(self):
        """Test creating a block and calculating its hash"""
        block = Block(
            coinbase_address="0x1234567890abcdef1234567890abcdef12345678",
            prev_block_hash="0000000000000000000000000000000000000000000000000000000000000000",
            block_height=1,
            timestamp=time.time() * 1000,
            nonce=123456,
            difficulty_bits=16
        )
        
        # Check that the block hash is calculated correctly
        self.assertIsNotNone(block.block_hash)
        self.assertEqual(len(block.block_hash), 64)  # SHA-256 hex digest length
        
        # Test converting to and from dict
        block_dict = block.to_dict()
        reconstructed_block = Block.from_dict(block_dict)
        
        self.assertEqual(block.coinbase_address, reconstructed_block.coinbase_address)
        self.assertEqual(block.prev_block_hash, reconstructed_block.prev_block_hash)
        self.assertEqual(block.block_height, reconstructed_block.block_height)
        self.assertEqual(block.timestamp, reconstructed_block.timestamp)
        self.assertEqual(block.nonce, reconstructed_block.nonce)
        self.assertEqual(block.difficulty_bits, reconstructed_block.difficulty_bits)
        self.assertEqual(block.block_hash, reconstructed_block.block_hash)
    
    def test_block_hash_calculation(self):
        """Test that the block hash calculation is deterministic"""
        block = Block(
            coinbase_address="0x1234567890abcdef1234567890abcdef12345678",
            prev_block_hash="0000000000000000000000000000000000000000000000000000000000000000",
            block_height=1,
            timestamp=1234567890.123,
            nonce=123456,
            difficulty_bits=16
        )
        
        # Calculate the hash manually
        block_dict = block.to_dict()
        block_str = json.dumps(block_dict, sort_keys=True)
        expected_hash = hashlib.sha256(block_str.encode()).hexdigest()
        
        # Check that the calculated hash matches
        self.assertEqual(block.block_hash, expected_hash)


class TestRandomnessBeacon(unittest.TestCase):
    """Test the RandomnessBeacon class functionality"""
    
    def setUp(self):
        """Set up a fresh randomness beacon for each test"""
        self.coinbase_address = "0x1234567890abcdef1234567890abcdef12345678"
        self.initial_difficulty_bits = 12
        self.beacon = RandomnessBeacon(
            coinbase_address=self.coinbase_address, 
            initial_difficulty_bits=self.initial_difficulty_bits
        )
    
    def test_genesis_block(self):
        """Test that the genesis block is created correctly"""
        genesis_block = self.beacon.get_latest_block()
        
        self.assertEqual(genesis_block.block_height, 0)
        self.assertEqual(genesis_block.prev_block_hash, self.beacon.GENESIS_HASH)
        self.assertEqual(genesis_block.coinbase_address, "0x0000000000000000000000000000000000000000")
        self.assertEqual(genesis_block.difficulty_bits, self.initial_difficulty_bits)
    
    def test_mining_block(self):
        """Test mining a new block"""
        # Mine a block
        new_block = self.beacon.mine_block()
        
        # Check that the block has the correct properties
        self.assertEqual(new_block.block_height, 1)
        self.assertEqual(new_block.prev_block_hash, self.beacon.get_latest_block().block_hash)
        self.assertEqual(new_block.coinbase_address, self.coinbase_address)
        
        # Check difficulty calculation: for the first block after genesis,
        # difficulty should remain the same as the genesis block
        genesis_block = self.beacon.get_latest_block()
        self.assertEqual(new_block.difficulty_bits, genesis_block.difficulty_bits)
        
        # Check that the block passes PoW verification
        challenge = new_block.coinbase_address + new_block.prev_block_hash
        pow_primitive = ProofOfWorkPrimitive(difficulty_bits=new_block.difficulty_bits)
        self.assertTrue(pow_primitive.verify_proof(challenge, new_block.nonce))
    
    def test_add_valid_block(self):
        """Test adding a valid block to the chain"""
        # Mine a block
        new_block = self.beacon.mine_block()
        
        # Create a message with the block
        message = SharedMessage(data=new_block.to_dict())
        
        # Add the message to the beacon
        self.beacon.add_message(message)
        
        # Check that the block was added to the chain
        self.assertEqual(len(self.beacon.chain), 2)
        self.assertEqual(self.beacon.get_latest_block().block_hash, new_block.block_hash)
        
        # Check that the ledger was updated
        self.assertEqual(self.beacon.ledger.get(self.coinbase_address, 0), 1)
    
    def test_reject_invalid_block(self):
        """Test rejecting an invalid block"""
        # Create an invalid block (wrong height)
        invalid_block = Block(
            coinbase_address=self.coinbase_address,
            prev_block_hash=self.beacon.get_latest_block().block_hash,
            block_height=100,  # Invalid height
            timestamp=time.time() * 1000,
            nonce=123456,
            difficulty_bits=self.initial_difficulty_bits
        )
        
        # Create a message with the invalid block
        message = SharedMessage(data=invalid_block.to_dict())
        
        # Check that the block is rejected
        self.assertFalse(self.beacon.is_valid(message))
        
        # Try to add the message to the beacon
        self.beacon.add_message(message)
        
        # Check that the block was not added to the chain
        self.assertEqual(len(self.beacon.chain), 1)  # Still only genesis block
    
    def test_reject_future_timestamp(self):
        """Test rejecting a block with a timestamp too far in the future"""
        # Mine a valid block
        valid_block = self.beacon.mine_block()
        
        # Create a block with a timestamp 6 seconds in the future
        future_time = time.time() * 1000 + 6000  # 6 seconds in the future
        future_block = Block(
            coinbase_address=self.coinbase_address,
            prev_block_hash=valid_block.prev_block_hash,
            block_height=valid_block.block_height,
            timestamp=future_time,
            nonce=valid_block.nonce,
            difficulty_bits=valid_block.difficulty_bits
        )
        
        # Create a message with the future block
        message = SharedMessage(data=future_block.to_dict())
        
        # Check that the block is rejected
        self.assertFalse(self.beacon.is_valid(message))
    
    def test_resolve_collision(self):
        """Test resolving a collision between two blocks at the same height"""
        # Mine and add a first block
        block1 = self.beacon.mine_block()
        message1 = SharedMessage(data=block1.to_dict())
        self.beacon.add_message(message1)
        
        # Check that the block was added
        self.assertEqual(len(self.beacon.chain), 2)
        self.assertEqual(self.beacon.ledger.get(self.coinbase_address, 0), 1)
        
        # Create a competing block that will have a lexicographically smaller block hash
        # by manipulating the nonce and timestamp until we get a hash that's smaller
        
        # Get the genesis block which is the previous block for our competing block
        genesis_block = self.beacon.chain[0]
        
        # Try different nonces until we get a block with a hash smaller than block1's hash
        competing_address = "0x9876543210abcdef9876543210abcdef98765432"
        timestamp = time.time() * 1000
        
        # Keep trying different nonces until we find one that produces a block hash
        # that is lexicographically smaller than block1's hash
        nonce = 1
        while True:
            competing_block = Block(
                coinbase_address=competing_address,
                prev_block_hash=genesis_block.block_hash,
                block_height=1,
                timestamp=timestamp,
                nonce=nonce,
                difficulty_bits=block1.difficulty_bits
            )
            
            # If we found a block with a smaller hash, break
            if competing_block.block_hash < block1.block_hash:
                break
                
            # Try next nonce
            nonce += 1
            
            # Avoid infinite loop in test
            if nonce > 100:
                self.fail("Couldn't find a competing block with smaller hash in reasonable time")
        
        # Create a message with the competing block
        message2 = SharedMessage(data=competing_block.to_dict())
        
        # Add the message to the beacon
        self.beacon.add_message(message2)
        
        # Check that the competing block replaced the original block
        self.assertEqual(len(self.beacon.chain), 2)  # Still 2 blocks
        self.assertEqual(self.beacon.get_latest_block().block_hash, competing_block.block_hash)
        
        # Check that the ledger was updated
        self.assertEqual(self.beacon.ledger.get(self.coinbase_address, 0), 0)  # Reward was taken away
        self.assertEqual(self.beacon.ledger.get(competing_address, 0), 1)  # Reward was given to new address


    def test_difficulty_adjustment(self):
        """Test adjusting difficulty based on block time"""
        # Add first block to start from a known state
        block1 = self.beacon.mine_block()
        message1 = SharedMessage(data=block1.to_dict())
        self.beacon.add_message(message1)
        
        # Create a second block with a timestamp 5 seconds after the first block
        # (this is less than the TARGET_BLOCK_TIME of 10 seconds, so difficulty should increase)
        prev_block = self.beacon.get_latest_block()
        block2 = Block(
            coinbase_address=self.coinbase_address,
            prev_block_hash=prev_block.block_hash,
            block_height=prev_block.block_height + 1,
            timestamp=prev_block.timestamp + 5000,  # 5 seconds after previous block
            nonce=123456,
            difficulty_bits=prev_block.difficulty_bits + 1  # Difficulty should increase by 1
        )
        
        # Mine it properly to get a valid PoW
        challenge = block2.coinbase_address + block2.prev_block_hash
        pow_primitive = ProofOfWorkPrimitive(difficulty_bits=block2.difficulty_bits)
        nonce = pow_primitive.create_proof(challenge)
        
        # Update the block with the correct nonce
        block2 = Block(
            coinbase_address=block2.coinbase_address,
            prev_block_hash=block2.prev_block_hash,
            block_height=block2.block_height,
            timestamp=block2.timestamp,
            nonce=nonce,
            difficulty_bits=block2.difficulty_bits
        )
        
        # Add the block
        message2 = SharedMessage(data=block2.to_dict())
        self.beacon.add_message(message2)
        
        # Check that the block was added with the increased difficulty
        self.assertEqual(self.beacon.get_latest_block().difficulty_bits, prev_block.difficulty_bits + 1)
        
        # Create a third block with a timestamp 15 seconds after the second block
        # (this is more than the TARGET_BLOCK_TIME of 10 seconds, so difficulty should decrease)
        prev_block = self.beacon.get_latest_block()
        block3 = Block(
            coinbase_address=self.coinbase_address,
            prev_block_hash=prev_block.block_hash,
            block_height=prev_block.block_height + 1,
            timestamp=prev_block.timestamp + 15000,  # 15 seconds after previous block
            nonce=123456,
            difficulty_bits=prev_block.difficulty_bits - 1  # Difficulty should decrease by 1
        )
        
        # Mine it properly to get a valid PoW
        challenge = block3.coinbase_address + block3.prev_block_hash
        pow_primitive = ProofOfWorkPrimitive(difficulty_bits=block3.difficulty_bits)
        nonce = pow_primitive.create_proof(challenge)
        
        # Update the block with the correct nonce
        block3 = Block(
            coinbase_address=block3.coinbase_address,
            prev_block_hash=block3.prev_block_hash,
            block_height=block3.block_height,
            timestamp=block3.timestamp,
            nonce=nonce,
            difficulty_bits=block3.difficulty_bits
        )
        
        # Add the block
        message3 = SharedMessage(data=block3.to_dict())
        self.beacon.add_message(message3)
        
        # Check that the block was added with the decreased difficulty
        self.assertEqual(self.beacon.get_latest_block().difficulty_bits, prev_block.difficulty_bits - 1)
    
    def test_get_randomness(self):
        """Test getting randomness from the beacon"""
        # Mine and add a block
        new_block = self.beacon.mine_block()
        message = SharedMessage(data=new_block.to_dict())
        self.beacon.add_message(message)
        
        # Get randomness from the latest block
        randomness = self.beacon.get_randomness()
        
        # Check that the randomness is the block hash
        self.assertEqual(randomness, new_block.block_hash)
        
        # Get binary randomness
        binary_randomness = self.beacon.get_binary_randomness(length=128)
        
        # Check that the binary randomness is the correct length
        self.assertEqual(len(binary_randomness), 128)
        
        # Check that the binary randomness only contains 0s and 1s
        self.assertTrue(all(bit in "01" for bit in binary_randomness))
    
    def test_merklelized_sync(self):
        """Test merklelized synchronization"""
        # Add several blocks to the chain
        for _ in range(5):
            new_block = self.beacon.mine_block()
            message = SharedMessage(data=new_block.to_dict())
            self.beacon.add_message(message)
        
        # Check that the chain has 6 blocks (genesis + 5 mined)
        self.assertEqual(len(self.beacon.chain), 6)
        
        # Get the digest of the third block
        third_block_digest = self.beacon.chain[3].block_hash
        
        # Check that the beacon has this digest
        self.assertTrue(self.beacon.has_digest(third_block_digest))
        self.assertTrue(self.beacon.is_valid_digest(third_block_digest))
        
        # Get all messages since this digest
        messages = self.beacon.get_messages_since_digest(third_block_digest)
        
        # Should be 2 messages (blocks 4 and 5)
        self.assertEqual(len(messages), 2)
        
        # Check that the messages contain the correct blocks
        self.assertEqual(messages[0].data['block_height'], 4)
        self.assertEqual(messages[1].data['block_height'], 5)


# class TestRandomnessBeaconNode(unittest.TestCase):
#     """Test the RandomnessBeaconNode functionality"""
    
#     def setUp(self):
#         """Set up a test node"""
#         self.initial_difficulty_bits = 8
#         self.node = RandomnessBeaconNode(persistent=False, initial_difficulty_bits=self.initial_difficulty_bits)
#         self.node.start()
    
#     def tearDown(self):
#         """Clean up the test node"""
#         self.node.stop_mining()
#         self.node.close()
    
#     def test_node_mining(self):
#         """Test that the node can mine blocks"""
#         # Start mining
#         self.node.start_mining()
        
#         # Wait for a block to be mined
#         start_time = time.time()
#         max_wait_time = 10  # seconds
        
#         while time.time() - start_time < max_wait_time:
#             if self.node.beacon.get_latest_block().block_height > 0:
#                 break
#             time.sleep(0.1)
        
#         # Stop mining
#         self.node.stop_mining()
        
#         # Check that at least one block was mined
#         self.assertGreater(self.node.beacon.get_latest_block().block_height, 0)
        
#         # Check that the node's address got a reward
#         address = self.node.beacon.coinbase_address
#         self.assertGreaterEqual(self.node.beacon.ledger.get(address, 0), 1)
        
#         # Check the difficulty was preserved in the block header
#         latest_block = self.node.beacon.get_latest_block()
#         self.assertEqual(latest_block.difficulty_bits, self.initial_difficulty_bits)
    
#     def test_node_get_randomness(self):
#         """Test getting randomness from the node"""
#         # Mine a block
#         self.node.start_mining()
        
#         # Wait for a block to be mined
#         start_time = time.time()
#         max_wait_time = 10  # seconds
        
#         while time.time() - start_time < max_wait_time:
#             if self.node.beacon.get_latest_block().block_height > 0:
#                 break
#             time.sleep(0.1)
        
#         # Stop mining
#         self.node.stop_mining()
        
#         # Get randomness from the node
#         randomness = self.node.get_randomness()
        
#         # Check that the randomness is a valid hash
#         self.assertEqual(len(randomness), 64)
        
#         # Get binary randomness
#         binary_randomness = self.node.get_binary_randomness(length=128)
        
#         # Check that the binary randomness is the correct length and format
#         self.assertEqual(len(binary_randomness), 128)
#         self.assertTrue(all(bit in "01" for bit in binary_randomness))
    
#     def test_get_difficulty(self):
#         """Test getting the current difficulty from the node"""
#         # Check initial difficulty
#         self.assertEqual(self.node.get_difficulty(), self.initial_difficulty_bits)
        
#         # Mine a block
#         self.node.start_mining()
        
#         # Wait for a block to be mined
#         start_time = time.time()
#         max_wait_time = 10  # seconds
        
#         while time.time() - start_time < max_wait_time:
#             if self.node.beacon.get_latest_block().block_height > 0:
#                 break
#             time.sleep(0.1)
        
#         # Stop mining
#         self.node.stop_mining()
        
#         # Get the difficulty again
#         current_difficulty = self.node.get_difficulty()
        
#         # For the first block, difficulty should match the initial difficulty
#         self.assertEqual(current_difficulty, self.initial_difficulty_bits)


# class TestRandomnessBeaconNetwork(unittest.TestCase):
#     """Test a network of RandomnessBeaconNodes"""
    
#     def setUp(self):
#         """Set up a network of nodes"""
#         self.num_nodes = 3
#         self.initial_difficulty_bits = 8
#         self.nodes = create_randomness_beacon_network(self.num_nodes, initial_difficulty_bits=self.initial_difficulty_bits)
    
#     def tearDown(self):
#         """Clean up the network"""
#         close_network(self.nodes)
    
#     def test_network_sync(self):
#         """Test that blocks propagate through the network"""
#         # Mine a block on the first node
#         first_node = self.nodes[0]
#         block = first_node.beacon.mine_block()
#         message = SharedMessage(data=block.to_dict())
#         first_node.broadcast(message.to_json())
        
#         # First node should process it
#         first_node.handle_message(
#             message.to_json(),
#             hashlib.sha256(message.to_json().encode()).hexdigest(),
#             ("127.0.0.1", 0)
#         )
        
#         # Wait for propagation
#         start_time = time.time()
#         max_wait_time = 10  # seconds
        
#         while time.time() - start_time < max_wait_time:
#             # Check if all nodes have the block
#             all_have_block = True
#             for node in self.nodes:
#                 if node.beacon.get_latest_block().block_height == 0:
#                     all_have_block = False
#                     break
            
#             if all_have_block:
#                 break
            
#             time.sleep(0.1)
        
#         # Check that all nodes have the block
#         for node in self.nodes:
#             self.assertEqual(node.beacon.get_latest_block().block_height, 1)
#             self.assertEqual(node.beacon.get_latest_block().block_hash, block.block_hash)
#             # Check that difficulty was properly synced
#             self.assertEqual(node.beacon.get_latest_block().difficulty_bits, block.difficulty_bits)
    
#     def test_mining_in_network(self):
#         """Test mining in the network"""
#         # Start mining on all nodes
#         start_mining_in_network(self.nodes)
        
#         # Wait for some blocks to be mined
#         time.sleep(5)
        
#         # Stop mining
#         stop_mining_in_network(self.nodes)
        
#         # Check that some blocks were mined
#         max_height = max(node.beacon.get_latest_block().block_height for node in self.nodes)
#         self.assertGreater(max_height, 0)
        
#         # Give some time for final sync
#         time.sleep(2)
        
#         # Check that all nodes have synchronized to the same chain height
#         heights = [node.beacon.get_latest_block().block_height for node in self.nodes]
#         self.assertEqual(len(set(heights)), 1, f"Nodes have different heights: {heights}")
        
#         # Check that the ledgers are consistent
#         ledgers = []
#         for node in self.nodes:
#             ledger = {}
#             for address, count in node.beacon.ledger.items():
#                 ledger[address] = count
#             ledgers.append(ledger)
        
#         # All ledgers should be the same
#         for i in range(1, len(ledgers)):
#             self.assertEqual(ledgers[0], ledgers[i], f"Ledger {i} is different from ledger 0")
            
#         # Check that difficulty bits are consistent across all nodes
#         difficulty_bits = [node.beacon.get_latest_block().difficulty_bits for node in self.nodes]
#         self.assertEqual(len(set(difficulty_bits)), 1, f"Nodes have different difficulty bits: {difficulty_bits}")
    
#     def test_randomness_distribution(self):
#         """Test the distribution of randomness in the beacon"""
#         # Start mining on all nodes
#         start_mining_in_network(self.nodes)
        
#         # Wait for at least 10 blocks to be mined
#         start_time = time.time()
#         max_wait_time = 30  # seconds
        
#         while time.time() - start_time < max_wait_time:
#             max_height = max(node.beacon.get_latest_block().block_height for node in self.nodes)
#             if max_height >= 10:
#                 break
#             time.sleep(0.5)
        
#         # Stop mining
#         stop_mining_in_network(self.nodes)
        
#         # Give some time for final sync
#         time.sleep(2)
        
#         # Get the highest node
#         heights = [node.beacon.get_latest_block().block_height for node in self.nodes]
#         max_height = max(heights)
#         max_height_node = self.nodes[heights.index(max_height)]
        
#         # Collect binary randomness from each block
#         binary_strings = []
#         for height in range(1, max_height + 1):
#             binary = max_height_node.get_binary_randomness(block_height=height)
#             binary_strings.append(binary)
        
#         # Analyze the distribution of 0s and 1s
#         zeros_percentages = []
#         for binary in binary_strings:
#             zeros = binary.count('0')
#             zeros_percentages.append(zeros / len(binary) * 100)
        
#         # Check that the distribution is roughly even (between 40% and 60% zeros)
#         for i, percentage in enumerate(zeros_percentages):
#             self.assertTrue(
#                 40 <= percentage <= 60,
#                 f"Block {i+1} has {percentage:.2f}% zeros, which is outside the expected range"
#             )
        
#         # Check the standard deviation of the percentages
#         std_dev = statistics.stdev(zeros_percentages)
#         self.assertLess(std_dev, 10, f"Standard deviation of {std_dev:.2f} is too high")
        
#         # Calculate the mean percentage
#         mean_percentage = statistics.mean(zeros_percentages)
#         self.assertTrue(
#             45 <= mean_percentage <= 55,
#             f"Mean percentage of zeros ({mean_percentage:.2f}%) is outside the expected range"
#         )
    
#     def test_difficulty_adjustments_across_nodes(self):
#         """Test that difficulty adjustments are properly propagated across nodes"""
#         # Mine blocks with controlled timestamps to force difficulty changes
#         node = self.nodes[0]
        
#         # Mine the first block (normal difficulty)
#         genesis_block = node.beacon.get_latest_block()
        
#         # Create a block with a timestamp that will increase difficulty
#         block1 = Block(
#             coinbase_address=node.beacon.coinbase_address,
#             prev_block_hash=genesis_block.block_hash,
#             block_height=1,
#             timestamp=genesis_block.timestamp + 5000,  # 5 seconds (less than target)
#             nonce=1,
#             difficulty_bits=genesis_block.difficulty_bits + 1  # Difficulty increases
#         )
        
#         # Properly mine it
#         challenge = block1.coinbase_address + block1.prev_block_hash
#         pow_primitive = ProofOfWorkPrimitive(difficulty_bits=block1.difficulty_bits)
#         nonce = pow_primitive.create_proof(challenge)
        
#         block1 = Block(
#             coinbase_address=block1.coinbase_address,
#             prev_block_hash=block1.prev_block_hash,
#             block_height=block1.block_height,
#             timestamp=block1.timestamp,
#             nonce=nonce,
#             difficulty_bits=block1.difficulty_bits
#         )
        
#         # Broadcast the block
#         message1 = SharedMessage(data=block1.to_dict())
#         node.broadcast(message1.to_json())
#         node.handle_message(
#             message1.to_json(),
#             hashlib.sha256(message1.to_json().encode()).hexdigest(),
#             ("127.0.0.1", 0)
#         )
        
#         # Wait for propagation
#         time.sleep(2)
        
#         # Check that all nodes have the block with increased difficulty
#         for test_node in self.nodes:
#             latest_block = test_node.beacon.get_latest_block()
#             self.assertEqual(latest_block.block_height, 1)
#             self.assertEqual(latest_block.difficulty_bits, genesis_block.difficulty_bits + 1)
        
#         # Create another block with a timestamp that will decrease difficulty
#         block2 = Block(
#             coinbase_address=node.beacon.coinbase_address,
#             prev_block_hash=block1.block_hash,
#             block_height=2,
#             timestamp=block1.timestamp + 15000,  # 15 seconds (more than target)
#             nonce=1,
#             difficulty_bits=block1.difficulty_bits - 1  # Difficulty decreases
#         )
        
#         # Properly mine it
#         challenge = block2.coinbase_address + block2.prev_block_hash
#         pow_primitive = ProofOfWorkPrimitive(difficulty_bits=block2.difficulty_bits)
#         nonce = pow_primitive.create_proof(challenge)
        
#         block2 = Block(
#             coinbase_address=block2.coinbase_address,
#             prev_block_hash=block2.prev_block_hash,
#             block_height=block2.block_height,
#             timestamp=block2.timestamp,
#             nonce=nonce,
#             difficulty_bits=block2.difficulty_bits
#         )
        
#         # Broadcast the block
#         message2 = SharedMessage(data=block2.to_dict())
#         node.broadcast(message2.to_json())
#         node.handle_message(
#             message2.to_json(),
#             hashlib.sha256(message2.to_json().encode()).hexdigest(),
#             ("127.0.0.1", 0)
#         )
        
#         # Wait for propagation
#         time.sleep(2)
        
#         # Check that all nodes have the block with decreased difficulty
#         for test_node in self.nodes:
#             latest_block = test_node.beacon.get_latest_block()
#             self.assertEqual(latest_block.block_height, 2)
#             self.assertEqual(latest_block.difficulty_bits, block1.difficulty_bits - 1)
    
    # def test_collision_resolution(self):
    #     """Test resolving collisions in the network"""
    #     # Mine two competing blocks with different nodes
    #     node1 = self.nodes[0]
    #     node2 = self.nodes[1]
        
    #     # Stop automatic mining
    #     stop_mining_in_network(self.nodes)
        
    #     # Mine a block with node1
    #     block1 = node1.beacon.mine_block()
    #     message1 = SharedMessage(data=block1.to_dict())
    #     node1.broadcast(message1.to_json())
    #     node1.handle_message(
    #         message1.to_json(),
    #         hashlib.sha256(message1.to_json().encode()).hexdigest(),
    #         ("127.0.0.1", 0)
    #     )
        
    #     # Wait for propagation
    #     time.sleep(2)
        
    #     # Get the genesis block which is the previous block for our competing block
    #     genesis_block = node2.beacon.chain[0]
        
    #     # Try different nonces until we get a block with a hash smaller than block1's hash
    #     timestamp = time.time() * 1000
        
    #     # Keep trying different nonces until we find one that produces a block hash
    #     # that is lexicographically smaller than block1's hash
    #     nonce = 1
    #     while True:
    #         competing_block = Block(
    #             coinbase_address=node2.beacon.coinbase_address,
    #             prev_block_hash=genesis_block.block_hash,
    #             block_height=1,
    #             timestamp=timestamp,
    #             nonce=nonce,
    #             difficulty_bits=block1.difficulty_bits  # Same difficulty as block1
    #         )
            
    #         # If we found a block with a smaller hash, break
    #         if competing_block.block_hash < block1.block_hash:
    #             break
                
    #         # Try next nonce
    #         nonce += 1
            
    #         # Avoid infinite loop in test
    #         if nonce > 100:
    #             self.skipTest("Couldn't find a competing block with smaller hash in reasonable time")
        
    #     # Broadcast the competing block
    #     message2 = SharedMessage(data=competing_block.to_dict())
    #     node2.broadcast(message2.to_json())
    #     node2.handle_message(
    #         message2.to_json(),
    #         hashlib.sha256(message2.to_json().encode()).hexdigest(),
    #         ("127.0.0.1", 0)
    #     )
        
    #     # Wait for propagation
    #     time.sleep(2)
        
    #     # Check that all nodes have accepted the competing block
    #     for node in self.nodes:
    #         latest_block = node.beacon.get_latest_block()
    #         self.assertEqual(latest_block.block_height, 1)
    #         self.assertEqual(latest_block.block_hash, competing_block.block_hash)
        
    #     # Check that node2 got the reward instead of node1
    #     for node in self.nodes:
    #         self.assertEqual(node.beacon.ledger.get(node1.beacon.coinbase_address, 0), 0)
    #         self.assertEqual(node.beacon.ledger.get(node2.beacon.coinbase_address, 0), 1)
    
#     def test_invalid_difficulty_rejection(self):
#         """Test that blocks with invalid difficulty adjustments are rejected"""
#         # Stop mining to control the test
#         stop_mining_in_network(self.nodes)
        
#         node = self.nodes[0]
#         genesis_block = node.beacon.get_latest_block()
        
#         # Create a block with a timestamp that should increase difficulty, but with incorrect difficulty
#         incorrect_block = Block(
#             coinbase_address=node.beacon.coinbase_address,
#             prev_block_hash=genesis_block.block_hash,
#             block_height=1,
#             timestamp=genesis_block.timestamp + 5000,  # 5 seconds (less than target)
#             nonce=1,
#             difficulty_bits=genesis_block.difficulty_bits - 1  # WRONG: difficulty should increase but we're decreasing
#         )
        
#         # Mine it to get a valid PoW
#         challenge = incorrect_block.coinbase_address + incorrect_block.prev_block_hash
#         pow_primitive = ProofOfWorkPrimitive(difficulty_bits=incorrect_block.difficulty_bits)
#         nonce = pow_primitive.create_proof(challenge)
        
#         incorrect_block = Block(
#             coinbase_address=incorrect_block.coinbase_address,
#             prev_block_hash=incorrect_block.prev_block_hash,
#             block_height=incorrect_block.block_height,
#             timestamp=incorrect_block.timestamp,
#             nonce=nonce,
#             difficulty_bits=incorrect_block.difficulty_bits
#         )
        
#         # Try to broadcast the block with incorrect difficulty
#         message = SharedMessage(data=incorrect_block.to_dict())
        
#         # Verify that the block is rejected
#         self.assertFalse(node.beacon.is_valid(message))
        
#         # Try to add it directly and verify it doesn't get added
#         initial_chain_length = len(node.beacon.chain)
#         node.beacon.add_message(message)
        
#         # Chain length should remain the same
#         self.assertEqual(len(node.beacon.chain), initial_chain_length)


if __name__ == "__main__":
    unittest.main()