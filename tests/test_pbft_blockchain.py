import unittest
import time
from examples.pbft_blockchain import PBFTBlockchain, Block, PRE_PREPARE, PREPARE, COMMIT, VIEW_CHANGE, NEW_VIEW
from shared_message import SharedMessage
from crypto_primitives.sign import ECDSASignaturePrimitive
import json
from typing import List, Dict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

class MockNode:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.received_messages: List[Dict] = []
        
    def broadcast_message(self, message: Dict) -> None:
        self.received_messages.append(message)

class TestPBFTBlockchain(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.node_count = 4
        self.nodes = [MockNode(f"node_{i}") for i in range(self.node_count)]
        self.blockchains = [
            PBFTBlockchain(node.node_id, self.node_count, node.broadcast_message)
            for node in self.nodes
        ]
        
        # Generate keys for test nodes
        self.node_keys = []
        for i in range(4):
            ecdsa = ECDSASignaturePrimitive()
            ecdsa.generate_key()
            self.node_keys.append(ecdsa)
            
        # Set up the blockchain node with the first key
        self.blockchains[0].ecdsa = self.node_keys[0]
        self.blockchains[0].public_key = self.node_keys[0].get_public_pem()
        
        # Add all public keys to the set
        self.blockchains[0].public_keys = {
            node.get_public_pem() for node in self.node_keys
        }

    def test_block_creation(self):
        """Test block creation and validation."""
        transactions = ["tx1", "tx2"]
        block = Block(
            index=1,
            previous_hash="0" * 64,
            timestamp=time.time(),
            transactions=transactions,
            view_number=0,
            proposer="node_0"
        )
        
        # Test block hash calculation
        self.assertEqual(len(block.calculate_hash()), 64)
        
        # Test block to/from dict conversion
        block_dict = block.to_dict()
        restored_block = Block.from_dict(block_dict)
        self.assertEqual(block.index, restored_block.index)
        self.assertEqual(block.transactions, restored_block.transactions)

    def test_pre_prepare_validation(self):
        """Test pre-prepare message validation."""
        # Create a valid pre-prepare message
        block = Block(
            index=1,
            previous_hash=self.blockchains[0].chain[-1].calculate_hash(),
            timestamp=time.time(),
            transactions=[{"from": "alice", "to": "bob", "amount": 100}],
            view_number=0,
            proposer=self.node_keys[0].get_public_pem(),
            signatures={}
        )
        
        message = {
            "message_type": PRE_PREPARE,
            "view_number": 0,
            "block": block.to_dict(),
            "public_key": self.node_keys[0].get_public_pem(),
            "timestamp": time.time()
        }
        
        # Sign the message
        temp_dict = dict(message)
        payload_str = json.dumps(temp_dict, sort_keys=True)
        sig_bytes = self.node_keys[0].sign(payload_str.encode("utf-8"))
        message["signature"] = sig_bytes.hex()
        
        shared_msg = SharedMessage(data=message)
        self.assertTrue(self.blockchains[0].is_valid(shared_msg))
        
        # Test invalid view number
        message["view_number"] = 1
        temp_dict = dict(message)
        del temp_dict["signature"]
        payload_str = json.dumps(temp_dict, sort_keys=True)
        sig_bytes = self.node_keys[0].sign(payload_str.encode("utf-8"))
        message["signature"] = sig_bytes.hex()
        shared_msg = SharedMessage(data=message)
        self.assertFalse(self.blockchains[0].is_valid(shared_msg))

    def test_prepare_validation(self):
        """Test prepare message validation."""
        # First create a pre-prepare message
        block = Block(
            index=1,
            previous_hash=self.blockchains[0].chain[-1].calculate_hash(),
            timestamp=time.time(),
            transactions=[{"from": "alice", "to": "bob", "amount": 100}],
            view_number=0,
            proposer=self.node_keys[0].get_public_pem(),
            signatures={}
        )
        
        pre_prepare_msg = {
            "message_type": PRE_PREPARE,
            "view_number": 0,
            "block": block.to_dict(),
            "public_key": self.node_keys[0].get_public_pem(),
            "timestamp": time.time()
        }
        
        # Sign the pre-prepare message
        temp_dict = dict(pre_prepare_msg)
        payload_str = json.dumps(temp_dict, sort_keys=True)
        sig_bytes = self.node_keys[0].sign(payload_str.encode("utf-8"))
        pre_prepare_msg["signature"] = sig_bytes.hex()
        
        self.blockchains[0].add_message(SharedMessage(data=pre_prepare_msg))
        
        # Now test prepare message
        prepare_msg = {
            "message_type": PREPARE,
            "view_number": 0,
            "block_hash": block.calculate_hash(),
            "public_key": self.node_keys[1].get_public_pem(),
            "timestamp": time.time()
        }
        
        # Sign the prepare message with node2's key
        temp_dict = dict(prepare_msg)
        payload_str = json.dumps(temp_dict, sort_keys=True)
        sig_bytes = self.node_keys[1].sign(payload_str.encode("utf-8"))
        prepare_msg["signature"] = sig_bytes.hex()
        
        shared_msg = SharedMessage(data=prepare_msg)
        self.assertTrue(self.blockchains[0].is_valid(shared_msg))

    def test_commit_validation(self):
        """Test commit message validation."""
        # First create necessary pre-prepare and prepare messages
        block = Block(
            index=1,
            previous_hash=self.blockchains[0].chain[-1].calculate_hash(),
            timestamp=time.time(),
            transactions=[{"from": "alice", "to": "bob", "amount": 100}],
            view_number=0,
            proposer=self.node_keys[0].get_public_pem(),
            signatures={}
        )
        
        pre_prepare_msg = {
            "message_type": PRE_PREPARE,
            "view_number": 0,
            "block": block.to_dict(),
            "public_key": self.node_keys[0].get_public_pem(),
            "timestamp": time.time()
        }
        
        # Sign the pre-prepare message
        temp_dict = dict(pre_prepare_msg)
        payload_str = json.dumps(temp_dict, sort_keys=True)
        sig_bytes = self.node_keys[0].sign(payload_str.encode("utf-8"))
        pre_prepare_msg["signature"] = sig_bytes.hex()
        
        self.blockchains[0].add_message(SharedMessage(data=pre_prepare_msg))
        
        # Add enough prepare messages
        for i in range(3):  # Need 3 prepare messages (2f + 1)
            prepare_msg = {
                "message_type": PREPARE,
                "view_number": 0,
                "block_hash": block.calculate_hash(),
                "public_key": self.node_keys[i+1].get_public_pem(),
                "timestamp": time.time()
            }
            
            # Sign with the corresponding node's key
            temp_dict = dict(prepare_msg)
            payload_str = json.dumps(temp_dict, sort_keys=True)
            sig_bytes = self.node_keys[i+1].sign(payload_str.encode("utf-8"))
            prepare_msg["signature"] = sig_bytes.hex()
            
            self.blockchains[0].add_message(SharedMessage(data=prepare_msg))
        
        # Now test commit message
        commit_msg = {
            "message_type": COMMIT,
            "view_number": 0,
            "block_hash": block.calculate_hash(),
            "public_key": self.node_keys[1].get_public_pem(),
            "timestamp": time.time()
        }
        
        # Sign with node2's key
        temp_dict = dict(commit_msg)
        payload_str = json.dumps(temp_dict, sort_keys=True)
        sig_bytes = self.node_keys[1].sign(payload_str.encode("utf-8"))
        commit_msg["signature"] = sig_bytes.hex()
        
        shared_msg = SharedMessage(data=commit_msg)
        self.assertTrue(self.blockchains[0].is_valid(shared_msg))

    def test_view_change_validation(self):
        """Test view change message validation."""
        view_change_msg = {
            "message_type": VIEW_CHANGE,
            "view_number": 1,
            "public_key": self.node_keys[1].get_public_pem(),
            "timestamp": time.time(),
            "proof": {
                "last_block": self.blockchains[0].chain[-1].calculate_hash(),
                "view": 0
            }
        }
        
        # Sign with node2's key
        temp_dict = dict(view_change_msg)
        payload_str = json.dumps(temp_dict, sort_keys=True)
        sig_bytes = self.node_keys[1].sign(payload_str.encode("utf-8"))
        view_change_msg["signature"] = sig_bytes.hex()
        
        shared_msg = SharedMessage(data=view_change_msg)
        self.assertTrue(self.blockchains[0].is_valid(shared_msg))
        
        # Test invalid view number
        view_change_msg["view_number"] = 0
        temp_dict = dict(view_change_msg)
        del temp_dict["signature"]
        payload_str = json.dumps(temp_dict, sort_keys=True)
        sig_bytes = self.node_keys[1].sign(payload_str.encode("utf-8"))
        view_change_msg["signature"] = sig_bytes.hex()
        shared_msg = SharedMessage(data=view_change_msg)
        self.assertFalse(self.blockchains[0].is_valid(shared_msg))

    def test_new_view_validation(self):
        """Test new view message validation."""
        # First add enough view change messages
        for i in range(3):  # Need 3 view change messages (2f + 1)
            view_change_msg = {
                "message_type": VIEW_CHANGE,
                "view_number": 1,
                "public_key": self.node_keys[i+1].get_public_pem(),
                "timestamp": time.time(),
                "proof": {
                    "last_block": self.blockchains[0].chain[-1].calculate_hash(),
                    "view": 0
                }
            }
            
            # Sign with the corresponding node's key
            temp_dict = dict(view_change_msg)
            payload_str = json.dumps(temp_dict, sort_keys=True)
            sig_bytes = self.node_keys[i+1].sign(payload_str.encode("utf-8"))
            view_change_msg["signature"] = sig_bytes.hex()
            
            self.blockchains[0].add_message(SharedMessage(data=view_change_msg))
        
        # Now test new view message
        new_view_msg = {
            "message_type": NEW_VIEW,
            "view_number": 1,
            "public_key": self.node_keys[0].get_public_pem(),
            "timestamp": time.time(),
            "view_changes": [node.get_public_pem() for node in self.node_keys[1:4]]
        }
        
        # Sign with our node's key
        temp_dict = dict(new_view_msg)
        payload_str = json.dumps(temp_dict, sort_keys=True)
        sig_bytes = self.node_keys[0].sign(payload_str.encode("utf-8"))
        new_view_msg["signature"] = sig_bytes.hex()
        
        shared_msg = SharedMessage(data=new_view_msg)
        self.assertTrue(self.blockchains[0].is_valid(shared_msg))

    def test_block_proposal(self):
        """Test block proposal by leader."""
        # Set up the blockchain with multiple nodes
        blockchain = self.blockchains[0]
        blockchain.public_keys = {
            self.node_keys[0].get_public_pem(),
            self.node_keys[1].get_public_pem()
        }
        blockchain.public_key = self.node_keys[0].get_public_pem()
        
        # Reset the pre_prepare_messages for view 0
        blockchain.pre_prepare_messages = {0: {}}
        
        transactions = [{"from": "alice", "to": "bob", "amount": 100}]
        blockchain.propose_block(transactions)
        
        # Verify pre-prepare message was created
        self.assertEqual(len(blockchain.pre_prepare_messages[0]), 1)
        
        # Test proposal by non-leader
        blockchain = self.blockchains[1]
        blockchain.public_keys = {
            self.node_keys[0].get_public_pem(),
            self.node_keys[1].get_public_pem()
        }
        blockchain.public_key = self.node_keys[1].get_public_pem()
        blockchain.pre_prepare_messages = {0: {}}
        
        blockchain.propose_block(transactions)
        self.assertEqual(len(blockchain.pre_prepare_messages[0]), 0)  # Should not increase

    def test_timeout_handling(self):
        """Test timeout handling and view change initiation."""
        # Set last block time to trigger timeout
        self.blockchains[0].last_block_time = time.time() - 6  # BLOCK_TIMEOUT is 5
        
        # If we're the leader, should initiate view change
        if self.blockchains[0]._is_leader():
            self.blockchains[0].check_timeout()
            self.assertEqual(len(self.blockchains[0].view_changes.get(1, {})), 1)
        else:
            self.blockchains[0].check_timeout()
            self.assertEqual(len(self.blockchains[0].view_changes), 0)

    def test_message_validation(self):
        """Test message validation logic."""
        blockchain = self.blockchains[0]
        
        # Test invalid message type
        invalid_message = {
            "message_type": "INVALID_TYPE",
            "view_number": 0,
            "sequence_number": 1,
            "public_key": self.node_keys[0].get_public_pem(),
            "timestamp": time.time()
        }
        # Sign the message
        temp_dict = dict(invalid_message)
        payload_str = json.dumps(temp_dict, sort_keys=True)
        sig_bytes = self.node_keys[0].sign(payload_str.encode("utf-8"))
        invalid_message["signature"] = sig_bytes.hex()
        
        self.assertFalse(blockchain._validate_message(invalid_message))
        
        # Test valid pre-prepare message
        valid_message = {
            "message_type": PRE_PREPARE,
            "view_number": 0,
            "sequence_number": 1,
            "public_key": self.node_keys[0].get_public_pem(),
            "timestamp": time.time(),
            "block": Block(
                index=1,
                previous_hash="0" * 64,
                timestamp=time.time(),
                transactions=["tx1"],
                view_number=0,
                proposer="node_0"
            ).to_dict()
        }
        # Sign the message
        temp_dict = dict(valid_message)
        payload_str = json.dumps(temp_dict, sort_keys=True)
        sig_bytes = self.node_keys[0].sign(payload_str.encode("utf-8"))
        valid_message["signature"] = sig_bytes.hex()
        
        self.assertTrue(blockchain._validate_message(valid_message))

    def test_leader_selection(self):
        """Test leader selection logic."""
        # Set up the blockchain with multiple nodes
        blockchain = self.blockchains[0]
        blockchain.public_keys = {
            self.node_keys[0].get_public_pem(),
            self.node_keys[1].get_public_pem()
        }
        blockchain.public_key = self.node_keys[0].get_public_pem()
        
        # In view 0, node_0 should be leader
        self.assertTrue(blockchain._is_leader())
        
        # Set up the blockchain with the second node
        blockchain = self.blockchains[1]
        blockchain.public_keys = {
            self.node_keys[0].get_public_pem(),
            self.node_keys[1].get_public_pem()
        }
        blockchain.public_key = self.node_keys[1].get_public_pem()
        
        # In view 0, node_1 should not be leader
        self.assertFalse(blockchain._is_leader())
        
        # Change view to 1, node_1 should be leader
        blockchain.current_view = 1
        self.assertTrue(blockchain._is_leader())

    def test_consensus(self):
        """Test the consensus process."""
        # Set up the blockchain with multiple nodes
        blockchain = self.blockchains[0]
        blockchain.public_keys = {
            self.node_keys[0].get_public_pem(),
            self.node_keys[1].get_public_pem()
        }
        blockchain.public_key = self.node_keys[0].get_public_pem()
        
        # Reset message collections
        blockchain.pre_prepare_messages = {0: {}}
        blockchain.prepare_messages = {0: {}}
        blockchain.commit_messages = {0: {}}
        
        # Create a block
        transactions = [{"from": "alice", "to": "bob", "amount": 100}]
        block = Block(0, "0" * 64, int(time.time()), transactions, 0, blockchain.public_key)
        
        # Leader proposes block
        blockchain.propose_block(transactions)
        
        # Verify pre-prepare message was created
        self.assertEqual(len(blockchain.pre_prepare_messages[0]), 1)
        
        # Create prepare message
        prepare_msg = {
            "type": "prepare",
            "view": 0,
            "block_hash": block.calculate_hash(),
            "sender": blockchain.public_key
        }
        
        # Sign the prepare message
        msg_str = json.dumps(prepare_msg, sort_keys=True)
        prepare_msg["signature"] = blockchain.private_key.sign(
            msg_str.encode(),
            ec.ECDSA(hashes.SHA256())
        ).hex()
        
        # Process prepare message
        blockchain.process_message(prepare_msg)
        
        # Verify prepare message was processed
        self.assertEqual(len(blockchain.prepare_messages[0]), 1)
        
        # Create commit message
        commit_msg = {
            "type": "commit",
            "view": 0,
            "block_hash": block.calculate_hash(),
            "sender": blockchain.public_key
        }
        
        # Sign the commit message
        msg_str = json.dumps(commit_msg, sort_keys=True)
        commit_msg["signature"] = blockchain.private_key.sign(
            msg_str.encode(),
            ec.ECDSA(hashes.SHA256())
        ).hex()
        
        # Process commit message
        blockchain.process_message(commit_msg)
        
        # Verify commit message was processed
        self.assertEqual(len(blockchain.commit_messages[0]), 1)
        
        # Verify block was added to chain
        self.assertEqual(len(blockchain.chain), 1)
        self.assertEqual(blockchain.chain[0].transactions, transactions)

if __name__ == '__main__':
    unittest.main() 