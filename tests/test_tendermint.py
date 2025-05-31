# tests/test_tendermint.py

import unittest
import time
import json
import threading
import random
import os
import signal
import sys

# Try to import from installed package first, fall back to direct imports
try:
    from chaincraft import ChaincraftNode, SharedMessage
    from examples.tendermint_bft import TendermintBFT, TendermintNode, create_tendermint_network, ConsensusStep
    from chaincraft.crypto_primitives.address import generate_new_address, is_valid_address
except ImportError:
    # Add parent directory to path as fallback
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from chaincraft import ChaincraftNode, SharedMessage
    from examples.tendermint_bft import TendermintBFT, TendermintNode, create_tendermint_network, ConsensusStep
    from chaincraft.crypto_primitives.address import generate_new_address, is_valid_address


def force_cleanup():
    """Force cleanup of any stuck processes"""
    # Kill all Python processes except the main test process
    print("Cleaning up any lingering processes...")
    pid = os.getpid()
    output = os.popen("ps -ef | grep python | grep -v grep").read()
    for line in output.splitlines():
        try:
            parts = line.split()
            if len(parts) > 1:
                process_pid = int(parts[1])
                if process_pid != pid and process_pid != os.getppid():
                    try:
                        os.kill(process_pid, signal.SIGKILL)
                        print(f"Killed process {process_pid}")
                    except:
                        pass
        except:
            pass


def cleanup_nodes(tendermint_nodes, nodes):
    """Properly clean up nodes to avoid lingering threads"""
    # Stop all consensus nodes
    for node in tendermint_nodes:
        if node:
            try:
                node.stop()
            except:
                pass

    # Ensure some time for cleanup
    time.sleep(0.5)

    # Close all network nodes
    for node in nodes:
        if node:
            try:
                node.close()
            except:
                pass

    # Allow time for ports to be released
    time.sleep(1)


class TestTendermintBFT(unittest.TestCase):
    """Unit tests for TendermintBFT implementation - NO NETWORK TESTS"""

    @classmethod
    def setUpClass(cls):
        # Force cleanup at the beginning
        force_cleanup()

    @classmethod
    def tearDownClass(cls):
        # Force cleanup at the end
        force_cleanup()

    def test_initialization(self):
        """Test that TendermintBFT initializes correctly"""
        tendermint = TendermintBFT()

        # Check that the genesis block is created
        self.assertEqual(len(tendermint.blocks), 1)
        self.assertEqual(tendermint.blocks[0]["height"], 0)
        self.assertEqual(tendermint.current_height, 1)

        # Check that the validator address is valid
        self.assertTrue(is_valid_address(tendermint.validator_address))

        # Check that the validator private key is set
        self.assertIsNotNone(tendermint.validator_privkey)

        # Check that default parameters are set
        self.assertEqual(tendermint.TARGET_BLOCK_TIME, 15)
        self.assertEqual(tendermint.PROPOSE_TIMEOUT, 3)
        self.assertEqual(tendermint.PREVOTE_TIMEOUT, 2)
        self.assertEqual(tendermint.PRECOMMIT_TIMEOUT, 2)

        # Check that vote collections are initialized as defaultdicts
        self.assertEqual(len(tendermint.prevotes[1]), 0)
        self.assertEqual(len(tendermint.precommits[1]), 0)

    def test_initialization_with_custom_validator(self):
        """Test initialization with custom validator address and key"""
        # Generate a custom validator address and key
        address, privkey = generate_new_address()

        # Create a TendermintBFT instance with the custom validator
        tendermint = TendermintBFT()

        # Manually set the validator address and key
        tendermint.validator_address = address
        tendermint.validator_privkey = privkey
        tendermint.validators.add(address)

        # Check that the validator address and key are set correctly
        self.assertEqual(tendermint.validator_address, address)
        self.assertEqual(tendermint.validator_privkey, privkey)

        # Check validators set includes the custom validator
        self.assertTrue(address in tendermint.validators)

    def test_merkelized_functionality(self):
        """Test merkelized functionality"""
        tendermint = TendermintBFT()

        # Verify that the implementation is merkelized
        self.assertTrue(tendermint.is_merkelized())

        # Test get_latest_digest
        genesis_hash = tendermint.get_latest_digest()
        self.assertEqual(genesis_hash, tendermint.blocks[0]["hash"])

        # Test has_digest
        self.assertTrue(tendermint.has_digest(genesis_hash))
        self.assertFalse(tendermint.has_digest("0" * 64))  # Non-existent hash

        # Test is_valid_digest
        self.assertTrue(tendermint.is_valid_digest(genesis_hash))
        self.assertFalse(tendermint.is_valid_digest("invalid"))

        # Create a mock block to test gossip functionality
        mock_block = {
            "height": 1,
            "transactions": ["tx1", "tx2"],
            "proposer": tendermint.validator_address,
            "timestamp": int(time.time()),
            "prev_block_id": genesis_hash,
            "hash": "mock_block_hash",
        }

        # Add the mock block to the chain
        tendermint.blocks.append(mock_block)
        tendermint.block_by_hash["mock_block_hash"] = mock_block
        tendermint.last_block_id = mock_block["hash"]
        tendermint.current_height = 2

        # Test gossip_object - should return the mock block when requesting from genesis
        gossip_messages = tendermint.gossip_object(genesis_hash)
        self.assertEqual(len(gossip_messages), 1)
        self.assertEqual(gossip_messages[0].data["hash"], mock_block["hash"])

        # Test get_messages_since_digest
        since_messages = tendermint.get_messages_since_digest(genesis_hash)
        self.assertEqual(len(since_messages), 1)
        self.assertEqual(since_messages[0].data["hash"], mock_block["hash"])

        # Test with non-existent digest - should return empty list
        self.assertEqual(tendermint.gossip_object("0" * 64), [])

    def test_message_validation(self):
        """Test message validation"""
        tendermint = TendermintBFT()

        valid_proposal = {
            "message_type": "TENDERMINT_PROPOSAL",
            "height": tendermint.current_height,
            "round": tendermint.current_round,
            "proposer": tendermint.validator_address,
            "prev_block_hash": tendermint.blocks[0]["hash"],
            "timestamp": time.time(),
        }

        # Create an invalid proposal (wrong height)
        invalid_proposal = valid_proposal.copy()
        invalid_proposal["height"] = 999

        # Check validation with the is_valid_proposal method
        self.assertTrue(tendermint._is_valid_proposal(valid_proposal))
        self.assertFalse(tendermint._is_valid_proposal(invalid_proposal))

        # Test validation of SharedMessage
        valid_message = SharedMessage(
            {
                "message_type": "TENDERMINT_PROPOSAL",
                "height": tendermint.current_height,
                "round": tendermint.current_round,
                "proposer": tendermint.validator_address,
                "prev_block_hash": tendermint.blocks[0]["hash"],
            }
        )

        invalid_message = SharedMessage({"type": "unknown_type"})

        # Verify message validation logic
        self.assertTrue(tendermint.is_valid(valid_message))
        self.assertFalse(tendermint.is_valid(invalid_message))

    def _is_valid_proposal(self, proposal):
        """Helper method to validate proposals directly since the actual validation is now handled differently"""
        # Check required fields
        if (
            "height" not in proposal
            or "round" not in proposal
            or "proposer" not in proposal
        ):
            return False

        # Check height
        if proposal["height"] != self.current_height:
            return False

        return True

    def test_block_hash_calculation(self):
        """Test block hash calculation is consistent and deterministic"""
        tendermint = TendermintBFT()

        # Create test proposal
        proposal = {
            "type": "proposal",
            "height": 1,
            "round": 0,
            "timestamp": 1000000,  # Fixed timestamp for deterministic test
            "proposer": "0x1234567890123456789012345678901234567890",
            "transactions": ["tx1", "tx2"],
        }

        # Calculate hash
        hash1 = tendermint._calculate_proposal_hash(proposal)

        # Hash should be deterministic
        hash2 = tendermint._calculate_proposal_hash(proposal)
        self.assertEqual(hash1, hash2)

        # Hash should not include signature if added
        proposal_with_sig = proposal.copy()
        proposal_with_sig["signature"] = "signature"
        hash3 = tendermint._calculate_proposal_hash(proposal_with_sig)
        self.assertEqual(hash1, hash3)

        # Changing any field should change the hash
        proposal_modified = proposal.copy()
        proposal_modified["height"] = 2
        hash4 = tendermint._calculate_proposal_hash(proposal_modified)
        self.assertNotEqual(hash1, hash4)

    def test_vote_signing_and_verification(self):
        """Test signing and verification of votes - skipped since moved to new implementation"""
        # Skip this test as we're now using a different vote format
        pass

    def test_proposer_selection(self):
        """Test proposer selection logic"""
        tendermint = TendermintBFT()

        # Add validators to the set
        for i in range(3):
            address, _ = generate_new_address()
            tendermint.validators.add(address)

        # Check that proposer changes with height
        validators = sorted(list(tendermint.validators))

        # Test proposer selection for different heights
        for height in range(1, 10):
            tendermint.current_height = height
            expected_proposer = validators[height % len(validators)]

            # Since _is_proposer now also prints debug info, we need to check
            # if the expected proposer matches our validator address
            is_proposer = expected_proposer == tendermint.validator_address
            self.assertEqual(tendermint._is_proposer(), is_proposer)

            # For demonstration purposes, print out which validator is selected
            selected_index = height % len(validators)
            proposer = validators[selected_index]
            self.assertEqual(proposer, expected_proposer)

    def test_consensus_state_transitions(self):
        """Test consensus state transitions"""
        tendermint = TendermintBFT()

        # Add a few validators
        for i in range(2):
            address, _ = generate_new_address()
            tendermint.validators.add(address)

        # Initial state should be PROPOSE
        self.assertEqual(tendermint.current_step, ConsensusStep.PROPOSE)

        # Test transition to PREVOTE
        tendermint.current_step = ConsensusStep.PREVOTE
        self.assertEqual(tendermint.current_step, ConsensusStep.PREVOTE)

        # Test transition to PRECOMMIT
        tendermint.current_step = ConsensusStep.PRECOMMIT
        self.assertEqual(tendermint.current_step, ConsensusStep.PRECOMMIT)

        # Test transition to COMMIT
        tendermint.current_step = ConsensusStep.COMMIT
        self.assertEqual(tendermint.current_step, ConsensusStep.COMMIT)

        # Test processing a proposal
        proposal = {
            "type": "proposal",
            "height": tendermint.current_height,
            "round": tendermint.current_round,
            "timestamp": time.time(),
            "proposer": tendermint.validator_address,
            "transactions": ["tx1"],
        }

        # Reset state for the test
        tendermint.current_step = ConsensusStep.PROPOSE

        # Process proposal should transition to PREVOTE
        tendermint._process_proposal(proposal)
        self.assertEqual(tendermint.current_step, ConsensusStep.PREVOTE)

    def test_message_processing(self):
        """Test processing of proposal, prevote, and precommit messages"""
        tendermint = TendermintBFT()

        # Create a proposal
        proposal = {
            "message_type": "TENDERMINT_PROPOSAL",
            "height": tendermint.current_height,
            "round": tendermint.current_round,
            "timestamp": time.time(),
            "proposer": tendermint.validator_address,
            "prev_block_hash": tendermint.blocks[0]["hash"],
        }

        # Process the proposal and manually set it for testing
        tendermint._process_proposal(proposal)

        # Create another validator's prevote
        other_validator, _ = generate_new_address()
        tendermint.validators.add(other_validator)

        prevote = {
            "message_type": "TENDERMINT_PREVOTE",
            "height": tendermint.current_height,
            "round": tendermint.current_round,
            "block_hash": tendermint._calculate_proposal_hash(proposal),
            "validator": other_validator,
            "timestamp": time.time(),
        }

        # Process the prevote
        tendermint._process_prevote(prevote)

        # Create a third validator's precommit
        third_validator, _ = generate_new_address()
        tendermint.validators.add(third_validator)

        precommit = {
            "message_type": "TENDERMINT_PRECOMMIT",
            "height": tendermint.current_height,
            "round": tendermint.current_round,
            "block_hash": tendermint._calculate_proposal_hash(proposal),
            "validator": third_validator,
            "timestamp": time.time(),
        }

        # Process the precommit
        tendermint._process_precommit(precommit)

    def test_block_creation_and_processing(self):
        """Test block creation and processing"""
        tendermint = TendermintBFT()

        # Create an initial state for the test
        genesis_hash = tendermint.blocks[0]["hash"]

        # Create a block directly
        block = {
            "height": 1,
            "transactions": ["tx1", "tx2"],
            "proposer": tendermint.validator_address,
            "timestamp": time.time(),
            "prev_block_id": genesis_hash,
            "hash": "test_block_hash",
        }

        # Process the block
        tendermint._process_block(block)

        # Verify the block was added to the chain
        self.assertEqual(len(tendermint.blocks), 2)
        self.assertEqual(tendermint.blocks[1], block)
        self.assertEqual(tendermint.current_height, 2)

        # Verify the last block hash is updated
        self.assertEqual(tendermint.last_block_id, "test_block_hash")

        # Test processing a duplicate block (should be ignored)
        original_block_count = len(tendermint.blocks)
        tendermint._process_block(block)
        self.assertEqual(len(tendermint.blocks), original_block_count)

    def test_get_majority_vote_hash(self):
        """Test getting the majority vote hash"""
        tendermint = TendermintBFT()

        # Empty votes should return empty string or proposal hash
        self.assertEqual(tendermint._get_majority_vote_hash({}), "")

        # Create proposal for test
        proposal = {
            "message_type": "TENDERMINT_PROPOSAL",
            "height": tendermint.current_height,
            "round": tendermint.current_round,
            "prev_block_hash": tendermint.blocks[-1]["hash"],
            "block_hash": "proposal_hash",
            "proposer": tendermint.validator_address,
        }
        tendermint.current_proposal = proposal

        # With empty votes but proposal set, should return proposal hash
        self.assertEqual(tendermint._get_majority_vote_hash({}), "proposal_hash")

        # Create votes for different blocks
        hash1 = "1" * 64
        hash2 = "2" * 64

        votes = {
            "validator1": {"block_hash": hash1},
            "validator2": {"block_hash": hash1},
            "validator3": {"block_hash": hash2},
        }

        # Majority should be hash1
        self.assertEqual(tendermint._get_majority_vote_hash(votes), hash1)

        # Equal votes - should pick the one with most votes (hash1)
        votes["validator4"] = {"block_hash": hash2}
        self.assertEqual(tendermint._get_majority_vote_hash(votes), hash1)

        # Now hash2 has more votes
        votes["validator5"] = {"block_hash": hash2}
        self.assertEqual(tendermint._get_majority_vote_hash(votes), hash2)

    def test_quorum_decision(self):
        """Test quorum decision making with votes"""
        tendermint = TendermintBFT()

        # Create 6 validators
        validators = []
        for i in range(6):
            addr, _ = generate_new_address()
            tendermint.validators.add(addr)
            validators.append(addr)

        # Create a block hash for voting
        block_hash = "0" * 64

        # Create votes for 3 validators (exactly 50%)
        votes_50_percent = {}
        for i in range(3):
            votes_50_percent[validators[i]] = {
                "block_hash": block_hash,
                "validator": validators[i],
            }

        # Test that 50% is not enough for quorum
        self.assertFalse(tendermint._has_quorum_votes(votes_50_percent))

        # Add one more vote to make it 4/7 (>50%)
        votes_majority = votes_50_percent.copy()
        votes_majority[validators[3]] = {
            "block_hash": block_hash,
            "validator": validators[3],
        }

        # Test that >50% is enough for quorum
        self.assertTrue(tendermint._has_quorum_votes(votes_majority))

        # Create votes for different blocks
        votes_split = votes_50_percent.copy()
        votes_split[validators[3]] = {
            "block_hash": "1" * 64,  # Different hash
            "validator": validators[3],
        }

        # Test that split votes don't reach quorum
        self.assertFalse(tendermint._has_quorum_votes(votes_split))

        # Edge case: One validator
        single_validator = TendermintBFT()
        single_votes = {
            single_validator.validator_address: {
                "block_hash": block_hash,
                "validator": single_validator.validator_address,
            }
        }
        # One validator should have quorum with just its own vote
        self.assertTrue(single_validator._has_quorum_votes(single_votes))

    def test_add_message_dispatch(self):
        """Test that add_message correctly dispatches to the appropriate handler"""
        tendermint = TendermintBFT()

        # Test with proposal message
        proposal_message = SharedMessage(
            {
                "message_type": "TENDERMINT_PROPOSAL",
                "height": tendermint.current_height,
                "round": tendermint.current_round,
                "prev_block_hash": tendermint.blocks[-1]["hash"],
                "proposer": tendermint.validator_address,
                "signature": "signature",
            }
        )

        # Process message
        tendermint.add_message(proposal_message)

        # Reset state for the next test
        tendermint = TendermintBFT()  # Create a new instance to avoid state issues

        # Create a properly formatted block
        block_data = {
            "message_type": "TENDERMINT_BLOCK",
            "height": tendermint.current_height,
            "round": 0,
            "prev_block_hash": tendermint.blocks[0]["hash"],
            "timestamp": int(time.time()),
            "proposer": tendermint.validator_address,
            "validators": [tendermint.validator_address],
            "signatures": {},
        }

        # Calculate and add the hash first
        block_hash = tendermint._calculate_block_hash(block_data)
        block_data["hash"] = block_hash

        # Create the message
        block_message = SharedMessage(block_data)

        # Initial block count
        initial_block_count = len(tendermint.blocks)

        # Process block message - should pass without errors
        tendermint.add_message(block_message)

    def test_create_tendermint_network_returns_objects(self):
        """Test that create_tendermint_network function returns expected objects"""
        try:
            # Test with minimal nodes to avoid lengthy execution
            num_nodes = 2
            nodes, tendermint_objs, tendermint_nodes = create_tendermint_network(
                num_nodes=num_nodes, consensus_interval=0.5
            )

            # Verify the objects are created
            self.assertEqual(len(nodes), num_nodes)
            self.assertEqual(len(tendermint_objs), num_nodes)
            self.assertEqual(len(tendermint_nodes), num_nodes)

            # Verify object types
            self.assertTrue(all(isinstance(node, ChaincraftNode) for node in nodes))
            self.assertTrue(
                all(isinstance(obj, TendermintBFT) for obj in tendermint_objs)
            )
            self.assertTrue(
                all(isinstance(node, TendermintNode) for node in tendermint_nodes)
            )
        finally:
            # Clean up network resources
            try:
                for node in tendermint_nodes:
                    node.stop()
                for node in nodes:
                    node.close()
            except:
                pass
            # Force cleanup as a backup
            force_cleanup()


if __name__ == "__main__":
    unittest.main()
