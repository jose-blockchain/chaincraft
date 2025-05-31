import unittest
import cProfile
import pstats
import io
import time
import random
import json
import os

import os
import sys

# Try to import from installed package first, fall back to direct imports
try:
    from chaincraft.shared_message import SharedMessage
    from chaincraft.shared_object import SharedObject
except ImportError:
    # Add parent directory to path as fallback
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from chaincraft.shared_message import SharedMessage
    from chaincraft.shared_object import SharedObject
from contextlib import contextmanager
from pstats import SortKey

from chaincraft import ChaincraftNode


class SimpleSharedObject(SharedObject):
    """A simple shared object for testing purposes."""

    def __init__(self):
        self.messages = []
        self.digests = {}

    def is_valid(self, message):
        # Simple validation - accept all messages
        return True

    def add_message(self, message):
        self.messages.append(message)

    def is_merkelized(self):
        # This object doesn't support merkelization
        return False

    def add_digest(self, digest, messages):
        # Simple implementation - just store the digest and messages
        self.digests[digest] = messages
        return True

    def has_digest(self, digest):
        # Check if we have this digest
        return digest in self.digests

    def get_latest_digest(self):
        # Return the latest digest or None if no digests
        if not self.digests:
            return None
        return list(self.digests.keys())[-1]

    def get_messages_since_digest(self, digest):
        # Return messages since the given digest
        # For simplicity, just return all messages
        return self.messages

    def gossip_object(self):
        # This object doesn't support gossip
        return False

    def is_valid_digest(self, digest):
        # Simple validation - accept all digests
        return True


@contextmanager
def profile(name):
    """Context manager for profiling a code block."""
    profiler = cProfile.Profile()
    profiler.enable()
    try:
        yield
    finally:
        profiler.disable()
        s = io.StringIO()
        ps = pstats.Stats(profiler, stream=s).sort_stats(SortKey.CUMULATIVE)
        ps.print_stats(20)  # Print top 20 functions by cumulative time
        print(f"\n--- Profiling results for {name} ---")
        print(s.getvalue())

        # Also save to a file
        with open(f"profile_{name}.txt", "w") as f:
            ps = pstats.Stats(profiler, stream=f).sort_stats(SortKey.CUMULATIVE)
            ps.print_stats(50)  # Save top 50 functions to file


class TestChaincraftProfiling(unittest.TestCase):
    def setUp(self):
        # Clean up any profile files from previous runs
        for file in os.listdir("."):
            if file.startswith("profile_") and file.endswith(".txt"):
                os.remove(file)

        # Create a test node
        self.node = ChaincraftNode(
            max_peers=5,
            persistent=False,
            debug=False,
            port=random.randint(10000, 11000),
        )
        self.node.start()

        # Add a simple shared object
        self.shared_object = SimpleSharedObject()
        self.node.add_shared_object(self.shared_object)

    def tearDown(self):
        self.node.close()

    def test_message_creation_and_broadcast(self):
        """Profile message creation and broadcasting."""
        num_messages = 10000  # Adjusted to 10000 (10x previous, 100x original)

        with profile("message_creation_and_broadcast"):
            for i in range(num_messages):
                data = {
                    "message_type": "TEST",
                    "content": f"Test message {i}",
                    "timestamp": time.time(),
                }
                self.node.create_shared_message(data)
                # Small delay to avoid overwhelming the network
                time.sleep(0.0001)  # Adjusted delay to keep test duration reasonable

        # Verify messages were processed
        self.assertGreaterEqual(len(self.shared_object.messages), 1)

    def test_peer_connection(self):
        """Profile peer connection and discovery."""
        num_peers = 5
        nodes = []

        try:
            # Create additional nodes
            with profile("peer_connection"):
                for i in range(num_peers):
                    node = ChaincraftNode(
                        max_peers=5,
                        persistent=False,
                        debug=False,
                        port=random.randint(12000, 13000),
                    )
                    node.start()
                    nodes.append(node)

                    # Connect to our main node
                    self.node.connect_to_peer(node.host, node.port)

                    # Small delay to allow connection to establish
                    time.sleep(0.1)

            # Verify connections
            self.assertGreaterEqual(len(self.node.peers), 1)

        finally:
            # Clean up
            for node in nodes:
                node.close()

    def test_message_handling(self):
        """Profile message handling and processing."""
        num_messages = 10000  # Adjusted to 10000 (10x previous, 100x original)

        # Create a second node to send messages to our main node
        second_node = ChaincraftNode(
            max_peers=5,
            persistent=False,
            debug=False,
            port=random.randint(14000, 15000),
        )
        second_node.start()

        try:
            # Connect nodes
            self.node.connect_to_peer(second_node.host, second_node.port)
            second_node.connect_to_peer(self.node.host, self.node.port)

            # Wait for connection to establish
            time.sleep(0.5)

            # Send messages from second node to main node
            with profile("message_handling"):
                for i in range(num_messages):
                    data = {
                        "message_type": "TEST",
                        "content": f"Test message {i}",
                        "timestamp": time.time(),
                    }
                    second_node.create_shared_message(data)
                    # Small delay to avoid overwhelming the network
                    time.sleep(
                        0.0002
                    )  # Adjusted delay to keep test duration reasonable

                # Allow time for messages to be processed
                time.sleep(2)

            # Verify messages were received and processed
            self.assertGreaterEqual(len(self.shared_object.messages), 1)

        finally:
            second_node.close()

    def test_db_operations(self):
        """Profile database operations with persistent storage."""
        # Create a persistent node for this test
        db_node = ChaincraftNode(
            max_peers=5,
            persistent=True,
            reset_db=True,  # Start with a fresh DB
            debug=False,
            port=random.randint(16000, 17000),
        )
        db_node.start()

        try:
            with profile("db_operations"):
                # Create and store messages
                for i in range(5000):  # Adjusted to 5000 (10x previous, 100x original)
                    data = {
                        "message_type": "TEST",
                        "content": f"Test message {i}",
                        "timestamp": time.time(),
                    }
                    db_node.create_shared_message(data)

                # Force sync to ensure data is written
                db_node.db_sync()

                # Read back some data
                for key in list(db_node.db.keys())[:20]:
                    if (
                        key != db_node.PEERS.encode()
                        and key != db_node.BANNED_PEERS.encode()
                    ):
                        _ = db_node.db[key]

        finally:
            db_node.close()

    def test_complex_network_simulation(self):
        """Simulate a more complex network with multiple nodes and messages."""
        num_nodes = 5
        messages_per_node = 2000  # Adjusted to 2000 (10x previous, 100x original)
        nodes = []

        try:
            # Create a network of nodes
            for i in range(num_nodes):
                node = ChaincraftNode(
                    max_peers=num_nodes,
                    persistent=False,
                    debug=False,
                    port=random.randint(18000, 19000),
                )
                node.add_shared_object(SimpleSharedObject())
                node.start()
                nodes.append(node)

            # Connect all nodes in a mesh network
            for i in range(num_nodes):
                for j in range(num_nodes):
                    if i != j:
                        nodes[i].connect_to_peer(nodes[j].host, nodes[j].port)

            # Allow connections to establish
            time.sleep(1)

            # Profile the network activity
            with profile("complex_network_simulation"):
                # Each node sends messages
                for i in range(num_nodes):
                    for j in range(messages_per_node):
                        data = {
                            "message_type": "TEST",
                            "sender": f"node_{i}",
                            "content": f"Message {j} from node {i}",
                            "timestamp": time.time(),
                        }
                        nodes[i].create_shared_message(data)
                        time.sleep(0.001)  # Small delay

                # Allow time for messages to propagate
                time.sleep(3)

            # Verify message propagation
            for node in nodes:
                shared_obj = node.shared_objects[0]
                self.assertGreaterEqual(len(shared_obj.messages), 1)

        finally:
            # Clean up
            for node in nodes:
                node.close()


if __name__ == "__main__":
    unittest.main()
