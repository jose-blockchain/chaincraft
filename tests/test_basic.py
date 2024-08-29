import unittest
import random
import time
from chaincraft import ChaincraftNode

random.seed(7331)

def create_network(num_nodes, reset_db=False):
    nodes = [ChaincraftNode(reset_db=reset_db) for _ in range(num_nodes)]
    for node in nodes:
        node.start()
    return nodes

def connect_nodes(nodes):
    for i, node in enumerate(nodes):
        for _ in range(3):
            random_node = random.choice(nodes)
            if random_node != node and len(node.peers) < node.max_peers:
                node.connect_to_peer(random_node.host, random_node.port)

def wait_for_propagation(nodes, expected_count, timeout=30):
    start_time = time.time()
    while time.time() - start_time < timeout:
        counts = [len(node.db) for node in nodes]
        print(f"Current object counts: {counts}")
        if all(count == expected_count for count in counts):
            return True
        time.sleep(0.5)
    return False

class TestChaincraftNetwork(unittest.TestCase):
    def setUp(self):
        self.num_nodes = 5
        self.nodes = create_network(self.num_nodes, reset_db=True)
        connect_nodes(self.nodes)
        time.sleep(2)  # Wait for initial connections to establish

    def tearDown(self):
        for node in self.nodes:
            node.close()

    def test_network_creation(self):
        self.assertEqual(len(self.nodes), self.num_nodes)
        for node in self.nodes:
            self.assertTrue(node.is_running)
            self.assertTrue(0 < len(node.peers) <= node.max_peers)

    def test_object_creation_and_propagation(self):
        source_node = random.choice(self.nodes)
        message_hash, _ = source_node.create_shared_object("Test object")

        self.assertTrue(wait_for_propagation(self.nodes, 1))

        for node in self.nodes:
            self.assertIn(message_hash, node.db, f"Object not found in node {node.port}")
            stored_object = node.db[message_hash]
            self.assertIn("Test object", stored_object)

    def test_multiple_object_creation(self):
        for i in range(3):
            random_node = random.choice(self.nodes)
            random_node.create_shared_object(f"Object {i}")
            time.sleep(1)  # Wait a bit between object creations

        self.assertTrue(wait_for_propagation(self.nodes, 3))

        for node in self.nodes:
            self.assertEqual(len(node.db), 3, f"Node {node.port} has incorrect number of objects")

    def test_network_resilience(self):
        # Create initial object
        initial_node = self.nodes[0]
        initial_hash, _ = initial_node.create_shared_object("Initial object")

        self.assertTrue(wait_for_propagation(self.nodes, 1))

        # Simulate node failure
        failed_node = self.nodes.pop()
        failed_node.close()

        # Create new object
        new_node = random.choice(self.nodes)
        new_hash, _ = new_node.create_shared_object("New object")

        self.assertTrue(wait_for_propagation(self.nodes, 2))

        # Restart failed node
        restarted_node = ChaincraftNode(reset_db=False)
        restarted_node.start()
        for node in self.nodes:
            restarted_node.connect_to_peer(node.host, node.port)
            node.connect_to_peer(restarted_node.host, restarted_node.port)
        self.nodes.append(restarted_node)

        # Wait for the restarted node to catch up
        self.assertTrue(wait_for_propagation(self.nodes, 2, timeout=60))

        for node in self.nodes:
            self.assertIn(initial_hash, node.db, f"Initial object not found in node {node.port}")
            self.assertIn(new_hash, node.db, f"New object not found in node {node.port}")

if __name__ == '__main__':
    unittest.main()
