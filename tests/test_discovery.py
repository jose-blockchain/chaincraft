# test_discovery.py
import unittest
import time, random
from chaincraft import ChaincraftNode

random.seed(7331)

def wait_for_propagation(nodes, expected_count, timeout=5):
    start_time = time.time()
    while time.time() - start_time < timeout:
        counts = [len(node.peers) for node in nodes]
        print(f"Current peer counts: {counts}")
        if all(count == expected_count for count in counts):
            return True
        time.sleep(0.5)
    return False

class TestPeerDiscovery(unittest.TestCase):
    def setUp(self):
        self.nodes = []

    def tearDown(self):
        for node in self.nodes:
            node.close()

    def create_node(self, **kwargs):
        node = ChaincraftNode(**kwargs)
        self.nodes.append(node)
        return node

    def test_single_node_no_peers(self):
        node1 = self.create_node(persistent=False)
        node1.start()
        time.sleep(1)
        self.assertEqual(len(node1.peers), 0)

    def test_two_nodes_one_connection(self):
        node1 = self.create_node(persistent=False)
        node2 = self.create_node(persistent=False)
        node1.start()
        node2.start()
        node2.connect_to_peer(node1.host, node1.port, discovery=True)
        self.assertTrue(wait_for_propagation([node1, node2], 1))
        self.assertEqual(len(node1.peers), 1)
        self.assertEqual(len(node2.peers), 1)

    def test_three_nodes_discovery(self):
        node1 = self.create_node(persistent=False)
        node2 = self.create_node(persistent=False)
        node3 = self.create_node(persistent=False)
        node1.start()
        node2.start()
        node3.start()
        node2.connect_to_peer(node1.host, node1.port, discovery=True)
        self.assertTrue(wait_for_propagation([node1, node2], 1))
        self.assertEqual(len(node1.peers), 1)
        self.assertEqual(len(node2.peers), 1)
        node3.connect_to_peer(node2.host, node2.port, discovery=True)
        self.assertTrue(wait_for_propagation([node1, node2, node3], 2))
        self.assertEqual(len(node1.peers), 2)
        self.assertEqual(len(node2.peers), 2)
        self.assertEqual(len(node3.peers), 2)

    def test_four_nodes_discovery(self):
        node1 = self.create_node(persistent=False)
        node2 = self.create_node(persistent=False)
        node3 = self.create_node(persistent=False)
        node4 = self.create_node(persistent=False)
        node1.start()
        node2.start()
        node3.start()
        node4.start()
        node2.connect_to_peer(node1.host, node1.port)
        node3.connect_to_peer(node2.host, node2.port, discovery=True)
        node4.connect_to_peer(node1.host, node1.port, discovery=True)
        self.assertTrue(wait_for_propagation([node1, node2, node3, node4], 3))
        self.assertEqual(len(node1.peers), 3)
        self.assertEqual(len(node2.peers), 3)
        self.assertEqual(len(node3.peers), 3)
        self.assertEqual(len(node4.peers), 3)

    def test_max_peers_replacement(self):
        node1 = self.create_node(persistent=False, max_peers=2)
        node2 = self.create_node(persistent=False)
        node3 = self.create_node(persistent=False)
        node4 = self.create_node(persistent=False)
        node1.start()
        node2.start()
        node3.start()
        node4.start()
        node1.connect_to_peer(node2.host, node2.port)
        node1.connect_to_peer(node3.host, node3.port)
        self.assertTrue(wait_for_propagation([node1], 2))
        self.assertEqual(len(node1.peers), 2)
        node1.connect_to_peer(node4.host, node4.port)
        self.assertTrue(wait_for_propagation([node1], 2))
        self.assertEqual(len(node1.peers), 2)
        self.assertIn((node4.host, node4.port), node1.peers)
        self.assertNotIn((node3.host, node3.port), node1.peers)

    def test_massive_network_discovery(self):
        num_nodes = 100
        max_peers = 5
        nodes = [self.create_node(persistent=False, max_peers=max_peers) for _ in range(num_nodes)]
        
        # Start all nodes
        for node in nodes:
            node.start()
        
        # Connect nodes in a chain to ensure initial connectivity
        for i in range(1, num_nodes):
            nodes[i].connect_to_peer(nodes[i-1].host, nodes[i-1].port, discovery=True)
        
        # Allow time for peer discovery to propagate
        time.sleep(10)
        
        # Check that all nodes have close to max_peers connections
        peer_counts = [len(node.peers) for node in nodes]
        average_peers = sum(peer_counts) / num_nodes
        
        print(f"Average peer count: {average_peers}")
        print(f"Peer count distribution: {peer_counts}")
        
        # Assert that the average peer count is close to max_peers
        self.assertGreaterEqual(average_peers, max_peers * 0.8)
        self.assertLessEqual(average_peers, max_peers * 1.2)
        
        # Assert that no node has more than max_peers
        self.assertTrue(all(count <= max_peers for count in peer_counts))
        
        # Assert that most nodes have at least 1 peer
        nodes_with_peers = sum(1 for count in peer_counts if count > 0)
        self.assertGreaterEqual(nodes_with_peers / num_nodes, 0.95)

if __name__ == '__main__':
    unittest.main()