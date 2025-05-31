# tests/test_start.py
import unittest
import time
import socket
import dbm.ndbm
from chaincraft import ChaincraftNode


class TestChaincraftNode(unittest.TestCase):
    def setUp(self):
        self.nodes = []

    def tearDown(self):
        for node in self.nodes:
            node.close()

    def create_node(self, **kwargs):
        node = ChaincraftNode(**kwargs)
        self.nodes.append(node)
        return node

    def test_fixed_address_initialization(self):
        node = self.create_node(use_fixed_address=True)
        self.assertEqual(node.host, "localhost")
        self.assertEqual(node.port, 21000)

    def test_random_address_initialization(self):
        node = self.create_node(use_fixed_address=False)
        self.assertEqual(node.host, "127.0.0.1")
        self.assertNotEqual(node.port, 7331)
        self.assertTrue(5000 <= node.port <= 9000)

    def test_start_node(self):
        node = self.create_node(use_fixed_address=False)
        node.start()
        time.sleep(0.1)  # Give some time for the node to start
        self.assertTrue(hasattr(node, "socket"))

    def test_multiple_nodes_different_ports(self):
        node1 = self.create_node()
        node2 = self.create_node()
        self.assertNotEqual(node1.port, node2.port)

    def test_connect_to_peer(self):
        node1 = self.create_node()
        node2 = self.create_node()
        node1.connect_to_peer(node2.host, node2.port)
        self.assertEqual(len(node1.peers), 1)
        self.assertEqual(node1.peers[0], (node2.host, node2.port))

    def test_max_peers(self):
        node = self.create_node(max_peers=1)
        node.connect_to_peer("127.0.0.1", 8000)
        node.connect_to_peer("127.0.0.1", 8001)
        self.assertEqual(len(node.peers), 1)

    def test_create_shared_message(self):
        node = self.create_node(persistent=False)
        message_hash, shared_message = node.create_shared_message("Test data")
        self.assertIn(message_hash, node.db)
        self.assertEqual(shared_message.data, "Test data")

    def test_fixed_address_conflict(self):
        node1 = self.create_node(use_fixed_address=True)
        node1.start()

        # Attempt to create another node with the same fixed address
        with self.assertRaises(OSError):
            node2 = self.create_node(use_fixed_address=True)
            node2.start()

    def test_use_dict_storage(self):
        node = self.create_node(persistent=False)
        self.assertIsInstance(node.db, dict)

    def test_use_dbm_storage(self):
        node = self.create_node(persistent=True, reset_db=True)
        self.assertIsInstance(node.db, dbm.ndbm.open("__test__.db", "c").__class__)

    def test_reset_db(self):
        node = self.create_node(persistent=True, reset_db=True)
        self.assertEqual(len(node.db), 0)

    def test_gossip(self):
        node1 = self.create_node(persistent=False)
        node2 = self.create_node(persistent=False)
        node1.connect_to_peer(node2.host, node2.port)
        node2.connect_to_peer(node1.host, node1.port)

        node1.start()
        node2.start()

        message_hash, _ = node1.create_shared_message("Test gossip")
        time.sleep(6)  # Wait for gossip to propagate

        self.assertIn(message_hash, node2.db)


if __name__ == "__main__":
    unittest.main()
