import unittest
import json
import os
import time

import os
import sys

# Try to import from installed package first, fall back to direct imports
try:
    from chaincraft.shared_message import SharedMessage
    from chaincraft.index_helper import IndexHelper
except ImportError:
    # Add parent directory to path as fallback
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from chaincraft.shared_message import SharedMessage
    from chaincraft.index_helper import IndexHelper
from typing import Dict, Any, List

from chaincraft import ChaincraftNode


class TestIndexing(unittest.TestCase):
    def setUp(self):
        # Create a node with persistent and indexed flags set to True
        self.node = ChaincraftNode(
            max_peers=5,
            reset_db=True,
            persistent=True,
            indexed=True,
            debug=False,  # Turn off debug mode to remove debugging messages
        )
        self.node.start()

    def tearDown(self):
        self.node.close()
        # Clean up SQLite database files
        if os.path.exists(f"node_{self.node.port}_index.db"):
            os.remove(f"node_{self.node.port}_index.db")

    def test_set_indexed_fields(self):
        """Test setting indexed fields for a message type."""
        # Set indexed fields for a User message type
        self.node.set_indexed_fields("User", ["username", "email"])

        # Verify the fields were set correctly
        self.assertIn("User", self.node.indexed_fields)
        self.assertEqual(set(self.node.indexed_fields["User"]), {"username", "email"})

    def test_index_message(self):
        """Test indexing a message with indexed fields."""
        # Set indexed fields for a User message type
        self.node.set_indexed_fields("User", ["username", "email"])

        # Create a User message
        user_data = {
            "message_type": "User",
            "username": "testuser",
            "email": "test@example.com",
            "age": 25,  # This field should not be indexed
        }

        # Create and broadcast the message
        message_hash, shared_message = self.node.create_shared_message(user_data)

        # Wait a bit for indexing to complete
        time.sleep(0.1)

        # Search for the message by username
        results, count = self.node.search_messages("User", "username", "testuser")
        self.assertEqual(count, 1)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "testuser")

        # Search for the message by email
        results, count = self.node.search_messages("User", "email", "test@example.com")
        self.assertEqual(count, 1)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["email"], "test@example.com")

        # Search for a non-indexed field (should not find anything)
        results, count = self.node.search_messages("User", "age", "25")
        self.assertEqual(count, 0)
        self.assertEqual(len(results), 0)

    def test_pagination(self):
        """Test pagination of search results."""
        # Set indexed fields for a User message type
        self.node.set_indexed_fields("User", ["username"])

        # Create multiple users with the same username
        for i in range(15):
            user_data = {"message_type": "User", "username": "testuser", "id": i}
            self.node.create_shared_message(user_data)

        # Wait a bit for indexing to complete
        time.sleep(0.1)

        # Test first page (10 results)
        results, count = self.node.search_messages(
            "User", "username", "testuser", page=1, page_size=10
        )
        self.assertEqual(count, 15)
        self.assertEqual(len(results), 10)

        # Test second page (5 results)
        results, count = self.node.search_messages(
            "User", "username", "testuser", page=2, page_size=10
        )
        self.assertEqual(count, 15)
        self.assertEqual(len(results), 5)

    def test_multiple_message_types(self):
        """Test indexing multiple message types with different fields."""
        # Set indexed fields for different message types
        self.node.set_indexed_fields("User", ["username", "email"])
        self.node.set_indexed_fields("Post", ["title", "author"])

        # Create a User message
        user_data = {
            "message_type": "User",
            "username": "testuser",
            "email": "test@example.com",
        }
        self.node.create_shared_message(user_data)

        # Create a Post message
        post_data = {
            "message_type": "Post",
            "title": "Test Post",
            "author": "testuser",
            "content": "This is a test post",
        }
        self.node.create_shared_message(post_data)

        # Wait a bit for indexing to complete
        time.sleep(0.1)

        # Search for User by username
        results, count = self.node.search_messages("User", "username", "testuser")
        self.assertEqual(count, 1)
        self.assertEqual(results[0]["message_type"], "User")

        # Search for Post by title
        results, count = self.node.search_messages("Post", "title", "Test Post")
        self.assertEqual(count, 1)
        self.assertEqual(results[0]["message_type"], "Post")

        # Search for Post by author (should find the post)
        results, count = self.node.search_messages("Post", "author", "testuser")
        self.assertEqual(count, 1)
        self.assertEqual(results[0]["message_type"], "Post")

    def test_non_indexed_node(self):
        """Test that indexing is disabled when indexed flag is False."""
        # Create a node with indexed=False
        node = ChaincraftNode(
            max_peers=5,
            reset_db=True,
            persistent=True,
            indexed=False,
            debug=False,  # Turn off debug mode
        )
        node.start()

        # Set indexed fields (should not work)
        node.set_indexed_fields("User", ["username", "email"])
        self.assertEqual(len(node.indexed_fields), 0)

        # Create a message
        user_data = {
            "message_type": "User",
            "username": "testuser",
            "email": "test@example.com",
        }
        node.create_shared_message(user_data)

        # Search should return no results
        results, count = node.search_messages("User", "username", "testuser")
        self.assertEqual(count, 0)
        self.assertEqual(len(results), 0)

        node.close()

    def test_non_persistent_node(self):
        """Test that indexing is disabled when persistent flag is False."""
        # Create a node with persistent=False
        node = ChaincraftNode(
            max_peers=5,
            reset_db=True,
            persistent=False,
            indexed=True,
            debug=False,  # Turn off debug mode
        )
        node.start()

        # Set indexed fields (should not work)
        node.set_indexed_fields("User", ["username", "email"])
        self.assertEqual(len(node.indexed_fields), 0)

        # Create a message
        user_data = {
            "message_type": "User",
            "username": "testuser",
            "email": "test@example.com",
        }
        node.create_shared_message(user_data)

        # Search should return no results
        results, count = node.search_messages("User", "username", "testuser")
        self.assertEqual(count, 0)
        self.assertEqual(len(results), 0)

        node.close()


if __name__ == "__main__":
    unittest.main()
