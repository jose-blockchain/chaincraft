from chaincraft import ChaincraftNode
import random
import time


def create_network(num_nodes, reset_db=False):
    nodes = [ChaincraftNode(reset_db=reset_db) for _ in range(num_nodes)]
    for node in nodes:
        node.start()
    return nodes


def connect_nodes(nodes):
    for i, node in enumerate(nodes):
        for _ in range(2):
            random_node = random.choice(nodes)
            if random_node != node and len(node.peers) < node.max_peers:
                node.connect_to_peer(random_node.host, random_node.port)


def print_network_status(nodes):
    for i, node in enumerate(nodes):
        print(f"Node {i} ({node.host}:{node.port}):")
        print(f"  Peers: {[f'{p[0]}:{p[1]}' for p in node.peers]}")
        print(f"  Shared objects: {len(node.db)}")
    print("\n")


# Create a network of 5 nodes
num_nodes = 5
nodes = create_network(
    num_nodes, reset_db=True
)  # Set reset_db=True to reset the database

# Connect nodes
connect_nodes(nodes)

# Print initial network status
print("Initial network status:")
print_network_status(nodes)

# Create and share objects
for i in range(3):
    random_node = random.choice(nodes)
    message_hash, _ = random_node.create_shared_object(
        f"Hello from node {nodes.index(random_node)}!"
    )
    time.sleep(2)
    print(f"Status after object {i+1} (hash: {message_hash}):")
    print_network_status(nodes)

# Wait for gossip to propagate
time.sleep(10)

# Print final network status
print("Final network status:")
print_network_status(nodes)

# Close all nodes
print("Closing nodes...")
for node in nodes:
    node.close()

# Keep the main thread running
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Nodes stopped")
