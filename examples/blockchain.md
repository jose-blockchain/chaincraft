# Running a Chaincraft Blockchain Network

This tutorial will guide you through setting up and running a local blockchain network using the Chaincraft framework. We'll create a 5-node network where each node can mine blocks and transfer coins to other nodes.

## Prerequisites

Before getting started, you need to have the following dependencies installed:

```bash
pip install ecdsa
```

The blockchain implementation also requires the Chaincraft framework, which should be in your Python path.

## Network Setup

### Step 1: Create a Python script to initialize the network

Create a file called `run_blockchain_network.py` with the following content:

```python
import time
import threading
import random
from chaincraft import ChaincraftNode
from examples.blockchain import BlockchainNode, generate_wallet

# Configuration
NUM_NODES = 5
BASE_PORT = 21000
DIFFICULTY = 4  # Controls mining difficulty (higher is harder)
MINING_REWARD = 10.0  # Coins awarded for mining a block

# Create nodes
nodes = []
blockchain_nodes = []

def initialize_node(port):
    """Initialize a node with blockchain functionality"""
    print(f"Initializing node on port {port}...")
    node = ChaincraftNode(persistent=False, port=port)
    node.start()
    
    # Add blockchain functionality
    bc_node = BlockchainNode(node, difficulty=DIFFICULTY, reward=MINING_REWARD)
    
    # Give node some initial coins for testing
    genesis_address = "0x0000000000000000000000000000000000000000"
    if port == BASE_PORT:
        # Set up a transaction from genesis for each node
        bc_node.ledger.balances[bc_node.address] = 100.0
    
    return node, bc_node

def connect_nodes(node_list):
    """Connect nodes in a circular manner with each node connecting to two neighbors"""
    for i in range(len(node_list)):
        # Connect to next node
        next_idx = (i + 1) % len(node_list)
        node_list[i].connect_to_peer(
            node_list[next_idx].host, 
            node_list[next_idx].port,
            discovery=True
        )
        
        # Connect to next+1 node
        next_plus_one = (i + 2) % len(node_list)
        node_list[i].connect_to_peer(
            node_list[next_plus_one].host, 
            node_list[next_plus_one].port,
            discovery=True
        )
    
    print("All nodes connected.")

def mining_thread(bc_node, stop_event):
    """Thread function for mining blocks"""
    # Wait for network stabilization and transactions
    time.sleep(10)
    
    while not stop_event.is_set():
        # Try to mine a block
        block_hash = bc_node.mine_block()
        
        if block_hash:
            print(f"Node {bc_node.node.port} mined block: {block_hash[:8]}")
            print(f"Balance: {bc_node.get_balance()}")
            
            # Random sleep to prevent miners competing too frequently
            time.sleep(random.uniform(5, 15))
        else:
            # If no transactions, wait a bit
            time.sleep(5)

def transaction_thread(bc_nodes, stop_event):
    """Thread function for creating random transactions"""
    time.sleep(5)  # Let network stabilize
    
    while not stop_event.is_set():
        try:
            # Select random sender and recipient
            sender_idx = random.randrange(0, len(bc_nodes))
            recipient_idx = random.randrange(0, len(bc_nodes))
            
            # Make sure sender and recipient are different
            while recipient_idx == sender_idx:
                recipient_idx = random.randrange(0, len(bc_nodes))
            
            sender = bc_nodes[sender_idx]
            recipient = bc_nodes[recipient_idx]
            
            # Get sender balance
            balance = sender.get_balance()
            
            # Only create transaction if sender has funds
            if balance > 1.0:
                # Create a transaction with a random amount
                amount = random.uniform(0.1, min(5.0, balance - 0.1))
                fee = 0.01
                
                tx_id = sender.create_transaction(
                    recipient=recipient.address,
                    amount=amount,
                    fee=fee
                )
                
                print(f"Created transaction: {sender.node.port} -> {recipient.node.port}, "