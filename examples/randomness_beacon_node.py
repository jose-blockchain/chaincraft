import hashlib
import time
import threading
from typing import List, Dict, Optional, Tuple, Any, Callable

from shared_message import SharedMessage
from chaincraft import ChaincraftNode
from examples.randomness_beacon import RandomnessBeacon, Block, generate_eth_address

# Define the BlockMessage message_type
block_message_type = {
    "message_type": "BlockMessage",
    "mandatory_fields": {
        "coinbase_address": str,
        "prev_block_hash": str,
        "block_height": int,
        "timestamp": float,
        "nonce": int,
        "difficulty_bits": int
    },
    "optional_fields": {
        "block_hash": str
    }
}

class RandomnessBeaconNode(ChaincraftNode):
    """
    A node in the randomness beacon network.
    """
    
    def __init__(
        self,
        coinbase_address: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize a randomness beacon node.
        
        Args:
            coinbase_address: The address of this node. If None, a random address will be generated.
            **kwargs: Additional arguments to pass to the ChaincraftNode constructor.
        """
        super().__init__(**kwargs)
        
        # Register the BlockMessage message type
        self.accepted_message_types = [block_message_type]
        
        # Create a randomness beacon shared object
        self.beacon = RandomnessBeacon(coinbase_address=coinbase_address)
        
        # Add the beacon as a shared object
        self.add_shared_object(self.beacon)
        
        # Mining thread
        self.mining_thread = None
        self.is_mining = False
        
        # Add a mining interruption event
        self.mining_interrupt = threading.Event()
        
        # Track the latest block height being mined
        self.mining_block_height = 0
    
    def start_mining(self) -> None:
        """Start the mining thread"""
        if not self.mining_thread:
            self.is_mining = True
            self.mining_interrupt.clear()
            self.mining_thread = threading.Thread(target=self._mine_blocks, daemon=True)
            self.mining_thread.start()
    
    def stop_mining(self) -> None:
        """Stop the mining thread"""
        self.is_mining = False
        self.mining_interrupt.set()  # Signal the mining thread to interrupt
        if self.mining_thread:
            self.mining_thread.join(timeout=1)
            self.mining_thread = None
    
    def handle_message(self, message_json: str, message_hash: str, peer_address: Tuple[str, int]) -> None:
        """
        Handle a message from a peer.
        Override to add interruption of mining when a valid block is received.
        
        Args:
            message_json: The JSON string of the message.
            message_hash: The hash of the message.
            peer_address: The address of the peer that sent the message.
        """
        # Parse the message
        try:
            # Parse the message
            shared_message = SharedMessage.from_json(message_json)
            
            # Check if this is potentially a block message
            if shared_message.data is not None and isinstance(shared_message.data, dict):
                # Check if this is a BlockMessage type
                if shared_message.data.get("message_type") == "BlockMessage":
                    # Access the fields directly from the data dictionary inside the SharedMessage
                    block_data = shared_message.data
                    if 'block_height' in block_data:
                        current_height = self.beacon.get_latest_block().block_height
                        incoming_height = block_data['block_height']
                        
                        # If the incoming block is for a height we're currently mining
                        # or for a future height, interrupt mining
                        if incoming_height >= self.mining_block_height:
                            print(f"Received block for height {incoming_height}, interrupting mining at height {self.mining_block_height}")
                            self.mining_interrupt.set()
            
            # Process the message normally after checking
            super().handle_message(message_json, message_hash, peer_address)
            
            # After processing, reset interrupt flag and restart mining if needed
            if self.is_mining and self.mining_interrupt.is_set():
                self.mining_interrupt.clear()
                
        except Exception as e:
            print(f"Error handling message: {e}")
    
    def _mine_blocks(self) -> None:
        """Mine blocks continuously"""
        print(f"Starting mining with address {self.beacon.coinbase_address}")
        while self.is_mining and self.is_running:
            try:
                # Update the block height we're mining for
                self.mining_block_height = self.beacon.get_latest_block().block_height + 1
                
                # Create an interrupt callback
                def should_interrupt():
                    return self.mining_interrupt.is_set()
                
                # Mine a new block with interrupt support
                new_block = self.beacon.mine_block(interrupt_callback=should_interrupt)
                
                # If mining was interrupted, skip this iteration
                if new_block is None:
                    continue
                
                # Create a message with the block (adding message_type)
                block_data = new_block.to_dict()
                block_data["message_type"] = "BlockMessage"
                block_data["block_hash"] = new_block.block_hash
                block_message = SharedMessage(data=block_data)
                
                # Send the block to all peers
                self.broadcast(block_message.to_json())
                
                # Also add it locally
                self.handle_message(
                    block_message.to_json(),
                    hashlib.sha256(block_message.to_json().encode()).hexdigest(),
                    ("127.0.0.1", 0)
                )
                
                print(f"Mined block {new_block.block_height} with hash {new_block.block_hash[:8]}")
                
                # Sleep a little to prevent flooding the network
                time.sleep(0.1)
            except Exception as e:
                print(f"Error mining block: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(1)
    
    def get_randomness(self, block_height: Optional[int] = None) -> str:
        """
        Get the randomness for a specific block height.
        
        Args:
            block_height: The block height to get the randomness for.
            
        Returns:
            str: The randomness value (a hex string).
        """
        return self.beacon.get_randomness(block_height)
    
    def get_binary_randomness(self, block_height: Optional[int] = None, length: int = 256) -> str:
        """
        Get a binary string of randomness from a block.
        
        Args:
            block_height: The block height to get the randomness for.
            length: The length of the binary string to return (default: 256 bits).
            
        Returns:
            str: A binary string of random bits.
        """
        return self.beacon.get_binary_randomness(block_height, length)

# Additional utility functions for running a randomness beacon network

def create_randomness_beacon_network(num_nodes: int) -> List[RandomnessBeaconNode]:
    """
    Create a network of randomness beacon nodes.
    
    Args:
        num_nodes: The number of nodes to create.
        
    Returns:
        List[RandomnessBeaconNode]: The list of nodes in the network.
    """
    nodes = []
    for _ in range(num_nodes):
        node = RandomnessBeaconNode(
            persistent=False,
            debug=True
        )
        node.start()
        nodes.append(node)
    
    # Connect the nodes in a ring
    for i in range(num_nodes):
        node1 = nodes[i]
        node2 = nodes[(i+1) % num_nodes]
        node1.connect_to_peer(node2.host, node2.port)
        node2.connect_to_peer(node1.host, node1.port)
    
    return nodes


def start_mining_in_network(nodes: List[RandomnessBeaconNode]) -> None:
    """
    Start mining in all nodes in the network.
    
    Args:
        nodes: The list of nodes in the network.
    """
    for node in nodes:
        node.start_mining()


def stop_mining_in_network(nodes: List[RandomnessBeaconNode]) -> None:
    """
    Stop mining in all nodes in the network.
    
    Args:
        nodes: The list of nodes in the network.
    """
    for node in nodes:
        node.stop_mining()


def close_network(nodes: List[RandomnessBeaconNode]) -> None:
    """
    Close all nodes in the network.
    
    Args:
        nodes: The list of nodes in the network.
    """
    stop_mining_in_network(nodes)
    for node in nodes:
        node.close()


def test_network(num_nodes: int = 3, mining_time: int = 30) -> None:
    """
    Test the randomness beacon network.
    
    Args:
        num_nodes: The number of nodes to create.
        mining_time: The number of seconds to mine for.
    """
    print(f"Creating a network of {num_nodes} nodes...")
    nodes = create_randomness_beacon_network(num_nodes)
    
    print(f"Starting mining for {mining_time} seconds...")
    start_mining_in_network(nodes)
    
    # Wait for mining to happen
    try:
        for _ in range(mining_time):
            time.sleep(1)
            
            # Print the current state of the network
            print("\nCurrent network state:")
            for i, node in enumerate(nodes):
                latest_block = node.beacon.get_latest_block()
                print(f"Node {i} (address: {node.beacon.coinbase_address[:10]}...): " +
                      f"Chain height: {latest_block.block_height}, " +
                      f"Mined blocks: {node.beacon.ledger.get(node.beacon.coinbase_address, 0)}")
                print(f"  Latest randomness: {node.get_randomness()[:16]}...")
                
                # Count of 0s and 1s in binary randomness
                binary = node.get_binary_randomness()
                zeros = binary.count('0')
                ones = binary.count('1')
                print(f"  Binary randomness: {zeros} zeros, {ones} ones ({zeros/(zeros+ones)*100:.1f}% zeros)")
    finally:
        print("Stopping mining and closing network...")
        close_network(nodes)


# Entry point
if __name__ == "__main__":
    import threading
    import argparse
    
    parser = argparse.ArgumentParser(description='Randomness Beacon Network')
    parser.add_argument('--nodes', type=int, default=3, help='Number of nodes in the network')
    parser.add_argument('--time', type=int, default=60, help='Time to run in seconds')
    
    args = parser.parse_args()
    
    test_network(args.nodes, args.time)