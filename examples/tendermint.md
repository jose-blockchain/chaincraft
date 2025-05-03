# Running a Tendermint BFT Network Across Multiple Machines

This guide explains how to set up and run a Tendermint Byzantine Fault Tolerance (BFT) consensus network across multiple physical machines on a LAN or the Internet.

## Prerequisites

Before you begin, ensure each machine has:

- Python 3.7+ installed
- Required Python packages: `pip install ecdsa chaincraft`
- Network connectivity between all nodes
- Open ports for node communication (default: 8000-8100 TCP)
- Git clone of the Chaincraft repository on each machine

## Network Architecture

A Tendermint network consists of:

1. **Validator Nodes**: Participate in consensus by proposing and voting on blocks
2. **Observer Nodes** (optional): Sync with the blockchain but don't participate in consensus
3. **Network Topology**: Nodes connect in a peer-to-peer mesh network

## Setup Instructions

### Step 1: Configure Network Settings

On each machine, create a configuration file `tendermint_config.json`:

```json
{
  "node_id": "node1",  // Unique identifier for this node
  "host": "0.0.0.0",   // Listen on all interfaces
  "port": 8001,        // Unique port for this node
  "validators": [],    // Will be populated automatically
  "seed_nodes": [      // List of nodes to connect to on startup
    {"host": "192.168.1.101", "port": 8001},  // IP of another node in the network
    {"host": "192.168.1.102", "port": 8001}
  ],
  "is_validator": true,     // Whether this node is a validator
  "target_block_time": 15,  // Target time between blocks in seconds
  "log_level": "info"
}
```

Customize this configuration for each node, using the actual IP addresses of your machines.

### Step 2: Initialize the Network

On the first node (designated as the "genesis node"):

```bash
python examples/tendermint_cli.py init --config tendermint_config.json
```

This creates a genesis block and validator key files. Copy the generated `genesis.json` file to all other nodes.

### Step 3: Start the Genesis Node

```bash
python examples/tendermint_cli.py start --config tendermint_config.json
```

The genesis node will start and wait for connections from other nodes.

### Step 4: Join Additional Nodes to the Network

On each additional node:

```bash
python examples/tendermint_cli.py join --config tendermint_config.json --genesis genesis.json
```

This will connect the node to the genesis node and other peers in the network.

### Step 5: Verify the Network

On any node:

```bash
python examples/tendermint_cli.py status
```

This displays the current network status, including:
- Connected peers
- Blockchain height
- Validator set
- Consensus status

## Advanced Configuration

### Firewall Configuration

Ensure your firewall allows:
- Inbound/outbound TCP connections on your configured port (default: 8001)
- For cloud providers, configure security groups accordingly

### NAT Traversal

If nodes are behind NAT:
1. Configure port forwarding on your router to forward the Tendermint port to the machine
2. Use the public IP in the configuration for other nodes to connect

### Security Considerations

For production networks:
1. Use TLS connections for node communication
2. Implement validator key management best practices
3. Consider setting up a private network (VPN or dedicated connections)
4. Rotate validator keys periodically

## Troubleshooting

### Connection Issues

If nodes cannot connect:
1. Verify network connectivity with `ping` between nodes
2. Check firewall rules on all machines
3. Ensure seed node IPs are correct
4. Verify port forwarding if behind NAT

### Consensus Issues

If consensus is not progressing:
1. Check logs for timeout errors
2. Ensure all validators have the same genesis file
3. Verify validator keys are properly configured
4. Check system time synchronization between nodes

## Running on Public Cloud

### AWS Setup

1. Launch EC2 instances in the same security group
2. Configure security group to allow Tendermint port traffic
3. Use private IPs for instances in the same VPC
4. For cross-region setup, use public IPs and proper security groups

### Digital Ocean/Other Providers

Similar to AWS setup, ensure:
1. Firewall rules allow traffic
2. Use appropriate IP addresses in configuration

## Using the CLI Tool

The `tendermint_cli.py` tool provides a simple interface for managing your Tendermint network:

```
# Get help
python examples/tendermint_cli.py --help

# Initialize a new network
python examples/tendermint_cli.py init --config tendermint_config.json

# Start a node
python examples/tendermint_cli.py start --config tendermint_config.json

# Join an existing network
python examples/tendermint_cli.py join --config tendermint_config.json --genesis genesis.json

# Check node status
python examples/tendermint_cli.py status

# Add a new validator to the network
python examples/tendermint_cli.py add-validator --address 0x1234...

# View transaction history
python examples/tendermint_cli.py transactions
```

## Example: Setting Up a 4-Node Network on LAN

1. **Machine 1 (Genesis)**: 192.168.1.101
   ```bash
   # Initialize network
   python examples/tendermint_cli.py init --config node1_config.json
   # Start node
   python examples/tendermint_cli.py start --config node1_config.json
   ```

2. **Machine 2-4** (Validators): 192.168.1.102, 192.168.1.103, 192.168.1.104
   ```bash
   # Join network (copy genesis.json from Machine 1 first)
   python examples/tendermint_cli.py join --config nodeX_config.json --genesis genesis.json
   ```

3. **Verify** on any machine:
   ```bash
   python examples/tendermint_cli.py status
   ```

You should see all 4 nodes connected and producing blocks approximately every 15 seconds.

## Conclusion

You now have a functioning Tendermint BFT consensus network running across multiple machines. This setup can be extended to more nodes and customized according to your specific requirements. For more advanced usage, refer to the Chaincraft documentation. 