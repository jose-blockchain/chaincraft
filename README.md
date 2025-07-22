# Chaincraft

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Python Unit Tests](https://github.com/google/adk-python/actions/workflows/python-unit-tests.yml/badge.svg)]([https://github.com/google/adk-python/actions/workflows/python-unit-tests.yml](https://github.com/jio-gl/chaincraft/blob/main/.github/workflows/python-app.yml))
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Blockchain](https://img.shields.io/badge/blockchain-educational-blueviolet)](https://github.com/jio-gl/chaincraft)
[![ECDSA](https://img.shields.io/badge/ECDSA-supported-green)](https://github.com/jio-gl/chaincraft)
[![Project Status](https://img.shields.io/badge/status-in%20development-yellow)](https://github.com/jio-gl/chaincraft)
[![PyPI version](https://badge.fury.io/py/chaincraft.svg)](https://pypi.org/project/chaincraft/)
[![PyPI Downloads](https://static.pepy.tech/badge/cerebras-agent)](https://pepy.tech/projects/chaincraft)

# Chaincraft

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/jio-gl/chaincraft/actions/workflows/python-app.yml/badge.svg)](https://github.com/jio-gl/chaincraft/actions/workflows/python-app.yml)
[![PyPI version](https://badge.fury.io/py/chaincraft.svg)](https://pypi.org/project/chaincraft/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**A Python framework for blockchain education and rapid prototyping**

Chaincraft provides the fundamental building blocks for creating blockchain networks, implementing consensus mechanisms, and experimenting with distributed systems. Built for education and research, it offers a clean, extensible architecture for exploring blockchain concepts.

## Features

**Core Infrastructure**
- Decentralized peer-to-peer networking with automatic discovery
- Message gossip protocol with validation and type checking
- Persistent and in-memory storage options
- Cryptographic primitives (ECDSA, Proof of Work, VDF, VRF)

**Distributed State Management**
- Shared Objects framework for consensus implementation
- Merklelized storage for efficient state synchronization
- Built-in support for various consensus mechanisms
- Message indexing and validation

**Developer Experience**
- Simple Python API and command-line interface
- Comprehensive examples and documentation
- Modular design for easy customization
- Educational focus with clear architectural patterns

## Quick Start

### Installation

```bash
pip install chaincraft
```

### Start a Node

```bash
# Command line
chaincraft-cli -p 8000

# Python
import chaincraft
node = chaincraft.ChaincraftNode()
node.start()
```

### Connect Nodes

```python
# Connect to another node
node.connect_to_peer("127.0.0.1", 21000)

# Broadcast a message
node.create_shared_message("Hello, Chaincraft!")
```

## Core Concepts

### Nodes and Networking
`ChaincraftNode` handles peer discovery, connection management, and message propagation across the network.

### Shared Objects
Abstract base class for implementing distributed data structures with consensus. Perfect for building blockchains, state machines, or any distributed application.

### Cryptographic Primitives
Built-in implementations of essential blockchain cryptography including digital signatures, proof of work, and verifiable random functions.

## Examples

**Simple Blockchain**
```python
from chaincraft.examples.blockchain import SimpleBlockchain
from chaincraft import ChaincraftNode

# Create a blockchain node
blockchain = SimpleBlockchain()
node = ChaincraftNode(shared_objects=[blockchain])
node.start()

# Mine a block
blockchain.mine_block("transaction_data")
```

**Custom Consensus Mechanism**
```python
from chaincraft.shared_object import SharedObject

class MyConsensus(SharedObject):
    def __init__(self):
        self.state = {}
    
    def is_valid(self, message):
        # Implement validation logic
        return True
    
    def add_message(self, message):
        # Update state based on consensus rules
        self.state.update(message.data)
```

## Documentation

### API Reference
- [Core Components](docs/api/core.md)
- [Cryptographic Primitives](docs/api/crypto.md)
- [Shared Objects](docs/api/shared_objects.md)

### Tutorials
- [Building Your First Blockchain](docs/tutorials/first_blockchain.md)
- [Implementing Custom Consensus](docs/tutorials/consensus.md)
- [Peer-to-Peer Networking](docs/tutorials/networking.md)

### Examples
- [Simple Blockchain](examples/blockchain/) - Basic PoW blockchain
- [Message Chain](examples/message_chain/) - Merklelized append-only log
- [ECDSA Transactions](examples/transactions/) - Signed transaction system
- [Chatroom](examples/chatroom/) - Real-time messaging application

## Development

### From Source
```bash
git clone https://github.com/jio-gl/chaincraft.git
cd chaincraft
pip install -e ".[dev]"
```

### Running Tests
```bash
# All tests
python -m unittest discover -v

# Specific test
python -m unittest tests.test_blockchain_example
```

### Contributing
We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Architecture

Chaincraft explores fundamental blockchain design decisions:

**The Blockchain Trilemma**
- Security vs Scalability vs Decentralization

**Time Models**
- Asynchronous vs Time-Bounded vs Synchronized

**Identity Systems**
- Anonymous vs Resource-Based vs Identity-Based

**Consensus Mechanisms**
- Proof of Work, Proof of Stake, Byzantine Fault Tolerance

## Roadmap

### Version 1.0 (Current)
- ✅ Gossip protocol and peer discovery
- ✅ Message validation and persistent storage
- ✅ Shared Objects and merklelized sync
- ✅ Cryptographic primitives
- ✅ Proof of Work and PBFT consensus
- 🔄 Transaction validation (balance-based and UTXO)
- ⏳ Additional consensus mechanisms (PoS, PoA, PoET)
- ⏳ Smart contracts and state machine replication

### Version 2.0 (Planned)
- Configurable consensus protocols
- Multiple ledger types (UTXO, account-based)
- Gas auction mechanisms
- Sharding support

## Requirements

- Python 3.8+
- `cryptography>=44.0.1`

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/jio-gl/chaincraft/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jio-gl/chaincraft/discussions)