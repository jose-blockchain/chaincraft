# Chaincraft Protocol Implementation Specification v3 (0.6.0)

This document describes SPECS v3 for implementing a protocol using Chaincraft.
You write protocol logic only; Chaincraft handles networking, gossip,
storage, peer management, and concurrency.

**What v3 (0.6.0) adds, and why it stays uniform.** The `SharedObject` /
`SharedMessage` substrate described below is unchanged and remains the
foundation every protocol builds on. On top of it, 0.6.0 introduces a layer of
**pluggable, swap-by-name components** so that assembling or forking a system is
a configuration change, not a rewrite:

- **Ledger models** (`chaincraft.ledger`) — account/`balance` or `utxo`.
- **Fee policies** (`chaincraft.fees`) — `highest_first`, `median`, `eip1559`.
- **Mempool policy** (`chaincraft.mempool`) — admission/retention rules.
- **Consensus engines** (`chaincraft.consensus`) — a first-class, categorized,
  registry-driven abstraction (no longer buried in `examples/`).
- **Assembly** (`chaincraft.config`) — `BlockchainConfig` + `build_blockchain`.

Two rules keep usage uniform across the whole library:

1. **Select by name through a registry.** Every component family exposes a
   `get_*` helper (`get_ledger_model`, `get_fee_policy`, `get_consensus_engine`)
   and a name→class registry, so a default works out of the box and any part is
   one string away from being swapped.
2. **Impossible combinations fail fast.** Components validate their own
   parameters on construction, and `BlockchainConfig.validate()` rejects
   self-contradictory assemblies with a clear `ConfigError`. The system is
   highly configurable, but it will not let you build something that cannot
   work (see "Configuration Validation").

## Architecture Overview

```
┌───────────────────────────────────────────────────────────────┐
│                         ChaincraftNode                        │
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐            │
│  │ Listener │  │  Gossip  │  │ Merkelized Sync   │            │
│  │ (thread) │  │ (thread) │  │     (thread)      │            │
│  └────┬─────┘  └──────────┘  └───────────────────┘            │
│       │                                                       │
│       ▼                                                       │
│  handle_message()                                             │
│       │                                                       │
│       ├── Gossip path: SharedMessage                          │
│       │    ├── _handle_shared_message()                       │
│       │    │    ├── obj.is_valid(msg) for ALL objects         │
│       │    │    └── linear pipeline per object (v2):          │
│       │    │         obj.add_message(msg, frontier_state?)    │
│       │    │         -> Optional[StateMemento]                │
│       │    │         -> passed to next SharedObject           │
│       │    └── _store_and_broadcast()                         │
│       │         (store in DB, hash+dedupe, gossip to peers)   │
│       │                                                       │
│       └── P2P direct path: {"p2p": "..."}                     │
│            └── obj.handle_p2p(addr, data) for EACH object     │
│                 (NOT stored, NOT hashed, NOT gossiped)        │
│                                                               │
│  shared_objects: [YourProtocolObject, ...]                    │
└───────────────────────────────────────────────────────────────┘
```

## Core Abstractions

### SharedMessage

A thin wrapper around any JSON-serializable data.

```python
from chaincraft.shared_message import SharedMessage

msg = SharedMessage(data={"message_type": "MY_VOTE", "value": 42})
```

Messages are automatically serialized, hashed, deduplicated, stored, and
gossiped by the node. You never call `broadcast()` directly for protocol
messages; use `node.create_shared_message(data)` instead.

### SharedObject

The abstract base class for protocol logic. Every protocol implements
one `SharedObject` subclass.

```python
from chaincraft.shared_object import SharedObject
from chaincraft.state_memento import StateMemento

class MyProtocolObject(SharedObject):
    def is_valid(self, message: SharedMessage) -> bool: ...
    def add_message(
        self,
        message: SharedMessage,
        frontier_state: Optional[StateMemento] = None,
    ) -> Optional[StateMemento]: ...
    def emit_state_memento(self) -> StateMemento: ...
    def get_state_digests(self) -> List[str]: ...
    def is_merkelized(self) -> bool: ...
    def get_latest_digest(self) -> str: ...
    def has_digest(self, hash_digest: str) -> bool: ...
    def is_valid_digest(self, hash_digest: str) -> bool: ...
    def add_digest(self, hash_digest: str) -> bool: ...
    def gossip_object(self, digest) -> List[SharedMessage]: ...
    def get_messages_since_digest(self, digest: str) -> List[SharedMessage]: ...
```

### ChaincraftNode

The runtime. Manages UDP sockets, peer lists, gossip, and message
dispatch. Spawns its own daemon threads for listening, gossip, and
merkelized sync. **You never spawn threads for protocol logic.**

## Message Flow (Gossip Path)

When a peer sends a message to this node:

1. **Listener thread** receives the UDP datagram.
2. `handle_message()` is called.
3. `is_message_accepted()` checks schema constraints (optional).
4. `_handle_shared_message()` runs:
   - **Validation phase**: calls `obj.is_valid(msg)` on **every**
     SharedObject in the node. If **any** returns `False`, the message
     is rejected and the sender receives a strike (ban after 3 strikes).
   - **Processing phase**: only if **all** objects validated, process
     objects **sequentially** in registration order while passing an
     optional `frontier_state` memento downstream.
   - Then stores and broadcasts (gossips) the message to all peers.
5. Your `add_message()` runs protocol state transitions.

In v2, `frontier_state` carries canonical/frontier digests between
SharedObjects so downstream objects can detect reorgs or canonical
rewrites (including multi-block rewrites) and catch up.

This two-phase design supports nodes with **multiple SharedObjects**
that represent different facets of the same protocol. A typical example
is a blockchain node with three objects:

- A **merkelized Chain** (ordered blocks with digest-linked sync)
- A **merkelized Ledger / UTXO set** (account balances; merkelized so
  nodes can verify they share the same state snapshot)
- A **non-merkelized Mempool** (backlog of unconfirmed transactions
  pending inclusion in the next block; integrity not critical)

A new message (e.g. a block) must be valid for all three before any
of them process it. Once accepted, each object updates its own state
sequentially: the Chain appends the block, the Ledger applies the
balance changes, and the Mempool removes the now-confirmed transactions.

When this node creates a message locally:

1. `node.create_shared_message(data)` wraps data in a SharedMessage.
2. Calls `obj.is_valid(msg)` on all SharedObjects.
3. If all valid, processes shared objects in the same linear pipeline
   (including optional `frontier_state` propagation).
4. Broadcasts the message to all peers.
5. Stores it in the node's DB (deduplicated by hash).

## Message Flow (Direct / Request-Response Path)

For protocols that need point-to-point query/response (not gossip),
use the generic **P2P dispatch**. Any JSON message containing a `"p2p"`
key is treated as an ephemeral direct message between two nodes. These
messages are **not** stored, **not** hashed, **not** deduplicated, and
**not** gossiped — they travel only between the sender and the receiver
via UDP unicast (`send_to_peer`). Other nodes in the network never see
them.

The node's listener detects `"p2p"` in the parsed dict and calls
`handle_p2p(addr, data)` on every SharedObject. This is the single
public entry point for P2P messages — the same pattern as `add_message()`
for gossip messages. Each SharedObject dispatches internally to private
handlers based on the `"p2p"` value.

### P2P message format

```json
{"p2p": "MY_PROTOCOL_QUERY", "field1": "value1", "field2": 42}
```

The `"p2p"` value identifies the message type. All payload fields are
top-level siblings — no nested wrapper.

### Implementing P2P in your SharedObject

```python
class MyObject(SharedObject):
    MSG_QUERY = "MY_PROTOCOL_QUERY"
    MSG_RESPONSE = "MY_PROTOCOL_RESPONSE"

    def handle_p2p(self, addr, data):
        p2p_type = data.get("p2p")
        if p2p_type == self.MSG_QUERY:
            self._handle_query(addr, data)
        elif p2p_type == self.MSG_RESPONSE:
            self._handle_response(addr, data)

    def _handle_query(self, addr, data):
        # Validate fields, update state, respond
        resp = {"p2p": self.MSG_RESPONSE, "result": ...}
        self.node.send_to_peer(addr, json.dumps(resp))

    def _handle_response(self, addr, data):
        # Collect response, advance protocol state
        ...
```

Use `node.send_to_peer(peer, json_string)` for unicast.
Use `node.broadcast(json_string)` only for protocol-level flooding
(prefer `create_shared_message` for gossip-path messages).

## Merkelized Objects

For protocols that maintain a digest-linked structure of messages,
implement the merkelized interface. The underlying structure does not
have to be a linear chain — it can be a **DAG**, a **Merkle tree**, or
any directed acyclic graph where entries reference parent digests.
A blockchain (linear chain) is just one specific case.

- `is_merkelized()` → return `True`
- `get_latest_digest()` → return the hash of the current frontier
  (tip of a chain, root of a tree, set of leaf digests in a DAG, etc.)
- `has_digest(h)` / `is_valid_digest(h)` → structure membership checks
- `gossip_object(digest)` → return messages a peer is missing since that digest
- `get_messages_since_digest(digest)` → return messages reachable after a digest

The node's merkelized sync thread periodically broadcasts
`REQUEST_SHARED_OBJECT_UPDATE` to peers. When a peer receives this,
`_handle_shared_object_update_request()` calls `gossip_object()` on
the matching SharedObject and sends the missing messages back.

## Non-Merkelized Objects

Not every shared data structure needs digest-linked sync. Objects where
messages are independent and order does not matter — such as a chatroom,
a blockchain mempool (unconfirmed transactions), or consensus votes —
are typically non-merkelized. They rely on the node's built-in gossip
and hash-based deduplication, which is sufficient.

For these objects, return `False` from `is_merkelized()` and stub the
digest methods:

```python
def is_merkelized(self) -> bool:
    return False

def get_latest_digest(self) -> str:
    return ""

def has_digest(self, hash_digest: str) -> bool:
    return False

def is_valid_digest(self, hash_digest: str) -> bool:
    return False

def add_digest(self, hash_digest: str) -> bool:
    return False

def gossip_object(self, digest) -> List[SharedMessage]:
    return []

def get_messages_since_digest(self, digest: str) -> List[SharedMessage]:
    return []
```

## Implementing a Protocol: Step by Step

### 1. Define your SharedObject subclass

Focus on two methods:

- **`is_valid(msg)`**: Return `True` if this message is well-formed and
  the state transition it represents is legal. This is your validator.
- **`add_message(msg, frontier_state=None)`**: The single public entry
  point from the node. Apply the state transition here. Dispatch
  internally to private handlers based on message type or content — do
  not add more public handler methods. Legacy objects may still use
  `add_message(msg)` without `frontier_state`. For example:

```python
def add_message(self, message, frontier_state=None):
    data = message.data
    if data["blockHeight"] == len(self.blocks) - 1:
        self._handle_replacement(data)
    else:
        self._handle_new_block(data)
```

All protocol-specific routing lives inside `add_message()`, delegating
to `_private_methods()` as needed.

### 2. Register it with the node

```python
from chaincraft.node import ChaincraftNode

node = ChaincraftNode(port=9000, local_discovery=True)
protocol = MyProtocolObject(node)
node.add_shared_object(protocol)
node.start()
```

You may also wrap this pattern in a protocol-specific node subclass
that inherits `ChaincraftNode` and auto-registers the protocol object
(for example, `SnowballNode` in `examples/snowball_protocol.py`).

### 3. Initiate protocol actions

```python
node.create_shared_message({"message_type": "MY_ACTION", "value": 42})
```

This validates, stores, and gossips in one call. If your SharedObject
rejects the message, a `SharedObjectException` is raised.

### 4. React to incoming messages

The node provides **two public entry points** into your SharedObject,
both called from the listener thread:

- **`add_message(msg, frontier_state=None)`** — for gossip-path messages
  (stored, deduplicated, broadcast). Dispatch to `_private_methods()`
  internally.
- **`handle_p2p(addr, data)`** — for ephemeral point-to-point messages
  (not stored, not gossiped). Dispatch to `_private_methods()` internally.

You do not poll, sleep, or spawn threads. Your handlers run synchronously
in the listener thread.

### 5. Expose state to callers

Add getters on your SharedObject. Callers poll or use callbacks:

```python
# Polling
while protocol.get_accepted() is None:
    time.sleep(0.1)

# Callback (set in constructor)
protocol = MyProtocolObject(node, on_decided=my_callback)
```

## Thread Safety

`add_message()` and `handle_p2p()` run in the node's listener thread.
If your protocol also exposes methods called from outside (e.g.
`propose()` from the main thread, or a callback wired to the UI),
you share state between two threads. Protect that shared state with a
`threading.Lock`. See `SlushObject._lock` and `SnowflakeObject._lock`
for the pattern.

## What You Do NOT Do

- **No threads.** ChaincraftNode manages all concurrency.
- **No sockets.** Use `node.send_to_peer()` or `node.create_shared_message()`.
- **No gossip logic.** The node gossips all stored messages automatically.
- **No deduplication.** Messages are hashed and deduplicated by the node.
- **No peer management.** Use `node.connect_to_peer()` and `local_discovery`.

## Pluggable Components (0.6.0)

A blockchain in Chaincraft is assembled from interchangeable parts. The default
config produces a working chain; each part is swappable by name.

| Family | Module | `get_*` helper | Built-in names |
|---|---|---|---|
| Ledger model | `chaincraft.ledger` | `get_ledger_model` | `balance`, `utxo` |
| Fee policy | `chaincraft.fees` | `get_fee_policy` | `highest_first`, `median`, `eip1559` |
| Payload pricing | `chaincraft.fees.payload` | `get_payload_pricing` | `none`, `per_byte`, `per_compressed_byte`, `flat`, `absolute`, `total_bytes` |
| Consensus engine | `chaincraft.consensus` | `get_consensus_engine` | `relay`, `avalanche`, `hashgraph`, `tendermint`, `pbft`, `hotstuff`, `pow`, `beacon`, `vdf`, `nano_lattice`, `dagcoin`, … |
| Mempool policy | `chaincraft.mempool` | (dataclass `MempoolPolicy`) | — |
| Fork choice | `chaincraft.config` | (`BlockchainConfig.fork_choice`) | `longest_chain`, `heaviest`, `bft_finality` |
| Decentralized protocols | `chaincraft.protocols` | — | `ChatGroup`, `TopicPubSub`, `CRDTKeyValue` |

```python
from chaincraft import BlockchainConfig, build_blockchain
from chaincraft.mempool import MempoolPolicy

config = BlockchainConfig(
    ledger_model="balance",          # or "utxo"
    fee_policy="eip1559",            # or "highest_first", "median"
    initial_base_fee=1,
    max_transactions_per_block=100,
    target_transactions_per_block=50,
    mempool_policy=MempoolPolicy(max_size=10_000, min_fee=1, enable_rbf=True),
    payload_pricing="per_byte",      # charge for opaque tx data (not smart contracts)
    payload_kwargs={"rate": 1},
    max_payload_bytes=4096,
    genesis_allocations={"alice": 1_000},
)
chain = build_blockchain(config)     # validates, then assembles

from chaincraft.ledger import Transaction
tx = Transaction(
    sender="alice", recipient="bob", amount=10, fee=20, nonce=0,
    data=b"hello",                   # opaque payload; priced by payload_pricing
)
chain.submit(tx)                     # admission via fee + payload + mempool policy
block = chain.produce_block(miner="alice")

# Optional: attach a consensus engine when wiring a node
config = BlockchainConfig(consensus_engine="tendermint", fork_choice="bft_finality",
                          consensus_kwargs={"validator_id": "v0",
                                            "validators": ["v0","v1","v2","v3"]})
builder = BlockchainBuilder(config)
chain = builder.wire_node(node)        # builds chain + attaches engine to node
```

Swapping the ledger or fee market is a one-line change to the config; nothing
else in your code moves.

**Balance ledger and data payloads.** 0.6.0 supports full cryptocurrency
blockchains on the account/balance model (and UTXO for structural fees). Each
``Transaction`` may carry an opaque ``data`` byte string (notes, hashes, app
messages). The ledger stores and forwards it but does **not** execute it —
smart contracts are not supported yet. How much that data costs is configured
independently via ``payload_pricing``:

- ``none`` — payload is free (default).
- ``per_byte`` — ``rate × len(data)`` native units.
- ``per_compressed_byte`` — ``rate × len(zlib.compress(data))``.
- ``flat`` — fixed fee when ``data`` is non-empty.
- ``absolute`` — fixed fee on every transaction regardless of payload.
- ``total_bytes`` — ``rate ×`` full serialized transaction size.

Set ``max_payload_bytes`` on ``BlockchainConfig`` to reject oversized attachments
at admission. Fee policies add the payload minimum to their own rules (e.g.
EIP-1559 requires ``fee >= base_fee + payload_cost``).

### Configuration Validation

The assembly layer is permissive about *which* parts you combine, but it
distinguishes two cases. Validation runs in `BlockchainConfig.validate()`
(called by `build_blockchain`) and in component constructors.

**Impossible / incompatible → hard error.** Combinations that cannot work are
rejected, so the system never silently misbehaves:

- Unknown `ledger_model` / `fee_policy` name.
- `max_transactions_per_block < 1`, or `target` outside `[1, max]`.
- Negative `coinbase_reward`, `initial_base_fee`, or genesis allocation.
- `eip1559` with `initial_base_fee` below the policy's `min_base_fee` floor.
- A per-sender mempool cap (`max_per_sender`) on a `utxo` ledger, which has no
  sender identity to count against.
- `avalanche` with `alpha` outside `(0, 1]` (would need more yes-votes than
  peers sampled), `k < 1`, or thresholds `< 1`.

Invalid blockchain assemblies raise `chaincraft.ConfigError`; invalid component
parameters raise `ValueError` or `chaincraft.consensus.ConsensusError`.

**Allowed but experimental / unstable → non-fatal warning.** Combinations that
*run* but carry weaker guarantees or pair a feature with a ledger that cannot
fully use it emit a warning and proceed, so you stay in control:

- `eip1559` on the `utxo` ledger (burn accounting validated for `balance` only).
- Replace-by-fee enabled on a `utxo` ledger (no sender/nonce to match — inert).
- `eip1559` with `coinbase_reward=0` (miners paid by tips only; may be
  unincentivized).
- `avalanche` with `alpha <= 0.5` (quorum not a strict majority).
- `tendermint` with fewer than 4 validators (tolerates 0 Byzantine faults).

These raise `chaincraft.ExperimentalConfigWarning` or
`chaincraft.consensus.UnstableConsensusWarning` via the standard `warnings`
module. Silence them per combination with `warnings.filterwarnings(...)`, or
promote them to errors in strict environments with `warnings.simplefilter(
"error", ...)`. Prefer surfacing all of this at startup rather than failing
obscurely mid-run.

## Randomness Beacon (0.6.0)

The randomness beacon is **not** a ledger and does not require cryptography by
default. It maintains a fork-aware chain of opaque block ids; each block yields
a pseudorandom float via a pluggable :class:`RandomnessDerivation`.

| Component | Registry | Names |
|---|---|---|
| Block source | `chaincraft.beacon` | `hash_chain` (default), `sequential`, `pow` |
| Randomness derivation | `chaincraft.beacon` | `direct`, `rehash`, `timestamp_mix`, `xor_chain`, `modulo`, `height_salt` |

```python
from chaincraft.beacon import build_beacon, BeaconConfig

beacon = build_beacon(block_source="hash_chain", randomness="rehash")
beacon.append()
print(beacon.random_float(), beacon.random_int(1, 6))

# Gossip engine adapter (registered as consensus "beacon"):
from chaincraft.consensus import get_consensus_engine
engine = get_consensus_engine("beacon", randomness="xor_chain")
engine.propose()
```

## Decentralized Protocols (0.6.0)

Non-blockchain protocols live in `chaincraft/protocols/` with the same modular
spirit as the blockchain layers:

| Protocol | Module | Configurable knobs |
|---|---|---|
| ChatGroup | `chaincraft.protocols.chat` | membership: `open`, `invite`, `admin_approval` |
| TopicPubSub | `chaincraft.protocols.pubsub` | topic subscriptions, publish payloads |
| CRDT KV | `chaincraft.protocols.crdt` | last-write-wins merge per key |

```python
from chaincraft.protocols import ChatGroup, TopicPubSub, CRDTKeyValue

group = ChatGroup(membership="open")
pubsub = TopicPubSub()
store = CRDTKeyValue()
store.add_message(SharedMessage(data=store.local_put("color", "blue", writer="a")))
```

The legacy teaching example remains at `examples/chatroom_protocol.py`.

## Consensus Engines (0.6.0)

Consensus is a first-class, pluggable concept. Engines live in
`chaincraft/consensus/`, grouped into families so users can explore and compare
a broad catalog and **fork any of them easily**:

- `gossip` — randomized sampling / virtual voting (e.g. **Avalanche**, Hashgraph)
- `pow` — proof-of-work and verifiable-delay linear work
- `bft` — quorum protocols (e.g. **Tendermint**, PBFT, HotStuff)
- `dag` — DAG / block-lattice protocols (Nano, DAGcoin)

```python
from chaincraft.consensus import default_registry, get_consensus_engine

default_registry.categories()        # {'gossip': [...], 'bft': [...], ...}
engine = get_consensus_engine("tendermint", validator_id="v0",
                              validators=["v0", "v1", "v2", "v3"])
engine.propose("blockA")
engine.is_decided(), engine.decision()
```

### The `ConsensusEngine` contract

Every engine subclasses a category base (`GossipConsensus`, `PoWConsensus`,
`BFTConsensus`, `DAGConsensus`, all of which extend `ConsensusEngine`) and
implements three abstract methods plus, optionally, message hooks:

```python
class ConsensusEngine(ABC):
    name: str = "abstract"           # registry key
    category: str = "abstract"       # one of the families above

    # Lifecycle (you implement these three)
    def propose(self, value): ...        # submit a value to drive a decision
    def is_decided(self) -> bool: ...    # has a decision been reached?
    def decision(self): ...              # the decided value, or None

    # Message hooks (override what you need)
    def observe(self, message): ...      # a gossiped SharedMessage arrived
    def on_p2p(self, addr, data): ...    # a direct P2P message arrived

    # Node integration (provided; rarely overridden)
    def broadcast(self, data): ...       # gossip via the attached node
```

An engine **is** a `SharedObject`: its default `is_valid` / `add_message` /
`handle_p2p` adapters route node traffic into `observe()` (gossip path) and
`on_p2p()` (direct path), and `is_merkelized()` returns `False`. So you attach
an engine exactly like any other protocol object:

```python
node.add_shared_object(engine)   # also calls engine._attach_node(node)
```

After attachment, `engine.broadcast(data)` gossips through
`node.create_shared_message(data)`. This makes every engine **transport-
agnostic**: drive it with a real `ChaincraftNode`, or with an in-memory bus in
tests, without changing the engine.

### Extending or forking a consensus protocol

1. Pick the family and subclass its base.
2. Implement `propose`, `is_decided`, `decision`; override `observe` /
   `on_p2p` as needed; validate parameters in `__init__`.
3. Register it with `@register_consensus` so it is selectable by name.

```python
from chaincraft.consensus import register_consensus
from chaincraft.consensus.gossip import GossipConsensus
from chaincraft.consensus.base import message_data

@register_consensus
class MyGossipConsensus(GossipConsensus):
    name = "my_gossip"

    def __init__(self, threshold=3, **kwargs):
        super().__init__(**kwargs)
        if threshold < 1:
            from chaincraft.consensus.base import ConsensusError
            raise ConsensusError("threshold must be >= 1")
        self.threshold = threshold
        self._decision = None

    def propose(self, value):
        self.broadcast({"consensus": self.name, "value": value})

    def observe(self, message):
        data = message_data(message)
        if isinstance(data, dict) and data.get("consensus") == self.name:
            ...  # accumulate evidence, set self._decision when satisfied

    def is_decided(self): return self._decision is not None
    def decision(self): return self._decision
```

To fork an existing engine, subclass it (or copy its module under the same
family), override only the decision logic, and register under a new `name`.

### Core engines vs. teaching toys

Full, reusable engines live in `chaincraft/consensus/<family>/`. Deliberately
simplified, single-decree **teaching** implementations stay in `examples/` so
learners can read one self-contained file:

- Core `gossip`: `AvalancheConsensus` — full DAG metastable consensus
  (vertices, conflict sets, per-set Snowball, ancestry-gated acceptance).
- Core `gossip`: `HashgraphConsensus` — event-DAG gossip with simplified
  virtual-voting decision; registered as `"hashgraph"`.
- Core `bft`: `TendermintConsensus` — deterministic propose/prevote/precommit
  with a > 2/3 Byzantine quorum.
- Core `bft`: `PBFTConsensus` — classic three-phase pre-prepare / prepare /
  commit with a `2f+1` quorum; registered as `"pbft"`.
- Core `bft`: `HotStuffConsensus` — pipelined prepare / pre-commit / commit
  BFT; registered as `"hotstuff"`.
- Core `pow`: `ProofOfWorkConsensus` — longest-valid-chain Nakamoto consensus
  built on the reusable `ForkAwareChain` helper (heaviest-chain fork choice,
  deterministic tie-break, reorg deltas) with confirmation-based finality.
- Core `pow`: `RandomnessBeaconConsensus` — modular beacon chain (no ledger);
  pluggable block sources (`hash_chain`, `sequential`, `pow`) and randomness
  derivations (`direct`, `rehash`, `xor_chain`, …); see `chaincraft/beacon/`.
- Core `pow`: `VDFLinearWorkConsensus` — longest-valid-chain consensus secured
  by sequential VDF proofs (`crypto_primitives/vdf.py`); registered as `"vdf"`.
- Core `dag`: `NanoLatticeConsensus` — block-lattice with open/send/receive
  blocks and representative-weighted confirmation; registered as `"nano_lattice"`.
- Core `dag`: `DAGcoinConsensus` — tangle with cumulative-weight confirmation
  and conflict-set resolution; registered as `"dagcoin"`.
- Toys in `examples/`: `Slush`, `Snowflake`, `Snowball` (binary single-decree
  Avalanche family), the networked `tendermint_bft.py` walkthrough, and the
  mining-loop `blockchain.py` / `randomness_beacon.py` PoW demos.

Reusable building blocks also live in the family packages — e.g.
`chaincraft.consensus.pow.ForkAwareChain` is the fork-choice/reorg engine that
any longest- or heaviest-chain protocol can build on.

## Examples

| Protocol | Type | Path |
|---|---|---|
| Chatroom | Gossip (non-merkelized) | `examples/chatroom_protocol.py` |
| Randomness Beacon | Gossip (merkelized) | `examples/randomness_beacon.py` |
| Slush (toy) | Request-response | `examples/slush_protocol.py` |
| Snowflake (toy) | Request-response | `examples/snowflake_protocol.py` |
| Snowball (toy) | Request-response | `examples/snowball_protocol.py` |
| Tendermint BFT (toy) | Gossip (non-merkelized) | `examples/tendermint_bft.py` |
| Avalanche (full) | Core consensus engine (`gossip`) | `chaincraft/consensus/gossip/avalanche.py` |
| Tendermint (full) | Core consensus engine (`bft`) | `chaincraft/consensus/bft/tendermint.py` |
| Proof-of-Work (full) | Core consensus engine (`pow`) | `chaincraft/consensus/pow/proof_of_work.py` |
| Randomness Beacon (full) | Core consensus engine (`pow`) | `chaincraft/consensus/pow/beacon.py` |

### Gossip-path example (Chatroom)

```python
class ChatroomObject(SharedObject):
    def is_valid(self, message):
        # Verify signature, check membership, validate timestamp
        ...
        return True

    def add_message(self, message, frontier_state=None):
        # Apply: create room, accept member, store post
        # Optionally notify UI via callback
        if self.on_message_added:
            self.on_message_added(chatroom_name, data)
```

### Request-response example (Slush)

```python
class SlushObject(SharedObject):
    MSG_QUERY = "SLUSH_QUERY"
    MSG_RESPONSE = "SLUSH_RESPONSE"

    def propose(self, color):
        self._send_round(1)

    def handle_p2p(self, addr, data):
        p2p_type = data.get("p2p")
        if p2p_type == self.MSG_QUERY:
            self._handle_query(addr, data)
        elif p2p_type == self.MSG_RESPONSE:
            self._handle_response(addr, data)

    def _handle_query(self, addr, data):
        resp = {"p2p": self.MSG_RESPONSE, "r": data["r"], "col": ...}
        self.node.send_to_peer(addr, json.dumps(resp))

    def _handle_response(self, addr, data):
        # Collect, process round, advance or accept
        if r < self.m:
            self._send_round(r + 1)
        else:
            self._accepted = self._color

    # is_valid / add_message stub (not used for P2P-only protocols)
```

## Node Lifecycle

```python
node = ChaincraftNode(port=9000)
node.add_shared_object(my_protocol)
node.start()                            # Binds socket, starts threads
node.connect_to_peer("127.0.0.1", 9001) # Add peers
# ... protocol runs via message handlers ...
node.close()                            # Stops threads, closes socket
```
