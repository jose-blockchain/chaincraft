# Chaincraft Protocol Implementation Specification v1

This document describes how to implement a protocol using Chaincraft.
You write protocol logic only; Chaincraft handles networking, gossip,
storage, peer management, and concurrency.

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   ChaincraftNode                    │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ Listener │  │  Gossip  │  │ Merkelized Sync   │  │
│  │ (thread) │  │ (thread) │  │     (thread)      │  │
│  └────┬─────┘  └──────────┘  └───────────────────┘  │
│       │                                             │
│       ▼                                             │
│  handle_message()                                   │
│       │                                             │
│       ├── is_message_accepted()                     │
│       │                                             │
│       ├── _handle_shared_message()                  │
│       │       │                                     │
│       │       ├── obj.is_valid(msg) for ALL objects │
│       │       │                                     │
│       │       └── obj.add_message(msg) for EACH     │
│       │                                             │
│       └── _store_and_broadcast()                    │
│               (store in DB, gossip to peers)        │
│                                                     │
│  shared_objects: [YourProtocolObject, ...]          │
└─────────────────────────────────────────────────────┘
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

class MyProtocolObject(SharedObject):
    def is_valid(self, message: SharedMessage) -> bool: ...
    def add_message(self, message: SharedMessage) -> None: ...
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
   - **Processing phase**: only if **all** objects validated, calls
     `obj.add_message(msg)` **sequentially** on each SharedObject in
     registration order. Each object gets one shot to update its
     internal state for this message.
   - Then stores and broadcasts (gossips) the message to all peers.
5. Your `add_message()` runs protocol state transitions.

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
3. If all valid, calls `obj.add_message(msg)` on each.
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
- **`add_message(msg)`**: The single public entry point from the node.
  Apply the state transition here. Dispatch internally to private
  handlers based on message type or content — do not add more public
  handler methods. For example:

```python
def add_message(self, message):
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

- **`add_message(msg)`** — for gossip-path messages (stored, deduplicated,
  broadcast). Dispatch to `_private_methods()` internally.
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

## Examples

| Protocol | Type | Path |
|---|---|---|
| Chatroom | Gossip (non-merkelized) | `examples/chatroom_protocol.py` |
| Randomness Beacon | Gossip (merkelized) | `examples/randomness_beacon.py` |
| Slush | Request-response | `examples/slush_protocol.py` |
| Snowflake | Request-response | `examples/snowflake_protocol.py` |
| Snowball | Request-response | `examples/snowball_protocol.py` |
| Tendermint BFT | Gossip (non-merkelized) | `examples/tendermint_bft.py` |

### Gossip-path example (Chatroom)

```python
class ChatroomObject(SharedObject):
    def is_valid(self, message):
        # Verify signature, check membership, validate timestamp
        ...
        return True

    def add_message(self, message):
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
