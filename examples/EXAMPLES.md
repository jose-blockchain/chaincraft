# Chaincraft Examples Guide

This file explains each protocol in `examples/` in plain language.
Think of it as a "what it is, why it matters, and how to run it" map.

---

## 1) Chatroom (`chatroom_protocol.py`)

**Core idea:** Shared chat state over gossip.

- Every message is a normal Chaincraft `SharedMessage`.
- The object validates and stores chat events (join, post, etc.).
- This is the simplest mental model for event-driven protocols.

**Why it matters:**  
It teaches the default Chaincraft path: validate -> add -> gossip.

**Use when:**  
You want to model collaborative state, feeds, logs, or social events.

---

## 2) Randomness Beacon (`randomness_beacon.py`)

**Core idea:** A merkelized stream of randomness-related messages.

- State is digest-aware, so peers can compare sync points.
- Demonstrates how to use merkelized object behavior in practice.

**Why it matters:**  
It shows the bridge between simple gossip and verifiable state synchronization.

**Use when:**  
You need a reproducible, shared sequence where state proofs/checkpoints matter.

---

## 3) Blockchain + Mempool (`blockchain.py`)

**Core idea:** Chain + pending transactions + validation flow.

- `Blockchain` tracks confirmed blocks.
- `Mempool` holds candidate transactions before inclusion in blocks.
- The example shows how protocol objects cooperate inside one node.

**Why it matters:**  
It is the canonical "multi-object protocol composition" example.

**Use when:**  
You need ordered final history plus a pre-confirmation queue.

---

## 4) Slush (`slush_protocol.py`)

**Core idea:** Metastable sampling consensus for binary choice.

- Nodes repeatedly sample peers and ask "R or B?"
- If sampled majority is strong enough, nodes move toward that color.
- Very small state, very simple dynamics.

**Why it matters:**  
It introduces Avalanche-family intuition: random sampling creates convergence.

**Use when:**  
You want the first conceptual step toward Avalanche-style consensus.

---

## 5) Snowflake (`snowflake_protocol.py`)

**Core idea:** Slush + a conviction counter.

- Same repeated sampling pattern.
- Adds a consecutive-success counter.
- Accepts once confidence in current color remains stable long enough.

**Why it matters:**  
It upgrades Slush toward stronger Byzantine fault tolerance behavior.

**Use when:**  
You need binary consensus with a stricter stability condition than Slush.

---

## 6) Snowball (`snowball_protocol.py`)

**Core idea:** Snowflake + persistent confidence per color.

- Maintains confidence counters `d[R]` and `d[B]`.
- Switches preference only when new color confidence strictly exceeds current.
- Uses `last_color` + consecutive counter to finalize decision.
- Includes `SnowballNode` for full networking with protocol auto-registration.

**Why it matters:**  
It is the strongest single-decision consensus example before full Avalanche DAG.

**Use when:**  
You want robust binary preference formation with memory of past successful samples.

---

## 7) Tendermint BFT (`tendermint_bft.py`)

**Core idea:** Round/step-driven BFT voting lifecycle.

- Models propose/prevote/precommit style progression.
- Different flavor from sampling protocols (leader/round mechanics).

**Why it matters:**  
It gives a second consensus family for contrast with Avalanche-style designs.

**Use when:**  
You need deterministic round-based BFT semantics rather than probabilistic sampling.

---

## How To Read These Examples

A practical sequence:

1. `chatroom_protocol.py` (gossip basics)
2. `blockchain.py` (composed protocol objects)
3. `slush_protocol.py` -> `snowflake_protocol.py` -> `snowball_protocol.py` (Avalanche family progression)
4. `tendermint_bft.py` (alternative BFT model)

---

## Practical Notes

- **Gossip-path protocols** mainly implement `is_valid()` + `add_message()`.
- **Request-response protocols** mainly implement `handle_p2p()` dispatch.
- Non-merkelized objects should keep digest methods stubbed.
- Merkelized objects should expose stable digest-based sync semantics.

This is the key Chaincraft pattern: keep protocol logic focused, let the node manage networking, storage, and concurrency.
