# Chaincraft Python — TODO

## SPECS v2 — Changeset support for reorgs

The current `add_message()` is forward-only. Deep blockchain reorgs
(e.g. replacing the last 3 blocks with a longer fork) require undoing
state across multiple SharedObjects (Chain, Ledger, Mempool) atomically.

**Proposed design**: `add_message()` returns an optional `Changeset` dict
that is passed to the next SharedObject in the pipeline. This way a
Chain object detecting a 3-block reorg can emit a changeset specifying
which blocks were reverted and which transactions need to go back into
the Mempool or be unwound from the Ledger. Each downstream object
receives the changeset and acts on it.

```
Chain.add_message(block)
  → detects reorg, reverts 3 blocks internally
  → returns Changeset {"reverted_blocks": [...], "reverted_txs": [...]}

Ledger.add_message(block, changeset)
  → reverses balance changes for reverted_txs
  → applies new block balances

Mempool.add_message(block, changeset)
  → re-adds reverted_txs to the pool
  → removes newly confirmed txs
```

This keeps the pipeline model (no orchestrator/coordinator needed) while
giving each object the context it needs to handle undo + redo.

**Important**: the SharedObject pipeline must remain **linear** — an
ordered list where each object passes its changeset to the next. If
objects formed a graph (fan-out, cycles, conditional routing), changeset
propagation becomes unmanageable: ordering is ambiguous, conflicts are
hard to resolve, and reversibility breaks down. A linear pipeline is
simple, predictable, and sufficient for real protocols.

**Changeset as a list of typed operations**: Rather than passing raw
data blobs, each SharedObject defines a small set of reversible
operations (its "core operators"). A Changeset is a list of these
operations — internal messages between objects in the pipeline.

Each operation has a forward and reverse form:

```
# Ledger operators
CREDIT_BALANCE(addr, amount)    ↔  DEBIT_BALANCE(addr, amount)
DEBIT_BALANCE(addr, amount)     ↔  CREDIT_BALANCE(addr, amount)

# Mempool operators
REMOVE_TX(tx_id)                ↔  RESTORE_TX(tx_id, tx_data)
ADD_TX(tx_id, tx_data)          ↔  REMOVE_TX(tx_id)
```

When Chain detects a 3-block reorg, `add_message()` returns a Changeset
containing the reverse operations for the reverted blocks:

```python
# Chain.add_message returns:
Changeset([
    RESTORE_TX("abc1", tx_data),   # Mempool: put back reverted tx
    RESTORE_TX("abc2", tx_data),
    DEBIT_BALANCE("miner_old", 10), # Ledger: undo old miner reward
    CREDIT_BALANCE("miner_new", 10), # Ledger: apply new miner reward
])
```

Each downstream object processes only the operations it recognizes and
ignores the rest. This is type-safe, auditable, and naturally reversible.

- [ ] Design `Operation` base type (name, params, reverse)
- [ ] Design `Changeset` as `List[Operation]`
- [ ] Each SharedObject declares which operation types it handles
- [ ] Extend `add_message()` signature: `add_message(msg, changeset=None) -> Optional[Changeset]`
- [ ] Update `_process_shared_objects` in node.py to pass changeset through the pipeline
- [ ] Add reorg integration test with Chain + Ledger + Mempool

## SPECS v1

- [ ] Add `NonMerkelizedSharedObject` base class (or defaults in `SharedObject`) so
      protocols that don't need merkelized sync skip the 7 stub methods.
- [ ] Clarify behavior of P2P-only SharedObjects that return `False` from `is_valid`:
      they block all gossip messages and cause strikes if they are the only object on
      the node. Consider `is_valid` returning `True` by default or documenting the
      expected pattern for mixed gossip + P2P protocols.
- [ ] Document `accepted_message_types` in SPECS.md — the schema-level filter in
      `is_message_accepted()` that runs before SharedObjects see the message.
- [ ] Note in SPECS.md that `handle_p2p` is called on every SharedObject; objects
      that don't handle a given P2P type silently ignore it.
