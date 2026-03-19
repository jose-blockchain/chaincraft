# Chaincraft Python — TODO

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
