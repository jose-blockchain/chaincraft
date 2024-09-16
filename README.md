# chaincraft
Educational Python library for Blockchains

## Roadmap

- [x] Gossip: Sharing JSON messages between the nodes (`SharedMessage`).
- [x] Permanent storage: the JSON messages are stored in key/value.
- [x] Discovery: Global or Local Discovery of new nodes. ALMOST DONE
- [ ] Mandatory and Optional Fields and Types: Some format for JSON, prevalidation.
- [ ] `SharedObject` list that is updated by `SharedMessages` (inside can go Linked Fields Chaining). 
- [ ] Primitives (RSA, ECSA, VDF, VRF, Signature Aggregation, LSH)
- [ ] Indexing (MongoDB-like)
- [ ] Merklelized Storage: to know quicker when some a SharedObject is broken or which index for a linear array of messages/blocks.

## `SharedMessage`

- `prevalidation(message) : boolean` with mandatory/optional fields and types.
- Test `isValid(message)` for all `SharedObjects` like Ledgers or Mempools.
- Do update for all shared objects with `addMessage(message)`.

## `SharedObject`

- `isValid(SharedMessage) : boolean`: a message `m` if valid is `all( isValid(m ) for o in sharedObject)`
- `addMessage(ShareMessage) : void`
- `isMerkelized()/hasDigest() : boolean`
- `getDigest() : SharedMessage`
- `isValidDigest() : boolean` to check if the digest for the shared object is valid.
- `gossipObject(peer,myDigest) : List(SharedMessage)` to sync the SharedObject locally, requesting more messages.
- Local `SharedObject` gossip using `hasDigest()`, `getDigest()`, `gossipObject()` and `isValidDigest()`. 

## Design Principles for Prototyping Blockchains and Protocols

- Blockchain Trilemma (Tradeoff):
    - Security
    - Scalability
    - Decentralization
- Time Synchronization (Tradeoff): having better synced time has pros and cons.
    - Totally Async (no validation of timestamps)
    - Eventually Synced (timestamps are used for some things, but you accept timestamp far away in time)
    - Bounded Synced Time (`timestamp +/- delta` are the only valid messages, where delta is 15 seconds for example).
- Identity and Anon User (Tradeoff):
    - Totally Anon Users.
    - Anon Users w/Resources (think Proof-of-Work without signatures)
    - Identified with Signatures.
    - Signature plus protocol to accept the new identity (think adding a validator to Proof-of-Stake).

## Run tests

```bash
python -m unittest discover -v -s tests
```
