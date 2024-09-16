# chaincraft
Educational Python library for Blockchains

## Roadmap

- [x] Gossip: Sharing JSON messages between the nodes (`SharedMessage`).
- [x] Permanent storage: the JSON messages are stored in key/value.
- [x] Discovery: Global or Local Discovery of new nodes. ALMOST DONE
- [ ] Mandatory and Optional Fields and Types: Some format for JSON, prevalidation.
- [ ] `SharedObject` list that is updated by `SharedMessages` (inside can go Linked Fields Chaining).
- [ ] Indexing (MongoDB-like)
- [ ] Merkle Patricia Trie: quickly read and update a large chain of messages. HERE
- [ ] Primitives (RSA, ECSA, VDF, VRF, Signature Aggregation, LSH)

## `SharedMessage`

- `prevalidation() : boolean` with mandatory/optional fields and types.
- 

## `SharedObject`

- `isValid(SharedMessage) : boolean`
- `addMessage(ShareMessage) : void`
- `isMerkelized()/hasDigest() : boolean`
- `getDigest() : Hash`

## Design Principles

- Blockchain Trilemma: Security, Scalability and Decentralization (Tradeoff)
- Time Syncronization: Totally Async, Eventually Sync, Bounded Sync time (t + delta, where delta is 15 seconds for example).

## Run tests

```bash
python -m unittest discover -v -s tests
```
