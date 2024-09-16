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

## Run tests

```bash
python -m unittest discover -v -s tests
```
