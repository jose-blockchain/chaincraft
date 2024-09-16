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

- `prevalidation(message) : boolean` with mandatory/optional fields and types.
- Test `isValid(message)` for all `SharedObjects` like Ledgers or Mempools.
- Do update for all shared object with `addMessage(message)`.

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
- Time Syncronization (Tradeoff): having better synced time has pros and cons.
    - Totally Asynced (no validation of timestamps)
    - Eventually Synced (timestamps are used for some things, but you accept timestamp far away in time)
    - Bounded Synced Time (t +/- delta are only valid messages, where delta is 15 seconds for example).

## Run tests

```bash
python -m unittest discover -v -s tests
```
