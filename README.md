# chaincraft

Chaincraft: The platform for blockchain education and prototyping

## Roadmap

- [x] Gossip: Sharing JSON messages between the nodes (`SharedMessage`).
- [x] Permanent storage: the JSON messages are stored in key/value.
- [x] Discovery: Global or Local Discovery of new nodes.
- [x] Mandatory and Optional Fields and Types: Some format for JSON, prevalidation. Ban peers sending invalid format.
- [x] `SharedObject` list that is updated by `SharedMessages` (inside can go Linked Fields Chaining). Ban peers sending invalid messages.
- [x] Merklelized Storage: to know quicker when some a SharedObject is broken or which index for a linear array of messages/blocks.
- [ ] Primitives (RSA, ECSA, VDF, VRF, Signature Aggregation, LSH, Quantum-resistant Primitives)
- [ ] Indexing (MongoDB-like)

## `SharedMessage`

- `prevalidation(message) : boolean` with mandatory/optional fields and types.
- Test `isValid(message)` for all `SharedObjects` like Ledgers or Mempools.
- Do update for all shared objects with `addMessage(message)`.

## `SharedObject`

- `isValid(SharedMessage) : boolean`: a message `m` if valid is `all( isValid(m ) for o in sharedObject)`
- `addMessage(ShareMessage) : void`: is "added" to all ShredObjects if is valid like `[o.addMessage(m) for o in sharedObject]`
- `isMerkelized()/hasDigest() : boolean`
- `getDigest() : SharedMessage`
- `isValidDigest() : boolean` to check if the digest for the shared object is valid.
- `gossipObject(peer,myDigest) : List(SharedMessage)` to sync the SharedObject locally, requesting more messages.
- Local `SharedObject` gossip using `hasDigest()`, `getDigest()`, `gossipObject()` and `isValidDigest()`. 

# Example (Bitcoin)

- The shared object are `Ledger` and `Mempool`.
- A bitcoin transaction `tx` is only a transfer for simplicity.
- Example: `Ledger.isValid(tx)` is `true` if the sender has enough balance in account to do the transfer.
- Example `Mempool.addMessage(tx)` will do a sorted insert into the priority queue of `Mempool` based on the fee that the sender is paying, higher fees gets more priority to be included in the next block of transactions.

## Design Principles for Prototyping Blockchains and Protocols

- Blockchain Trilemma (Tradeoff):
    - Security
    - Scalability
    - Decentralization
- Time Synchronization (Tradeoff): having better synced time has pros and cons.
    - Totally Async (no validation of timestamps)
    - Eventually Synced (timestamps are used for some things, but you accept timestamp far away in time)
    - Bounded Synced Time (`timestamp +/- delta` are the only valid messages, where delta is 15 seconds for example).
    - Totally Time-synced, like depend on time being totally synced.
- Identity and Anon User (Tradeoff):
    - Totally Anon Users.
    - Anon Users w/Resources (think Proof-of-Work without signatures)
    - Identified with Signatures.
    - Signature plus protocol to accept the new identity (think adding a validator to Proof-of-Stake).
- Levels of Data Synchronization:
    - Torrent: very liberal and concurrent.
    - Blockchain: very restrictive and sequential.
    - Middle-ground: decentralized app (non-financial)
        - Eventually consistent.
        - All data is validated.
        - Example1: Decentralized Messenger (santi).
        - Example2: Decentralized AI

## Brainstorming in DeAI

- Prededetemined Training Sample Blocks List: B1, B2, ..., Bn..
- Eventually: block Bi is processed.
- Is Okey if Bn is processed and validated and distributed and B(n-1) is not yet available.
- Alternative: a node can propose Bn if is missing, Bn-1 is known, or wants to replace existing Bn.


## Run tests

Run all tests:

```bash
python -m unittest discover -v -s tests
```

Result:
```bash
...
----------------------------------------------------------------------
Ran 38 tests in 61.963s

OK
```

A single testfile:

```bash
python -m unittest tests/test_start.py
```

To run a single test inside a testfile:

```bash
python -m unittest -v -k test_local_discovery_enabled tests/test_local_discovery.py
```

## Example Usage of Primitives

Here are a few code snippets to illustrate how you might use the different primitives:

### Proof-of-Work (PoW)

```python
from crypto_primitives.pow import ProofOfWorkPrimitive

# Initialize PoW with desired difficulty
pow_primitive = ProofOfWorkPrimitive(difficulty_bits=12)

challenge = "Hello, Chaincraft!"
nonce, hash_hex = pow_primitive.create_proof(challenge)
print("Found nonce:", nonce)
print("Hash:", hash_hex)

# Verify the proof
is_valid = pow_primitive.verify_proof(challenge, nonce, hash_hex)
print("Proof valid?", is_valid)
```

### Verifiable Delay Function (VDF)

```python
from crypto_primitives.vdf import VDFPrimitive

# A simple, mock VDF with a set number of iterations
vdf_primitive = VDFPrimitive(iterations=5000)

input_data = "chaincraft_vdf_challenge"
proof = vdf_primitive.create_proof(input_data)
print("VDF proof:", proof)

# Verify the proof by recomputing
verification = vdf_primitive.verify_proof(input_data, proof)
print("VDF verified:", verification)
```

### ECDSA (Signing/Verification)

```python
from crypto_primitives.ecdsa_sign import ECDSASignaturePrimitive

# Create and store an ECDSA key pair
ecdsa_primitive = ECDSASignaturePrimitive()
ecdsa_primitive.generate_key()

message = b"Sample data for signing"
signature = ecdsa_primitive.sign(message)
print("Signature (hex):", signature.hex())

# Verification
verified = ecdsa_primitive.verify(message, signature)
print("Signature verified?", verified)
```

### ECDSA-based VRF (Verifiable Random Function)

```python
from crypto_primitives.vrf import ECDSAVRFPrimitive

# Create an ECDSA VRF key pair
vrf_primitive = ECDSAVRFPrimitive()
vrf_primitive.generate_key()

message = b"VRF input"
proof = vrf_primitive.sign(message)  # ECDSA signature as proof
print("VRF proof (signature hex):", proof.hex())

# Verify and generate VRF output (pseudo-randomness)
is_valid = vrf_primitive.verify(message, proof)
vrf_output = vrf_primitive.vrf_output(message, proof) if is_valid else None
print("VRF verified?", is_valid)
print("VRF output (hash of signature):", vrf_output.hex() if vrf_output else None)
```

Combine these primitives as needed in your blockchain or decentralized application logic, for example to create a PoW-based consensus, to prove time delays (VDF), or to sign/verify transactions or blocks (ECDSA/VRF).
