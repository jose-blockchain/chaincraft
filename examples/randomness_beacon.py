from typing import Dict, List, Optional, Set
import json
import hashlib
import time
import os
import threading
import sys

# Try to import from installed package first, fall back to direct imports
try:
    from chaincraft.core_objects import MerkelizedObject
    from chaincraft.shared_object import SharedObjectException
    from chaincraft.shared_message import SharedMessage
    from chaincraft.crypto_primitives.pow import ProofOfWorkPrimitive
except ImportError:
    # Add parent directory to path as fallback
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if root not in sys.path:
        sys.path.insert(0, root)
    if "chaincraft" in sys.modules:
        del sys.modules["chaincraft"]
    try:
        from chaincraft.core_objects import MerkelizedObject
    except ImportError:
        from chaincraft.shared_object import SharedObject as MerkelizedObject
    from chaincraft.shared_object import SharedObjectException
    from chaincraft.shared_message import SharedMessage
    from chaincraft.crypto_primitives.pow import ProofOfWorkPrimitive


class RandomnessBeacon(MerkelizedObject):
    # Genesis block hash - known to everyone
    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, coinbase_address=None, difficulty_bits=12):
        # Canonical chain blocks (genesis -> canonical tip).
        self.blocks: List[Dict] = []
        # All known blocks (canonical + side branches), keyed by hash.
        self.block_by_hash: Dict[str, Dict] = {}
        # Parent -> children map for fork tracking.
        self.children_by_hash: Dict[str, Set[str]] = {}
        # Current frontier tips across all known branches.
        self.tip_hashes: Set[str] = set()
        self.ledger: Dict[str, int] = (
            {}
        )  # Tracks canonical blocks mined by each address
        self.coinbase_address = coinbase_address  # This node's mining address
        # Convert difficulty_bits to difficulty value (2^difficulty_bits)
        self.difficulty = 2**difficulty_bits
        self.pow_primitive = ProofOfWorkPrimitive(difficulty=self.difficulty)
        self.block_replacement_event = (
            threading.Event()
        )  # Event to signal block replacements
        self.block_change_lock = threading.Lock()  # Lock for thread safety

        # Initialize with genesis block
        genesis_block = {
            "message_type": "BEACON_BLOCK",
            "blockHeight": 0,
            "prevBlockHash": self.GENESIS_HASH,
            "timestamp": int(time.time()),
            "coinbaseAddress": "0x0000000000000000000000000000000000000000",
            "nonce": 0,
        }
        genesis_hash = self._calculate_block_hash(genesis_block)
        genesis_block["blockHash"] = genesis_hash

        self.blocks.append(genesis_block)
        self.block_by_hash[genesis_hash] = genesis_block
        self.children_by_hash[genesis_hash] = set()
        self.tip_hashes.add(genesis_hash)

    def is_valid(self, message: SharedMessage) -> bool:
        """Validate a new block message"""
        try:
            block = message.data

            # Basic structure check
            if not isinstance(block, dict):
                return False

            # Check message type
            if block.get("message_type") != "BEACON_BLOCK":
                return False

            # Check required fields
            required_fields = [
                "blockHeight",
                "prevBlockHash",
                "timestamp",
                "coinbaseAddress",
                "nonce",
            ]
            if not all(field in block for field in required_fields):
                return False

            # Time validation: within ±15 seconds
            current_time = int(time.time())
            if abs(block["timestamp"] - current_time) > 15:
                return False

            # Genesis is fixed in this example.
            if block["blockHeight"] == 0:
                return False

            # Parent must already be known. This enables side-branch growth
            # and multi-block reorg candidates.
            prev_hash = block["prevBlockHash"]
            if prev_hash not in self.block_by_hash:
                return False

            expected_height = self.block_by_hash[prev_hash]["blockHeight"] + 1
            if block["blockHeight"] != expected_height:
                return False

            # Calculate block hash if not provided
            if "blockHash" not in block:
                block["blockHash"] = self._calculate_block_hash(block)

            # Verify PoW
            challenge = block["coinbaseAddress"] + block["prevBlockHash"]
            if not self.pow_primitive.verify_proof(
                challenge, block["nonce"], block["blockHash"]
            ):
                return False

            # All checks passed
            return True
        except Exception as e:
            print(f"Block validation error: {str(e)}")
            return False

    def add_message(self, message: SharedMessage, frontier_state=None) -> None:
        """Add a valid block, track forks, and reorg canonical chain when needed."""
        block = message.data

        # Calculate and add block hash if not already provided
        if "blockHash" not in block:
            block["blockHash"] = self._calculate_block_hash(block)

        # Check if we're already seen this block
        if block["blockHash"] in self.block_by_hash:
            return

        # Acquire lock for thread safety
        with self.block_change_lock:
            parent_hash = block["prevBlockHash"]
            block_hash = block["blockHash"]

            # Track new block in the full fork graph.
            self.block_by_hash[block_hash] = block
            self.children_by_hash.setdefault(parent_hash, set()).add(block_hash)
            self.children_by_hash.setdefault(block_hash, set())
            self.tip_hashes.add(block_hash)
            self.tip_hashes.discard(parent_hash)

            current_tip_hash = self.blocks[-1]["blockHash"]
            if not self._is_better_candidate(block_hash, current_tip_hash):
                return

            new_chain = self._build_chain_to_tip(block_hash)
            if not new_chain:
                return

            old_tip_hash = current_tip_hash
            self.blocks = new_chain
            self._rebuild_ledger_from_canonical()
            self.block_replacement_event.set()

            if old_tip_hash != block_hash:
                old_short = old_tip_hash[:8]
                new_short = block_hash[:8]
                print(
                    "Canonical chain updated: "
                    f"{old_short}... -> {new_short}... (height {len(self.blocks)-1})"
                )

    def _is_better_candidate(self, candidate_hash: str, current_hash: str) -> bool:
        candidate = self.block_by_hash.get(candidate_hash)
        current = self.block_by_hash.get(current_hash)
        if not candidate or not current:
            return False

        candidate_height = int(candidate["blockHeight"])
        current_height = int(current["blockHeight"])
        if candidate_height > current_height:
            return True
        if candidate_height < current_height:
            return False

        # Tie-break at same height: lower hash wins.
        return candidate_hash < current_hash

    def _build_chain_to_tip(self, tip_hash: str) -> List[Dict]:
        chain_reversed: List[Dict] = []
        cursor = self.block_by_hash.get(tip_hash)
        while cursor is not None:
            chain_reversed.append(cursor)
            if cursor["blockHeight"] == 0:
                break
            parent_hash = cursor["prevBlockHash"]
            cursor = self.block_by_hash.get(parent_hash)

        if not chain_reversed or chain_reversed[-1]["blockHeight"] != 0:
            return []
        chain = list(reversed(chain_reversed))
        for i in range(1, len(chain)):
            expected_height = chain[i - 1]["blockHeight"] + 1
            if chain[i]["blockHeight"] != expected_height:
                return []
        return chain

    def _rebuild_ledger_from_canonical(self) -> None:
        self.ledger = {}
        for block in self.blocks[1:]:
            addr = block["coinbaseAddress"]
            self.ledger[addr] = self.ledger.get(addr, 0) + 1

    def wait_for_block_change(self, timeout=None):
        """Wait for a block replacement event"""
        result = self.block_replacement_event.wait(timeout)
        self.block_replacement_event.clear()
        return result

    def _calculate_block_hash(self, block):
        """Calculate hash of a block header"""
        # Create a copy without blockHash field
        block_copy = block.copy()
        block_copy.pop("blockHash", None)

        # Sort keys for consistent serialization
        block_json = json.dumps(block_copy, sort_keys=True)
        return hashlib.sha256(block_json.encode()).hexdigest()

    def is_merkelized(self) -> bool:
        """Indicate this is a merklelized object for syncing"""
        return True

    def get_latest_digest(self) -> str:
        """Return the hash of the latest block for sync"""
        if not self.blocks:
            return self.GENESIS_HASH
        return self.blocks[-1]["blockHash"]

    def get_state_digests(self) -> List[str]:
        """
        SPECS v2 frontier: canonical digest window + all known branch tips.
        This allows downstream objects to detect multi-block reorgs.
        """
        canonical_window = [block["blockHash"] for block in self.blocks[-8:]]
        extras = sorted(h for h in self.tip_hashes if h not in canonical_window)
        return canonical_window + extras

    def has_digest(self, hash_digest: str) -> bool:
        """Check if we have a block with the given hash"""
        return hash_digest in self.block_by_hash

    def is_valid_digest(self, hash_digest: str) -> bool:
        """Verify if a digest is valid for this chain"""
        # Check if this hash is in our known blocks
        return hash_digest in self.block_by_hash

    def add_digest(self, hash_digest: str) -> bool:
        """Add a digest directly (used in merkle sync)"""
        # Not needed as we add blocks through add_message
        return False

    def gossip_object(self, digest) -> List[SharedMessage]:
        """Return messages from the given digest to the latest"""
        if not self.has_digest(digest):
            return []

        # Find index of the block with this digest
        start_idx = None
        for i, block in enumerate(self.blocks):
            if block["blockHash"] == digest:
                start_idx = i
                break

        # If digest is known but not on canonical chain, return no delta.
        if start_idx is None:
            return []

        # Return all subsequent blocks as messages
        result = []
        for i in range(start_idx + 1, len(self.blocks)):
            result.append(SharedMessage(data=self.blocks[i]))

        return result

    def get_messages_since_digest(self, digest: str) -> List[SharedMessage]:
        """Same as gossip_object for this implementation"""
        return self.gossip_object(digest)

    def create_block(self, nonce=None):
        """Create a new block (used for mining)"""
        if not self.coinbase_address:
            raise SharedObjectException("No coinbase address set for mining")

        with self.block_change_lock:
            prev_block = self.blocks[-1]

            # Double-check that we're mining at the right height
            next_height = len(self.blocks)

            block = {
                "message_type": "BEACON_BLOCK",
                "blockHeight": next_height,
                "prevBlockHash": prev_block["blockHash"],
                "timestamp": int(time.time()),
                "coinbaseAddress": self.coinbase_address,
                "nonce": nonce or 0,
            }

            if nonce is not None:
                # If nonce provided, calculate hash and add it
                block["blockHash"] = self._calculate_block_hash(block)

            return block

    def mine_block(self):
        """Mine a new block with PoW"""
        if not self.coinbase_address:
            raise SharedObjectException("No coinbase address set for mining")

        # Create block template
        block = self.create_block()

        # Calculate PoW
        challenge = block["coinbaseAddress"] + block["prevBlockHash"]
        nonce, block_hash = self.pow_primitive.create_proof(challenge)

        # Update block with nonce and hash
        block["nonce"] = nonce
        block["blockHash"] = block_hash

        return block

    def get_random_number(self, block_hash=None):
        """
        Get a random number derived from a block hash
        If block_hash is None, uses the latest block hash
        """
        if block_hash is None:
            if not self.blocks:
                return 0
            block_hash = self.blocks[-1]["blockHash"]

        # Convert hash to a number between 0 and 1
        hash_int = int(block_hash, 16)
        max_int = 2 ** (len(block_hash) * 4)  # 4 bits per hex character
        return hash_int / max_int

    def get_random_int(self, min_val, max_val, block_hash=None):
        """Get a random integer in the specified range"""
        random_val = self.get_random_number(block_hash)
        return min_val + int(random_val * (max_val - min_val + 1))


def generate_eth_address():
    """Generate an Ethereum-style address (simplified)"""
    # Generate a random private key
    private_key = os.urandom(32)

    # Hash it to simulate derivation of Ethereum address
    address_bytes = hashlib.sha256(private_key).digest()[-20:]
    return "0x" + address_bytes.hex()


class BeaconMiner:
    """Class to handle mining blocks for the RandomnessBeacon"""

    def __init__(self, node, beacon_obj, mining_interval=10):
        """
        Initialize the miner

        node: ChaincraftNode - the node to broadcast from
        beacon_obj: RandomnessBeacon - the shared object
        mining_interval: int - seconds between mining attempts
        """
        self.node = node
        self.beacon = beacon_obj
        self.mining_interval = mining_interval
        self.running = False
        self.restart_mining = False

    def start(self):
        """Start the mining process in a background thread"""
        self.running = True
        self.thread = threading.Thread(target=self._mine_loop, daemon=True)
        self.thread.start()

        # Start a parallel thread to watch for block changes
        self.watcher_thread = threading.Thread(
            target=self._watch_for_changes, daemon=True
        )
        self.watcher_thread.start()

    def stop(self):
        """Stop the mining process"""
        self.running = False

    def _watch_for_changes(self):
        """Watch for block chain changes and trigger mining restarts"""
        while self.running:
            # Wait for a block change event
            if self.beacon.wait_for_block_change(timeout=0.5):
                print("Miner detected block change, flagging for restart")
                self.restart_mining = True

    def _mine_loop(self):
        """Main mining loop"""
        miner_address = self.beacon.coinbase_address
        short_address = miner_address[:8] + "..." if miner_address else "unknown"
        print(f"Miner {short_address} starting mining loop")

        while self.running:
            try:
                # Check if we need to restart mining due to chain changes
                if self.restart_mining:
                    print(
                        f"Miner {short_address} restarting mining process due to chain update"
                    )
                    self.restart_mining = False
                    continue  # Skip to next iteration with fresh state

                # Make sure we're working on the correct height
                next_height = len(self.beacon.blocks)
                prev_hash = self.beacon.blocks[-1]["blockHash"]

                # Mine a block
                block = self.beacon.mine_block()

                # Double-check that the chain hasn't changed while mining
                current_height = len(self.beacon.blocks)
                current_top_hash = self.beacon.blocks[-1]["blockHash"]

                if current_height != next_height or current_top_hash != prev_hash:
                    print(
                        f"Miner {short_address}: Chain changed while mining, discarding block"
                    )
                    continue

                # Broadcast the block
                try:
                    self.node.create_shared_message(block)
                    h = block["blockHeight"]
                    hsh = block["blockHash"][:8]
                    print(
                        f"Miner {short_address} found block at height {h} with hash {hsh}..."
                    )
                except SharedObjectException as e:
                    # The block might have been replaced while we were mining
                    print(
                        f"Miner {short_address}: Block rejected (chain may have changed): {e}"
                    )

            except Exception as e:
                print(f"Mining error for {short_address}: {str(e)}")

            # Wait for next interval
            time.sleep(self.mining_interval)
