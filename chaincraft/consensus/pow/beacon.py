#!/usr/bin/env python3
"""Randomness-beacon proof-of-work consensus - core engine.

A PoW chain whose canonical tip hash is a verifiable randomness output. Each
block header is mined with challenge ``coinbase + parent_hash`` (matching the
teaching implementation in ``examples/randomness_beacon.py``). Fork choice uses
:class:`ForkAwareChain` (longest chain, deterministic hash tie-break).

The networked mining-loop demo remains in ``examples/``; this engine is
transport-agnostic and unit-testable via :meth:`propose`, :meth:`observe`, and
:meth:`random_float` / :meth:`random_int`.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, Mapping, Optional

from ...crypto_primitives.pow import ProofOfWorkPrimitive
from ..base import ConsensusError, UnstableConsensusWarning, message_data
from ..registry import register_consensus
from . import PoWConsensus
from .chain import ForkAwareChain

MESSAGE_TAG = "beacon"
GENESIS_HASH = "0" * 64


def block_hash(header: Mapping[str, Any]) -> str:
    """Canonical SHA-256 of a beacon block header (excluding the hash/id)."""
    body = {k: v for k, v in header.items() if k not in ("id", "blockHash")}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, default=str).encode()
    ).hexdigest()


def pow_challenge(coinbase: str, parent: str) -> str:
    return coinbase + parent


@register_consensus
class RandomnessBeaconConsensus(PoWConsensus):
    """PoW randomness beacon: decided value is a buried canonical block hash."""

    name = "beacon"

    def __init__(
        self,
        difficulty: int = 256,
        difficulty_bits: Optional[int] = None,
        coinbase: str = "0x0",
        confirmations: int = 1,
        max_timestamp_skew: Optional[int] = 15,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        if difficulty_bits is not None:
            if difficulty_bits < 1:
                raise ConsensusError(
                    f"difficulty_bits must be >= 1, got {difficulty_bits}"
                )
            difficulty = 2**difficulty_bits
        if difficulty < 1:
            raise ConsensusError(f"difficulty must be >= 1, got {difficulty}")
        if confirmations < 1:
            raise ConsensusError(f"confirmations must be >= 1, got {confirmations}")
        if difficulty >= 2**20:
            import warnings

            warnings.warn(
                f"beacon difficulty={difficulty} is very high; mining may be "
                "impractically slow in tests (consider difficulty_bits <= 16)",
                UnstableConsensusWarning,
                stacklevel=2,
            )
        self.difficulty = difficulty
        self.confirmations = confirmations
        self.coinbase = coinbase
        self.max_timestamp_skew = max_timestamp_skew
        self.pow = ProofOfWorkPrimitive(difficulty=difficulty)
        self.chain = ForkAwareChain(GENESIS_HASH, height=0, work=0)
        self._blocks: Dict[str, Dict[str, Any]] = {
            GENESIS_HASH: self._genesis_block()
        }
        self.last_result = None
        self._ledger: Dict[str, int] = {}

    @staticmethod
    def _genesis_block() -> Dict[str, Any]:
        return {
            "message_type": "BEACON_BLOCK",
            "blockHeight": 0,
            "prevBlockHash": GENESIS_HASH,
            "timestamp": 0,
            "coinbaseAddress": "0x" + "0" * 40,
            "nonce": 0,
            "id": GENESIS_HASH,
            "blockHash": GENESIS_HASH,
        }

    # -- mining / verification ---------------------------------------------
    def mine(self, timestamp: Optional[int] = None) -> Dict[str, Any]:
        """Mine a block extending the current canonical tip."""
        parent = self.chain.tip
        height = self.chain.height + 1
        ts = int(time.time()) if timestamp is None else timestamp
        header = {
            "message_type": "BEACON_BLOCK",
            "blockHeight": height,
            "prevBlockHash": parent,
            "timestamp": ts,
            "coinbaseAddress": self.coinbase,
            "nonce": 0,
        }
        challenge = pow_challenge(self.coinbase, parent)
        nonce, mined_hash = self.pow.create_proof(challenge)
        header["nonce"] = nonce
        header["id"] = mined_hash
        header["blockHash"] = mined_hash
        return header

    def _verify(self, block: Dict[str, Any]) -> bool:
        try:
            height = block["blockHeight"]
            parent = block["prevBlockHash"]
            coinbase = block["coinbaseAddress"]
            nonce = block["nonce"]
            bid = block.get("id") or block.get("blockHash")
        except (KeyError, TypeError):
            return False
        if height == 0:
            return False
        if not self.chain.contains(parent):
            return False
        if height != self.chain.block_height(parent) + 1:
            return False
        if self.max_timestamp_skew is not None:
            if abs(int(block["timestamp"]) - int(time.time())) > self.max_timestamp_skew:
                return False
        challenge = pow_challenge(coinbase, parent)
        return self.pow.verify_proof(challenge, nonce, bid)

    def _ingest(self, block: Dict[str, Any]) -> None:
        bid = block.get("id") or block.get("blockHash")
        if bid is None or self.chain.contains(bid):
            return
        self._blocks[bid] = dict(block)
        self.last_result = self.chain.add_block(bid, block["prevBlockHash"], work=1)
        self._rebuild_ledger()

    def _rebuild_ledger(self) -> None:
        self._ledger = {}
        for bid in self.chain.canonical_ids()[1:]:
            addr = self._blocks[bid]["coinbaseAddress"]
            self._ledger[addr] = self._ledger.get(addr, 0) + 1

    # -- randomness --------------------------------------------------------
    def finalized_height(self) -> int:
        return self.chain.height - self.confirmations

    def finalized_block_id(self) -> Optional[str]:
        h = self.finalized_height()
        if h < 1:
            return None
        return self.chain.canonical_ids()[h]

    def random_float(self, block_id: Optional[str] = None) -> float:
        """Map a block hash to a uniform float in [0, 1)."""
        bid = block_id or self.finalized_block_id() or self.chain.tip
        if bid == GENESIS_HASH:
            return 0.0
        value = int(bid, 16)
        return value / float(16 ** len(bid))

    def random_int(self, low: int, high: int, block_id: Optional[str] = None) -> int:
        if low > high:
            raise ValueError("low must be <= high")
        span = high - low + 1
        return low + int(self.random_float(block_id) * span) % span

    def blocks_mined_by(self, address: str) -> int:
        return self._ledger.get(address, 0)

    # -- ConsensusEngine interface -----------------------------------------
    def propose(self, value: Any = None) -> None:
        ts = int(value) if isinstance(value, int) else None
        block = self.mine(timestamp=ts)
        self.broadcast({"consensus": MESSAGE_TAG, "op": "block", "block": block})
        self._ingest(block)

    def observe(self, message: Any) -> None:
        data = message_data(message)
        if not isinstance(data, dict):
            return
        # Accept both wrapped engine messages and raw beacon blocks (toy compat).
        if data.get("consensus") == MESSAGE_TAG and data.get("op") == "block":
            block = data.get("block")
        elif data.get("message_type") == "BEACON_BLOCK":
            block = data
        else:
            return
        if isinstance(block, dict) and self._verify(block):
            self._ingest(block)

    def is_valid(self, message: Any) -> bool:
        data = message_data(message)
        if not isinstance(data, dict):
            return False
        if data.get("consensus") == MESSAGE_TAG and data.get("op") == "block":
            return self._verify(data.get("block", {}))
        if data.get("message_type") == "BEACON_BLOCK":
            return self._verify(data)
        return False

    def is_decided(self) -> bool:
        return self.finalized_height() >= 1

    def decision(self) -> Optional[str]:
        return self.finalized_block_id()

    def tip(self) -> str:
        return self.chain.tip

    def canonical_blocks(self) -> list:
        return [self._blocks[bid] for bid in self.chain.canonical_ids()]
