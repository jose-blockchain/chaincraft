"""Declarative blockchain assembly (Chaincraft 0.6.0).

``BlockchainConfig`` captures the interchangeable parts of a chain (ledger
model, fee market, block limits, reward schedule, genesis allocations) and
``BlockchainBuilder`` wires them into a working ``Blockchain`` engine. Swapping
a ledger model or fee policy is a one-line config change rather than a code
edit.

This module is intentionally transport-agnostic: it produces blocks from a local
mempool and applies them to ledger state. Wiring the engine onto a
``ChaincraftNode`` and a consensus engine is handled by the consensus framework
(tracked separately for 0.6.0).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from .fees import BlockContext, get_fee_policy
from .fees.base import FeePolicy
from .ledger import get_ledger_model
from .ledger.base import LedgerModel, LedgerState


@dataclass
class BlockchainConfig:
    """The interchangeable parts of a blockchain assembly."""

    ledger_model: str = "balance"
    fee_policy: str = "highest_first"
    max_transactions_per_block: int = 10
    target_transactions_per_block: Optional[int] = None
    coinbase_reward: int = 50
    initial_base_fee: int = 0
    genesis_allocations: Mapping[str, int] = field(default_factory=dict)
    ledger_kwargs: Mapping[str, Any] = field(default_factory=dict)
    fee_kwargs: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class Block:
    index: int
    miner: Optional[str]
    tx_ids: List[str]
    base_fee: int
    total_burned: int
    total_tips: int
    state_snapshot: Mapping[str, Any]


class Blockchain:
    """A minimal, fully pluggable chain engine driven by a config."""

    def __init__(
        self,
        ledger: LedgerModel,
        fee_policy: FeePolicy,
        state: LedgerState,
        config: BlockchainConfig,
    ):
        self.ledger = ledger
        self.fee_policy = fee_policy
        self.state = state
        self.config = config
        self.base_fee = config.initial_base_fee
        self.blocks: List[Block] = []
        self._mempool: Dict[str, Any] = {}
        self._last_block_tx_count = 0

    # -- mempool -----------------------------------------------------------
    def submit(self, tx: Any) -> bool:
        """Add a transaction to the local mempool if its fee is acceptable."""
        ctx = self._context()
        if not self.fee_policy.is_valid_fee(tx, ctx):
            return False
        self._mempool[tx.tx_id] = tx
        return True

    @property
    def pending(self) -> List[Any]:
        return list(self._mempool.values())

    # -- block production --------------------------------------------------
    def _context(self) -> BlockContext:
        return BlockContext(
            max_transactions=self.config.max_transactions_per_block,
            base_fee=self.base_fee,
            target_transactions=self.config.target_transactions_per_block,
            parent_tx_count=self._last_block_tx_count,
        )

    def produce_block(self, miner: Optional[str] = None) -> Block:
        """Select transactions, apply them with fees, and append a block."""
        ctx = self._context()
        selected = self.fee_policy.select_for_block(self.pending, ctx)

        charges = [self.fee_policy.effective_charge(tx, ctx) for tx in selected]
        total_burned = sum(c.burned for c in charges)
        total_tips = sum(c.tip for c in charges)

        self.state = self.ledger.apply_block(
            selected,
            self.state,
            charges=charges,
            miner=miner,
            coinbase_reward=self.config.coinbase_reward,
        )

        tx_ids = [tx.tx_id for tx in selected]
        for tx_id in tx_ids:
            self._mempool.pop(tx_id, None)

        block = Block(
            index=len(self.blocks),
            miner=miner,
            tx_ids=tx_ids,
            base_fee=self.base_fee,
            total_burned=total_burned,
            total_tips=total_tips,
            state_snapshot=self.state.to_snapshot(),
        )
        self.blocks.append(block)

        # Advance base fee for the next block based on this block's fullness.
        self._last_block_tx_count = len(tx_ids)
        self.base_fee = self.fee_policy.next_base_fee(self._context())
        return block

    # -- queries -----------------------------------------------------------
    def balance_of(self, account: str) -> int:
        return self.state.balance_of(account)

    def total_supply(self) -> int:
        return self.state.total_supply()


class BlockchainBuilder:
    """Builds a :class:`Blockchain` from a :class:`BlockchainConfig`."""

    def __init__(self, config: Optional[BlockchainConfig] = None):
        self.config = config or BlockchainConfig()

    def build(self) -> Blockchain:
        ledger = get_ledger_model(self.config.ledger_model, **self.config.ledger_kwargs)
        fee_policy = get_fee_policy(self.config.fee_policy, **self.config.fee_kwargs)
        state = ledger.genesis_state(self.config.genesis_allocations)
        return Blockchain(ledger, fee_policy, state, self.config)


def build_blockchain(config: Optional[BlockchainConfig] = None) -> Blockchain:
    """Convenience wrapper: build a chain from a config (or sensible defaults)."""
    return BlockchainBuilder(config).build()
