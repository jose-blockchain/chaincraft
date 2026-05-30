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

import warnings
from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional

from .fees import FEE_POLICIES, BlockContext, get_fee_policy
from .fees.base import FeePolicy
from .ledger import LEDGER_MODELS, get_ledger_model
from .ledger.base import LedgerModel, LedgerState
from .mempool import MempoolPolicy, TransactionPool


class ConfigError(ValueError):
    """Raised when a blockchain configuration is invalid or self-contradictory.

    The assembly layer is deliberately permissive about *which* components you
    combine, but some parameter combinations are simply impossible (e.g. a
    per-sender mempool cap on a UTXO ledger that has no notion of a sender, or an
    EIP-1559 chain whose initial base fee sits below the policy's own floor).
    Those are caught here with an explanatory message rather than failing
    obscurely later.
    """


class ExperimentalConfigWarning(UserWarning):
    """Warns about combinations that are *allowed* but new/unstable.

    Unlike :class:`ConfigError` (which blocks impossible assemblies), this is a
    non-fatal heads-up: the configuration will run, but the combination is
    experimental, has reduced guarantees, or pairs a feature with a ledger that
    cannot fully use it. Silence it with ``warnings.filterwarnings`` if desired.
    """


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
    mempool_policy: Optional[MempoolPolicy] = None

    def validate(self) -> "BlockchainConfig":
        """Reject impossible or self-contradictory configurations.

        Returns ``self`` so it can be chained. Raises :class:`ConfigError`.
        """
        if self.ledger_model not in LEDGER_MODELS:
            raise ConfigError(
                f"unknown ledger model {self.ledger_model!r}; "
                f"available: {sorted(LEDGER_MODELS)}"
            )
        if self.fee_policy not in FEE_POLICIES:
            raise ConfigError(
                f"unknown fee policy {self.fee_policy!r}; "
                f"available: {sorted(FEE_POLICIES)}"
            )
        if self.max_transactions_per_block < 1:
            raise ConfigError(
                "max_transactions_per_block must be >= 1, got "
                f"{self.max_transactions_per_block}"
            )
        target = self.target_transactions_per_block
        if target is not None and not (1 <= target <= self.max_transactions_per_block):
            raise ConfigError(
                "target_transactions_per_block must be between 1 and "
                f"max_transactions_per_block ({self.max_transactions_per_block}), "
                f"got {target}"
            )
        if self.coinbase_reward < 0:
            raise ConfigError(
                f"coinbase_reward must be >= 0, got {self.coinbase_reward}"
            )
        if self.initial_base_fee < 0:
            raise ConfigError(
                f"initial_base_fee must be >= 0, got {self.initial_base_fee}"
            )
        for account, amount in self.genesis_allocations.items():
            if amount < 0:
                raise ConfigError(
                    f"genesis allocation for {account!r} must be >= 0, got {amount}"
                )

        # EIP-1559: the initial base fee cannot start below the policy's floor,
        # otherwise the very first block would price transactions inconsistently.
        if self.fee_policy == "eip1559":
            min_base_fee = self.fee_kwargs.get("min_base_fee", 1)
            if self.initial_base_fee < min_base_fee:
                raise ConfigError(
                    f"eip1559 requires initial_base_fee >= min_base_fee "
                    f"({min_base_fee}), got {self.initial_base_fee}"
                )

        # A per-sender mempool cap is meaningless on a UTXO ledger, which has no
        # account/sender identity to count against.
        if (
            self.ledger_model == "utxo"
            and self.mempool_policy is not None
            and self.mempool_policy.max_per_sender is not None
        ):
            raise ConfigError(
                "mempool max_per_sender is incompatible with the 'utxo' ledger "
                "(UTXO transactions have no sender identity); use the 'balance' "
                "ledger or drop max_per_sender"
            )

        self._warn_experimental()
        return self

    def _warn_experimental(self) -> None:
        """Emit non-fatal warnings for allowed-but-risky combinations."""
        # EIP-1559 base-fee burn semantics are modelled against an account
        # balance ledger; on UTXO they are not fully validated yet.
        if self.ledger_model == "utxo" and self.fee_policy == "eip1559":
            warnings.warn(
                "eip1559 on the 'utxo' ledger is experimental: base-fee burn "
                "accounting is validated for the 'balance' ledger only",
                ExperimentalConfigWarning,
                stacklevel=2,
            )

        # Replace-by-fee is keyed on (sender, nonce); UTXO transactions have
        # neither, so RBF silently has no effect there.
        if (
            self.ledger_model == "utxo"
            and self.mempool_policy is not None
            and self.mempool_policy.enable_rbf
        ):
            warnings.warn(
                "replace-by-fee has no effect on the 'utxo' ledger (no "
                "sender/nonce to match); set enable_rbf=False to silence this",
                ExperimentalConfigWarning,
                stacklevel=2,
            )

        # All base fee is burned under EIP-1559; with no block reward, miners are
        # paid only by tips, which can be economically unstable.
        if self.fee_policy == "eip1559" and self.coinbase_reward == 0:
            warnings.warn(
                "eip1559 with coinbase_reward=0 pays miners from tips only "
                "(base fee is burned); block production may be unincentivized",
                ExperimentalConfigWarning,
                stacklevel=2,
            )


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
        self.mempool = TransactionPool(config.mempool_policy)
        self._last_block_tx_count = 0

    # -- mempool -----------------------------------------------------------
    def submit(self, tx: Any) -> bool:
        """Add a transaction to the mempool if its fee passes the fee policy.

        Admission also respects the configured mempool policy (size, TTL,
        per-sender limits, replace-by-fee).
        """
        ctx = self._context()
        if not self.fee_policy.is_valid_fee(tx, ctx):
            return False
        return bool(self.mempool.add(tx))

    @property
    def pending(self) -> List[Any]:
        return self.mempool.pending

    def reinject(self, txs) -> List[str]:
        """Re-add transactions reverted by a reorg so they are eligible again."""
        return self.mempool.reinject(txs)

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
        selected = self.mempool.select(self.fee_policy, ctx)

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
        self.mempool.remove_included(tx_ids)

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
        self.config.validate()
        ledger = get_ledger_model(self.config.ledger_model, **self.config.ledger_kwargs)
        fee_policy = get_fee_policy(self.config.fee_policy, **self.config.fee_kwargs)
        state = ledger.genesis_state(self.config.genesis_allocations)
        return Blockchain(ledger, fee_policy, state, self.config)


def build_blockchain(config: Optional[BlockchainConfig] = None) -> Blockchain:
    """Convenience wrapper: build a chain from a config (or sensible defaults)."""
    return BlockchainBuilder(config).build()
