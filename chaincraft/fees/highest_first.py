"""Highest-fee-first inclusion: the whole declared fee is paid to the miner."""

from __future__ import annotations

from typing import Any, List, Sequence

from ..ledger.base import FeeCharge
from .base import BlockContext, FeePolicy, _fee_of


class HighestFeeFirst(FeePolicy):
    """Order candidates by descending fee; charge the full fee as a tip."""

    name = "highest_first"

    def is_valid_fee(self, tx: Any, ctx: BlockContext) -> bool:
        return _fee_of(tx) >= 0

    def select_for_block(
        self, candidates: Sequence[Any], ctx: BlockContext
    ) -> List[Any]:
        ranked = sorted(candidates, key=_fee_of, reverse=True)
        return ranked[: ctx.max_transactions]

    def effective_charge(self, tx: Any, ctx: BlockContext) -> FeeCharge:
        fee = _fee_of(tx)
        return FeeCharge(charged=fee, burned=0, tip=fee)
