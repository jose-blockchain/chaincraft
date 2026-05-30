"""BFT / quorum consensus family.

Examples: PBFT, Tendermint, HotStuff. Migration of the example Tendermint BFT
engine is tracked separately.
"""

from ..base import CATEGORY_BFT, ConsensusEngine


class BFTConsensus(ConsensusEngine):
    """Base class for quorum-based BFT consensus engines."""

    category = CATEGORY_BFT


__all__ = ["BFTConsensus"]
