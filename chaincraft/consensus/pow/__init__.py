"""Proof-of-work consensus family.

Examples: SHA-256 proof-of-work longest/heaviest chain, and verifiable-delay
(VDF) linear-work variants. Migration of the example PoW chain and randomness
beacon is tracked separately.
"""

from ..base import CATEGORY_POW, ConsensusEngine


class PoWConsensus(ConsensusEngine):
    """Base class for proof-of-work style consensus engines."""

    category = CATEGORY_POW


__all__ = ["PoWConsensus"]
