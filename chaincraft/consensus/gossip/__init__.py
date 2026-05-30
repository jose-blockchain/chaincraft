"""Gossip-based consensus family (randomized sampling, virtual voting).

Examples: Avalanche (Slush/Snowflake/Snowball), Hashgraph. The existing
``examples/`` Avalanche protocols are migrated here under a shared base
(tracked separately).
"""

from ..base import CATEGORY_GOSSIP, ConsensusEngine


class GossipConsensus(ConsensusEngine):
    """Base class for gossip / sampling consensus engines."""

    category = CATEGORY_GOSSIP


from .relay import RelayProposalConsensus  # noqa: E402  (registers the engine)
from .avalanche import (  # noqa: E402
    BinarySamplingConsensus,
    Color,
    SlushObject,
    SnowflakeObject,
    SnowballObject,
    SnowballNode,
    run_slush_nodes,
    run_snowflake_nodes,
    run_snowball_nodes,
    COLORS,
)

__all__ = [
    "GossipConsensus",
    "RelayProposalConsensus",
    "BinarySamplingConsensus",
    "Color",
    "SlushObject",
    "SnowflakeObject",
    "SnowballObject",
    "SnowballNode",
    "run_slush_nodes",
    "run_snowflake_nodes",
    "run_snowball_nodes",
    "COLORS",
]
