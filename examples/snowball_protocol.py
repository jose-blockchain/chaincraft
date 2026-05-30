#!/usr/bin/env python3
"""Snowball protocol (Avalanche family).

The implementation now lives in :mod:`chaincraft.consensus.gossip.avalanche` as
part of the 0.6.0 core consensus framework. This module is kept as a thin
re-export for backward compatibility with existing imports and scripts.
"""

from chaincraft.consensus.gossip.avalanche import (
    Color,
    SnowballObject,
    SnowballNode,
    run_snowball_nodes,
    COLORS,
)

__all__ = [
    "Color",
    "SnowballObject",
    "SnowballNode",
    "run_snowball_nodes",
    "COLORS",
]


if __name__ == "__main__":
    run_snowball_nodes()
