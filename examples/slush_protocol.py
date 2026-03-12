#!/usr/bin/env python3
"""
Slush protocol from the Avalanche paper (Snowflake to Avalanche).
Avalanche.md Section 2.2 - toy single-decree consensus, NOT Byzantine fault tolerant.

Nodes converge on binary choice (RED or BLUE) via repeated sampling: sample k peers,
adopt color when >= alpha*k responses agree, run m rounds, then accept.

Uses ChaincraftNode and UDP: SlushObject is a SharedObject added to the node.
Chaincraft node dispatches SLUSH_QUERY/SLUSH_RESPONSE to handle_slush_* methods.
"""

import json
import logging
import random
import threading
import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

import os
import sys

try:
    from chaincraft.shared_object import SharedObject
    from chaincraft.shared_message import SharedMessage
except ImportError:
    _root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if _root not in sys.path:
        sys.path.insert(0, _root)
    if os.getcwd() not in sys.path:
        sys.path.insert(0, os.getcwd())
    from chaincraft.shared_object import SharedObject
    from chaincraft.shared_message import SharedMessage


class Color(Enum):
    """Binary choice: Red or Blue (paper R/B)."""

    RED = "R"
    BLUE = "B"
    UNCOLORED = "⊥"


# Type for ChaincraftNode (avoid circular import)
NodeT = Any


class SlushObject(SharedObject):
    """
    Slush consensus as SharedObject. Inherits from Chaincraft SharedObject,
    uses node.send_to_peer for UDP queries/responses.
    """

    MSG_QUERY = "SLUSH_QUERY"
    MSG_RESPONSE = "SLUSH_RESPONSE"

    def __init__(
        self,
        node: NodeT,
        k: int = 10,
        alpha: float = 0.5,
        m: int = 10,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        self.node = node
        self.k = k
        self.alpha = alpha
        self.m = m
        self._log = log_fn or (lambda msg: logging.info(msg))
        self._color = Color.UNCOLORED
        self._accepted: Optional[Color] = None
        self._current_round = 0
        self._pending: Dict[int, Dict[Tuple[str, int], Color]] = {}
        self._round_done = threading.Event()
        self._lock = threading.Lock()

    def _log_node(self, msg: str) -> None:
        self._log(f"[{self.node.port}] {msg}")

    def handle_slush_query(self, addr: Tuple[str, int], data: dict) -> None:
        """onQuery: if uncolored adopt query color; respond with current color."""
        payload = data.get(self.MSG_QUERY)
        if not payload or "col" not in payload or "r" not in payload:
            return
        r = payload["r"]
        col_str = payload["col"]
        with self._lock:
            if self._color == Color.UNCOLORED:
                self._color = Color.RED if col_str == "R" else Color.BLUE
                self._log_node(f"onQuery: adopted {self._color.value} from {addr}")
            resp = {
                self.MSG_RESPONSE: {
                    "r": r,
                    "col": self._color.value,
                    "from": f"{self.node.host}:{self.node.port}",
                }
            }
        msg = json.dumps(resp)
        self.node.send_to_peer(addr, msg)

    def handle_slush_response(self, addr: Tuple[str, int], data: dict) -> None:
        """Collect response; when enough for current round, unblock slush loop."""
        payload = data.get(self.MSG_RESPONSE)
        if not payload or "r" not in payload or "col" not in payload:
            return
        r = payload["r"]
        col = Color.RED if payload["col"] == "R" else Color.BLUE
        with self._lock:
            if r not in self._pending:
                self._pending[r] = {}
            self._pending[r][addr] = col
            if len(self._pending[r]) >= self.k:
                self._round_done.set()

    def run_slush_loop(self, initial_color: Optional[Color] = None) -> Optional[Color]:
        """
        slushLoop: m rounds. Each round sample k peers, query, if >= alpha*k
        same color adopt it. Returns final accepted color or None.
        """
        if initial_color is not None:
            with self._lock:
                self._color = initial_color
            self._log_node(f"slushLoop: initial color {initial_color.value}")
        # Non-proposers wait to adopt color from an incoming SLUSH_QUERY
        wait_start = time.time()
        while self._color == Color.UNCOLORED and time.time() - wait_start < 10.0:
            time.sleep(0.05)
        if self._color == Color.UNCOLORED:
            self._log_node("slushLoop: uncolored, no proposal received (timeout)")
            return None
        peers = list(self.node.peers)
        sample_size = min(self.k, len(peers))
        if sample_size == 0:
            self._log_node("slushLoop: no peers")
            return None
        for r in range(1, self.m + 1):
            with self._lock:
                self._current_round = r
                self._pending[r] = {}
            self._round_done.clear()
            sampled = random.sample(peers, sample_size)
            for peer in sampled:
                q = {
                    self.MSG_QUERY: {
                        "r": r,
                        "col": self._color.value,
                        "from": f"{self.node.host}:{self.node.port}",
                    }
                }
                self.node.send_to_peer(peer, json.dumps(q))
            self._round_done.wait(timeout=3.0)
            with self._lock:
                responses = list(self._pending.get(r, {}).values())
            if len(responses) >= max(1, int(self.alpha * self.k)):
                counts = {Color.RED: 0, Color.BLUE: 0}
                for c in responses:
                    if c in counts:
                        counts[c] += 1
                for c in (Color.RED, Color.BLUE):
                    if counts[c] >= int(self.alpha * self.k) and c != self._color:
                        with self._lock:
                            self._color = c
                        self._log_node(f"Round {r}: flipped to {c.value}")
                        break
        with self._lock:
            self._accepted = self._color
        self._log_node(f"Slush accepted: {self._accepted.value}")
        return self._accepted

    def get_accepted(self) -> Optional[Color]:
        return self._accepted

    # SharedObject stubs (Slush uses custom messages, not SharedMessage)
    def is_valid(self, message: SharedMessage) -> bool:
        return False

    def add_message(self, message: SharedMessage) -> None:
        pass

    def is_merkelized(self) -> bool:
        return False

    def get_latest_digest(self) -> str:
        return ""

    def has_digest(self, hash_digest: str) -> bool:
        return False

    def is_valid_digest(self, hash_digest: str) -> bool:
        return False

    def add_digest(self, hash_digest: str) -> bool:
        return False

    def gossip_object(self, digest: str) -> List[SharedMessage]:
        return []

    def get_messages_since_digest(self, digest: str) -> List[SharedMessage]:
        return []


def run_slush_nodes(
    num_nodes: int = 10,
    base_port: int = 9010,
    k: int = 4,
    alpha: float = 0.5,
    m: int = 8,
    proposer_idx: int = 0,
    initial_color: Color = Color.RED,
) -> Dict[int, Optional[Color]]:
    """
    Run Slush consensus with num_nodes ChaincraftNode instances over UDP.
    Nodes connect via connect_to_peer; SlushObject handles queries/responses via UDP.
    Returns dict port -> accepted color.
    """
    try:
        from chaincraft.node import ChaincraftNode
    except ImportError:
        sys.path.insert(
            0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        )
        from chaincraft.node import ChaincraftNode

    log_fn: Callable[[str], None] = lambda msg: print(f"[Slush] {msg}")
    nodes: List[ChaincraftNode] = []
    slushes: List[SlushObject] = []

    for i in range(num_nodes):
        port = base_port + i
        node = ChaincraftNode(
            port=port,
            max_peers=num_nodes - 1,
            local_discovery=True,
        )
        slush = SlushObject(node, k=k, alpha=alpha, m=m, log_fn=log_fn)
        node.add_shared_object(slush)
        node.start()
        nodes.append(node)
        slushes.append(slush)

    for i in range(num_nodes):
        for j in range(num_nodes):
            if i != j:
                nodes[i].connect_to_peer(nodes[j].host, nodes[j].port)
    time.sleep(0.5)

    slushes[proposer_idx]._color = initial_color
    log_fn(f"Node {nodes[proposer_idx].port} proposes {initial_color.value}")

    results: Dict[int, Optional[Color]] = {}
    threads: List[threading.Thread] = []
    for i, (node, slush) in enumerate(zip(nodes, slushes)):
        init_col = initial_color if i == proposer_idx else None
        t = threading.Thread(target=lambda s=slush, c=init_col: s.run_slush_loop(c))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    for node, slush in zip(nodes, slushes):
        results[node.port] = slush.get_accepted()

    for node in nodes:
        node.close()
    return results


COLORS = ("R", "B")
