#!/usr/bin/env python3
"""Avalanche-family single-decree consensus (Slush, Snowflake, Snowball).

These protocols converge on a binary choice (RED or BLUE) by repeated random
sampling of peers, as described in the Avalanche paper "Snowflake to Avalanche".
They are migrated here from ``examples/`` and now share a common
:class:`BinarySamplingConsensus` base that captures the duplicated plumbing
(sampling, query handling, response collection, the ``Color`` enum, and the
SharedObject adapters). Each protocol overrides only its decision logic:

* **Slush** - flip toward any color seen with >= alpha*k support; accept after
  ``m`` rounds.
* **Snowflake** - add a conviction counter; accept after ``beta`` consecutive
  successful samples for the same color.
* **Snowball** - add persistent per-color confidence; switch preference only
  when a color's confidence strictly exceeds the current preference's.

The objects are ``CoreSharedObject`` instances driven by ``ChaincraftNode``'s
direct peer-to-peer dispatch (:meth:`handle_p2p`); the gossip path is stubbed.
"""

from __future__ import annotations

import json
import logging
import random
import threading
import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from chaincraft.core_objects import CoreSharedObject
from chaincraft.node import ChaincraftNode
from chaincraft.shared_message import SharedMessage

#: ChaincraftNode-like; kept loose to avoid hard coupling in type hints.
NodeT = Any

COLORS = ("R", "B")


class Color(Enum):
    """Binary choice: Red or Blue (paper R/B)."""

    RED = "R"
    BLUE = "B"
    UNCOLORED = "\u22a5"


def _color_from(value: str) -> Color:
    return Color.RED if value == "R" else Color.BLUE


class BinarySamplingConsensus(CoreSharedObject):
    """Shared base for the Avalanche binary-sampling protocols.

    Subclasses set :attr:`MSG_QUERY` / :attr:`MSG_RESPONSE` and implement
    :meth:`_handle_query` and :meth:`_handle_response`. The base provides peer
    sampling, response collection gating, the ``handle_p2p`` dispatcher, and the
    SharedObject stub interface (these protocols use direct p2p, not gossip).
    """

    MSG_QUERY = "QUERY"
    MSG_RESPONSE = "RESPONSE"

    def __init__(
        self,
        node: NodeT,
        k: int = 10,
        alpha: float = 0.5,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        self.node = node
        self.k = k
        self.alpha = alpha
        self._log = log_fn or (lambda msg: logging.info(msg))
        self._accepted: Optional[Color] = None
        self._pending: Dict[int, Dict[Tuple[str, int], Color]] = {}
        self._processed: set = set()
        self._lock = threading.Lock()

    # -- shared helpers ----------------------------------------------------
    def _log_node(self, msg: str) -> None:
        self._log(f"[{self.node.port}] {msg}")

    def handle_p2p(self, addr: tuple, data: dict) -> None:
        """Entry point for direct node-to-node messages (not stored/gossiped)."""
        p2p_type = data.get("p2p")
        if p2p_type == self.MSG_QUERY:
            self._handle_query(addr, data)
        elif p2p_type == self.MSG_RESPONSE:
            self._handle_response(addr, data)

    def _sample_peers(self) -> List[Tuple[str, int]]:
        peers = list(self.node.peers)
        sample_size = min(self.k, len(peers))
        if sample_size == 0:
            return []
        return random.sample(peers, sample_size)

    def _record_response(
        self, key: int, addr: Tuple[str, int], col: Color
    ) -> Optional[List[Color]]:
        """Collect a response; return the response list once k are gathered.

        Returns ``None`` while still waiting, if already accepted, or if this
        key was already processed.
        """
        with self._lock:
            if self._accepted is not None:
                return None
            if key not in self._pending:
                self._pending[key] = {}
            self._pending[key][addr] = col
            if len(self._pending[key]) < self.k or key in self._processed:
                return None
            self._processed.add(key)
            return list(self._pending[key].values())

    def get_accepted(self) -> Optional[Color]:
        return self._accepted

    # -- subclass hooks ----------------------------------------------------
    def _handle_query(self, addr: Tuple[str, int], data: dict) -> None:
        raise NotImplementedError

    def _handle_response(self, addr: Tuple[str, int], data: dict) -> None:
        raise NotImplementedError

    # -- SharedObject stubs (these protocols use direct p2p, not gossip) ---
    def is_valid(self, message: SharedMessage) -> bool:
        return False

    def add_message(self, message: SharedMessage, frontier_state=None) -> None:
        pass


class SlushObject(BinarySamplingConsensus):
    """Slush (Avalanche paper, Section 2.2). Not Byzantine fault tolerant."""

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
        super().__init__(node, k=k, alpha=alpha, log_fn=log_fn)
        self.m = m
        self._color = Color.UNCOLORED
        # Alias so the canonical processed-set is exposed under the legacy name.
        self._processed_rounds = self._processed

    def _send_round(self, r: int) -> None:
        """Send round r queries to sampled peers. Runs in listener thread."""
        sampled = self._sample_peers()
        if not sampled:
            return
        with self._lock:
            self._pending[r] = {}
        for peer in sampled:
            q = {
                "p2p": self.MSG_QUERY,
                "r": r,
                "col": self._color.value,
                "from": f"{self.node.host}:{self.node.port}",
            }
            self.node.send_to_peer(peer, json.dumps(q))

    def propose(self, initial_color: Color) -> None:
        with self._lock:
            if self._accepted is not None:
                return
            self._color = initial_color
        self._log_node(f"propose: {initial_color.value}")
        self._send_round(1)

    def _handle_query(self, addr: Tuple[str, int], data: dict) -> None:
        if "col" not in data or "r" not in data:
            return
        r = data["r"]
        col_str = data["col"]
        adopted = False
        with self._lock:
            if self._color == Color.UNCOLORED:
                self._color = _color_from(col_str)
                adopted = True
                self._log_node(f"onQuery: adopted {self._color.value} from {addr}")
            resp = {
                "p2p": self.MSG_RESPONSE,
                "r": r,
                "col": self._color.value,
                "from": f"{self.node.host}:{self.node.port}",
            }
        self.node.send_to_peer(addr, json.dumps(resp))
        if adopted:
            self._send_round(1)

    def _handle_response(self, addr: Tuple[str, int], data: dict) -> None:
        if "r" not in data or "col" not in data:
            return
        r = data["r"]
        col = _color_from(data["col"])
        responses = self._record_response(r, addr, col)
        if responses is None:
            return
        if len(responses) < max(1, int(self.alpha * self.k)):
            return
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
        if r < self.m:
            self._send_round(r + 1)
        else:
            with self._lock:
                self._accepted = self._color
            self._log_node(f"Slush accepted: {self._accepted.value}")


class SnowflakeObject(BinarySamplingConsensus):
    """Snowflake (Avalanche paper, Section 2.3). BFT via a conviction counter."""

    MSG_QUERY = "SNOWFLAKE_QUERY"
    MSG_RESPONSE = "SNOWFLAKE_RESPONSE"

    def __init__(
        self,
        node: NodeT,
        k: int = 10,
        alpha: float = 0.5,
        beta: int = 5,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        super().__init__(node, k=k, alpha=alpha, log_fn=log_fn)
        self.beta = beta
        self._color = Color.UNCOLORED
        self._cnt = 0
        self._query_id = 0
        self._processed_qids = self._processed

    def _send_query(self) -> None:
        sampled = self._sample_peers()
        if not sampled:
            return
        with self._lock:
            self._query_id += 1
            qid = self._query_id
            self._pending[qid] = {}
        for peer in sampled:
            q = {
                "p2p": self.MSG_QUERY,
                "qid": qid,
                "col": self._color.value,
                "from": f"{self.node.host}:{self.node.port}",
            }
            self.node.send_to_peer(peer, json.dumps(q))

    def propose(self, initial_color: Color) -> None:
        with self._lock:
            if self._accepted is not None:
                return
            self._color = initial_color
            self._cnt = 0
        self._log_node(f"propose: {initial_color.value}")
        self._send_query()

    def _handle_query(self, addr: Tuple[str, int], data: dict) -> None:
        if "col" not in data or "qid" not in data:
            return
        qid = data["qid"]
        col_str = data["col"]
        adopted = False
        with self._lock:
            if self._color == Color.UNCOLORED:
                self._color = _color_from(col_str)
                self._cnt = 0
                adopted = True
                self._log_node(f"onQuery: adopted {self._color.value} from {addr}")
            resp = {
                "p2p": self.MSG_RESPONSE,
                "qid": qid,
                "col": self._color.value,
                "from": f"{self.node.host}:{self.node.port}",
            }
        self.node.send_to_peer(addr, json.dumps(resp))
        if adopted:
            self._send_query()

    def _handle_response(self, addr: Tuple[str, int], data: dict) -> None:
        if "qid" not in data or "col" not in data:
            return
        qid = data["qid"]
        col = _color_from(data["col"])
        responses = self._record_response(qid, addr, col)
        if responses is None:
            return
        if len(responses) < max(1, int(self.alpha * self.k)):
            return
        threshold = int(self.alpha * self.k)
        counts = {Color.RED: 0, Color.BLUE: 0}
        for c in responses:
            if c in counts:
                counts[c] += 1
        other = Color.BLUE if self._color == Color.RED else Color.RED
        if counts.get(other, 0) >= threshold:
            with self._lock:
                self._color = other
                self._cnt = 0
            self._log_node(f"Query {qid}: flipped to {other.value}, cnt=0")
            self._send_query()
        elif counts.get(self._color, 0) >= threshold:
            with self._lock:
                self._cnt += 1
                if self._cnt > self.beta:
                    self._accepted = self._color
                    self._log_node(
                        f"Snowflake accepted: {self._accepted.value} "
                        f"(cnt={self._cnt})"
                    )
                    return
            self._log_node(f"Query {qid}: same color, cnt={self._cnt}")
            self._send_query()


class SnowballObject(BinarySamplingConsensus):
    """Snowball: Snowflake plus persistent per-color confidence counters."""

    MSG_QUERY = "SNOWBALL_QUERY"
    MSG_RESPONSE = "SNOWBALL_RESPONSE"

    def __init__(
        self,
        node: NodeT,
        k: int = 10,
        alpha: float = 0.5,
        beta: int = 8,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        super().__init__(node, k=k, alpha=alpha, log_fn=log_fn)
        self.beta = beta
        self._preference = Color.UNCOLORED
        self._query_id = 0
        self._confidence: Dict[Color, int] = {Color.RED: 0, Color.BLUE: 0}
        self._last_color = Color.UNCOLORED
        self._cnt = 0
        self._processed_qids = self._processed

    def propose(self, initial_color: Color) -> None:
        with self._lock:
            if self._accepted is not None:
                return
            self._preference = initial_color
            self._last_color = initial_color
            self._cnt = 0
        self._log_node(f"propose: {initial_color.value}")
        self._send_query()

    def _send_query(self) -> None:
        sampled = self._sample_peers()
        if not sampled:
            return
        with self._lock:
            self._query_id += 1
            qid = self._query_id
            self._pending[qid] = {}
        for peer in sampled:
            msg = {
                "p2p": self.MSG_QUERY,
                "qid": qid,
                "col": self._preference.value,
                "from": f"{self.node.host}:{self.node.port}",
            }
            self.node.send_to_peer(peer, json.dumps(msg))

    def _handle_query(self, addr: Tuple[str, int], data: dict) -> None:
        if "qid" not in data or "col" not in data:
            return
        qid = data["qid"]
        proposed_color = _color_from(data["col"])
        adopted = False
        with self._lock:
            if self._preference == Color.UNCOLORED:
                self._preference = proposed_color
                self._last_color = proposed_color
                self._cnt = 0
                adopted = True
            response = {
                "p2p": self.MSG_RESPONSE,
                "qid": qid,
                "col": self._preference.value,
                "from": f"{self.node.host}:{self.node.port}",
            }
        self.node.send_to_peer(addr, json.dumps(response))
        if adopted:
            self._send_query()

    def _handle_response(self, addr: Tuple[str, int], data: dict) -> None:
        if "qid" not in data or "col" not in data:
            return
        qid = data["qid"]
        color = _color_from(data["col"])
        responses = self._record_response(qid, addr, color)
        if responses is None:
            return

        threshold = max(1, int(self.alpha * self.k))
        counts = {Color.RED: 0, Color.BLUE: 0}
        for c in responses:
            if c in counts:
                counts[c] += 1

        if counts[Color.RED] >= threshold and counts[Color.RED] > counts[Color.BLUE]:
            sample_majority = Color.RED
        elif counts[Color.BLUE] >= threshold and counts[Color.BLUE] > counts[Color.RED]:
            sample_majority = Color.BLUE
        else:
            self._send_query()
            return

        with self._lock:
            self._confidence[sample_majority] += 1

            if (
                self._preference == Color.UNCOLORED
                or self._confidence[sample_majority]
                > self._confidence[self._preference]
            ):
                self._preference = sample_majority

            if sample_majority != self._last_color:
                self._last_color = sample_majority
                self._cnt = 0
            else:
                self._cnt += 1
                if self._cnt > self.beta:
                    self._accepted = self._preference
                    self._log_node(
                        f"Snowball accepted: {self._accepted.value} "
                        f"(conf R={self._confidence[Color.RED]}, "
                        f"B={self._confidence[Color.BLUE]}, cnt={self._cnt})"
                    )
                    return

        self._send_query()

    def get_confidence(self) -> Dict[Color, int]:
        return dict(self._confidence)

    def get_consecutive_count(self) -> int:
        return self._cnt


class SnowballNode(ChaincraftNode):
    """ChaincraftNode wrapper that hosts a :class:`SnowballObject`."""

    def __init__(
        self,
        *,
        port: int,
        max_peers: int = 9,
        local_discovery: bool = True,
        k: int = 10,
        alpha: float = 0.5,
        beta: int = 8,
        log_fn: Optional[Callable[[str], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            port=port,
            max_peers=max_peers,
            local_discovery=local_discovery,
            **kwargs,
        )
        self.snowball = SnowballObject(self, k=k, alpha=alpha, beta=beta, log_fn=log_fn)
        self.add_shared_object(self.snowball)

    def propose(self, initial_color: Color) -> None:
        self.snowball.propose(initial_color)

    def get_accepted(self) -> Optional[Color]:
        return self.snowball.get_accepted()


def _run_sampling_nodes(
    object_factory,
    *,
    num_nodes: int,
    base_port: int,
    proposer_idx: int,
    initial_color: Color,
    label: str,
) -> Dict[int, Optional[Color]]:
    """Shared driver: build a mesh of nodes, propose, and poll for decisions."""
    log_fn: Callable[[str], None] = lambda msg: print(f"[{label}] {msg}")
    nodes: List[ChaincraftNode] = []
    objects = []

    for i in range(num_nodes):
        node = ChaincraftNode(
            port=base_port + i,
            max_peers=num_nodes - 1,
            local_discovery=True,
        )
        obj = object_factory(node, log_fn)
        node.add_shared_object(obj)
        node.start()
        nodes.append(node)
        objects.append(obj)

    for i in range(num_nodes):
        for j in range(num_nodes):
            if i != j:
                nodes[i].connect_to_peer(nodes[j].host, nodes[j].port)
    time.sleep(0.5)

    objects[proposer_idx].propose(initial_color)
    log_fn(f"Node {nodes[proposer_idx].port} proposes {initial_color.value}")

    timeout = 60.0
    start = time.time()
    while time.time() - start < timeout:
        if all(o.get_accepted() is not None for o in objects):
            break
        time.sleep(0.1)

    results = {node.port: obj.get_accepted() for node, obj in zip(nodes, objects)}
    for node in nodes:
        node.close()
    return results


def run_slush_nodes(
    num_nodes: int = 10,
    base_port: int = 9010,
    k: int = 4,
    alpha: float = 0.5,
    m: int = 8,
    proposer_idx: int = 0,
    initial_color: Color = Color.RED,
) -> Dict[int, Optional[Color]]:
    return _run_sampling_nodes(
        lambda node, log_fn: SlushObject(node, k=k, alpha=alpha, m=m, log_fn=log_fn),
        num_nodes=num_nodes,
        base_port=base_port,
        proposer_idx=proposer_idx,
        initial_color=initial_color,
        label="Slush",
    )


def run_snowflake_nodes(
    num_nodes: int = 10,
    base_port: int = 9310,
    k: int = 4,
    alpha: float = 0.5,
    beta: int = 5,
    proposer_idx: int = 0,
    initial_color: Color = Color.RED,
) -> Dict[int, Optional[Color]]:
    return _run_sampling_nodes(
        lambda node, log_fn: SnowflakeObject(
            node, k=k, alpha=alpha, beta=beta, log_fn=log_fn
        ),
        num_nodes=num_nodes,
        base_port=base_port,
        proposer_idx=proposer_idx,
        initial_color=initial_color,
        label="Snowflake",
    )


def run_snowball_nodes(
    num_nodes: int = 10,
    base_port: int = 9510,
    k: int = 4,
    alpha: float = 0.5,
    beta: int = 8,
    proposer_idx: int = 0,
    initial_color: Color = Color.RED,
) -> Dict[int, Optional[Color]]:
    log_fn: Callable[[str], None] = lambda msg: print(f"[Snowball] {msg}")
    nodes: List[SnowballNode] = []

    for i in range(num_nodes):
        node = SnowballNode(
            port=base_port + i,
            max_peers=num_nodes - 1,
            local_discovery=True,
            k=k,
            alpha=alpha,
            beta=beta,
            log_fn=log_fn,
        )
        node.start()
        nodes.append(node)

    for i in range(num_nodes):
        for j in range(num_nodes):
            if i != j:
                nodes[i].connect_to_peer(nodes[j].host, nodes[j].port)
    time.sleep(0.5)

    nodes[proposer_idx].propose(initial_color)
    log_fn(f"Node {nodes[proposer_idx].port} proposes {initial_color.value}")

    timeout = 60.0
    start = time.time()
    while time.time() - start < timeout:
        if all(node.get_accepted() is not None for node in nodes):
            break
        time.sleep(0.1)

    results = {node.port: node.get_accepted() for node in nodes}
    for node in nodes:
        node.close()
    return results
