"""Tests for the core randomness-beacon PoW consensus engine."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from chaincraft.consensus import default_registry, get_consensus_engine
from chaincraft.consensus.base import ConsensusError, UnstableConsensusWarning
from chaincraft.consensus.pow.beacon import (
    GENESIS_HASH,
    RandomnessBeaconConsensus,
    pow_challenge,
)
from chaincraft.shared_message import SharedMessage


class _Bus:
    def __init__(self):
        self.queue = []

    def create_shared_message(self, data):
        self.queue.append(data)
        return ("hash", SharedMessage(data=data))


class TestRegistration(unittest.TestCase):
    def test_registered_as_pow(self):
        self.assertIn("beacon", default_registry.available())
        self.assertIn("beacon", default_registry.by_category("pow"))

    def test_factory(self):
        eng = get_consensus_engine("beacon", difficulty_bits=8, coinbase="0xabc")
        self.assertIsInstance(eng, RandomnessBeaconConsensus)


class TestValidation(unittest.TestCase):
    def test_invalid_difficulty(self):
        with self.assertRaises(ConsensusError):
            RandomnessBeaconConsensus(difficulty=0)

    def test_high_difficulty_warns(self):
        with self.assertWarns(UnstableConsensusWarning):
            RandomnessBeaconConsensus(difficulty=2**22)


class TestMining(unittest.TestCase):
    def setUp(self):
        self.beacon = RandomnessBeaconConsensus(
            difficulty_bits=10,
            coinbase="0xminer",
            max_timestamp_skew=None,
        )

    def test_genesis(self):
        self.assertEqual(self.beacon.chain.tip, GENESIS_HASH)
        self.assertEqual(len(self.beacon.canonical_blocks()), 1)

    def test_mine_and_ingest(self):
        block = self.beacon.mine()
        self.assertEqual(block["blockHeight"], 1)
        challenge = pow_challenge(block["coinbaseAddress"], block["prevBlockHash"])
        self.assertTrue(
            self.beacon.pow.verify_proof(challenge, block["nonce"], block["id"])
        )
        self.beacon._ingest(block)
        self.assertEqual(self.beacon.chain.height, 1)
        self.assertEqual(self.beacon.blocks_mined_by("0xminer"), 1)

    def test_propose_broadcasts(self):
        bus = _Bus()
        self.beacon._attach_node(bus)
        self.beacon.propose()
        self.assertEqual(len(bus.queue), 1)
        self.assertEqual(bus.queue[0]["consensus"], "beacon")


class TestRandomness(unittest.TestCase):
    def test_random_float_in_unit_interval(self):
        b = RandomnessBeaconConsensus(
            difficulty_bits=10, max_timestamp_skew=None
        )
        b.propose()
        b.propose()
        r = b.random_float()
        self.assertGreaterEqual(r, 0.0)
        self.assertLess(r, 1.0)

    def test_random_int_in_range(self):
        b = RandomnessBeaconConsensus(
            difficulty_bits=10, confirmations=1, max_timestamp_skew=None
        )
        for _ in range(3):
            b.propose()
        n = b.random_int(1, 6)
        self.assertGreaterEqual(n, 1)
        self.assertLessEqual(n, 6)

    def test_decision_after_confirmations(self):
        b = RandomnessBeaconConsensus(
            difficulty_bits=10, confirmations=2, max_timestamp_skew=None
        )
        self.assertFalse(b.is_decided())
        b.propose()
        self.assertFalse(b.is_decided())
        b.propose()
        b.propose()
        self.assertTrue(b.is_decided())
        self.assertIsNotNone(b.decision())


class TestForkChoice(unittest.TestCase):
    def test_reorg_to_longer_branch(self):
        b = RandomnessBeaconConsensus(
            difficulty_bits=10, max_timestamp_skew=None
        )

        def mk(height, parent, coinbase):
            ch = pow_challenge(coinbase, parent)
            nonce, hid = b.pow.create_proof(ch)
            return {
                "message_type": "BEACON_BLOCK",
                "blockHeight": height,
                "prevBlockHash": parent,
                "timestamp": 1,
                "coinbaseAddress": coinbase,
                "nonce": nonce,
                "id": hid,
                "blockHash": hid,
            }

        a = mk(1, GENESIS_HASH, "0xa")
        b._ingest(a)
        alt = mk(1, GENESIS_HASH, "0xb")
        b._ingest(alt)
        tip = b.chain.tip
        loser = alt["id"] if tip == a["id"] else a["id"]
        ext = mk(2, loser, "0xc")
        b._ingest(ext)
        self.assertTrue(b.last_result.reorg)
        self.assertEqual(b.chain.tip, ext["id"])


class TestNetworkConvergence(unittest.TestCase):
    def test_nodes_sync_via_gossip(self):
        nodes = [
            RandomnessBeaconConsensus(
                difficulty_bits=10,
                coinbase=f"0x{i}",
                confirmations=1,
                max_timestamp_skew=None,
            )
            for i in range(3)
        ]
        bus = _Bus()
        for n in nodes:
            n._attach_node(bus)
        for _ in range(3):
            nodes[0].propose()
            while bus.queue:
                data = bus.queue.pop(0)
                for n in nodes:
                    n.observe(SharedMessage(data=data))
        tips = {n.tip() for n in nodes}
        self.assertEqual(len(tips), 1)


class TestRawBlockCompat(unittest.TestCase):
    """Core engine accepts raw BEACON_BLOCK messages like the example toy."""

    def test_observe_raw_beacon_block(self):
        b = RandomnessBeaconConsensus(
            difficulty_bits=10, max_timestamp_skew=None
        )
        block = b.mine()
        b.observe(SharedMessage(data=block))
        self.assertEqual(b.chain.height, 1)


if __name__ == "__main__":
    unittest.main()
