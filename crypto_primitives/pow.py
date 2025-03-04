# crypto_primitives/pow.py

import hashlib
import time
import random
from .abstract import KeylessCryptoPrimitive

class ProofOfWorkPrimitive(KeylessCryptoPrimitive):
    """
    Simple Proof-of-Work that searches for a nonce such that:
    SHA256(challenge + nonce) < difficulty_target.
    This is a naive approach to illustrate how you might implement PoW.
    """

    def __init__(self, difficulty_bits=20):
        """
        difficulty_bits defines how many leading zero bits are required.
        For example, difficulty_bits=20 => requires ~1 in 2^(20) solution.
        """
        self.difficulty_bits = difficulty_bits

    def create_proof(self, challenge: str):
        """
        Create a proof (nonce) by brute-forcing a hash with required leading zeros (in bits).
        Returns (nonce, hash).
        """
        prefix_zeros = self.difficulty_bits // 4  # approximate hex zeros
        target_prefix = "0" * prefix_zeros

        nonce = 0
        while True:
            test_str = challenge + str(nonce)
            hash_hex = hashlib.sha256(test_str.encode()).hexdigest()
            if hash_hex.startswith(target_prefix):
                return nonce
            nonce += 1

    def verify_proof(self, challenge: str, nonce: int) -> bool:
        """
        Verify if hashing challenge + nonce meets the difficulty requirement.
        """
        calculated = hashlib.sha256((challenge + str(nonce)).encode()).hexdigest()

        prefix_zeros = self.difficulty_bits // 4
        return calculated.startswith("0" * prefix_zeros)
