# crypto_primitives/pow.py

import hashlib
import time
import random
from .abstract import KeylessCryptoPrimitive

class ProofOfWorkPrimitive(KeylessCryptoPrimitive):
    """
    Simple Proof-of-Work that searches for a nonce such that:
    SHA256(challenge + nonce) % difficulty == 0.
    This is a continuous difficulty approach to Proof-of-Work.
    """

    def __init__(self, difficulty=2**20):
        """
        difficulty defines the divisor for the modulo operation.
        For example, difficulty=2^20 => requires ~1 in 2^20 solution.
        """
        self.difficulty = difficulty

    def create_proof(self, challenge: str):
        """
        Create a proof (nonce) by brute-forcing a hash such that
        int(hash_hex, 16) % difficulty == 0.
        Returns (nonce, hash).
        """
        nonce = 0
        while True:
            test_str = challenge + str(nonce)
            hash_hex = hashlib.sha256(test_str.encode()).hexdigest()
            calculated = int(hash_hex, 16)
            if calculated % self.difficulty == 0:
                return (nonce, hash_hex)
            nonce += 1

    def verify_proof(self, challenge: str, nonce: int, hash_hex: str) -> bool:
        """
        Verify if hashing challenge + nonce meets the difficulty requirement.
        """
        calculated_hash = hashlib.sha256((challenge + str(nonce)).encode()).hexdigest()

        if calculated_hash != hash_hex:
            return False

        calculated = int(calculated_hash, 16)
        return calculated % self.difficulty == 0
