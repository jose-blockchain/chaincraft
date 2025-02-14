# crypto_primitives/vdf.py

import hashlib
import time
from .abstract import KeylessCryptoPrimitive

class VDFPrimitive(KeylessCryptoPrimitive):
    """
    A mock Verifiable Delay Function that repeatedly hashes to simulate a time-based puzzle.
    Real VDFs (e.g. Wesolowski, Pietrzak) are more complex. This is just a toy example.
    """

    def __init__(self, iterations=200000):
        """
        iterations: how many times to re-hash. This simulates a time delay.
        """
        self.iterations = iterations

    def create_proof(self, input_data: str) -> str:
        """
        'Compute' the VDF by hashing repeatedly a certain number of times.
        Return the final digest as 'proof'.
        """
        current = input_data.encode()
        for _ in range(self.iterations):
            current = hashlib.sha256(current).digest()
        return current.hex()

    def verify_proof(self, input_data: str, proof: str) -> bool:
        """
        Recompute the same number of iterations and check equality to 'proof'.
        """
        check = self.create_proof(input_data)
        return (check == proof)
