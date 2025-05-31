# crypto_primitives/abstract.py

from abc import ABC, abstractmethod

class CryptoPrimitive(ABC):
    """
    Base class for all cryptographic primitives in Chaincraft.
    """
    pass


class KeylessCryptoPrimitive(CryptoPrimitive):
    """
    Abstract base class for crypto primitives that do NOT require a private key.
    E.g., Proof-of-Work, VDF, etc.
    """

    @abstractmethod
    def create_proof(self, *args, **kwargs):
        """
        Create or generate the proof for the given challenge/inputs.
        """
        pass

    @abstractmethod
    def verify_proof(self, *args, **kwargs) -> bool:
        """
        Verify the proof for correctness.
        """
        pass


class KeyCryptoPrimitive(CryptoPrimitive):
    """
    Abstract base class for crypto primitives that DO require a private key.
    E.g., ECDSA, VRF, Symmetric Encryption, etc.
    """

    @abstractmethod
    def generate_key(self, *args, **kwargs):
        """
        Generate or load a private key (depending on your use case).
        """
        pass

    @abstractmethod
    def sign(self, data: bytes, *args, **kwargs) -> bytes:
        """
        Sign given data using the private key.
        """
        pass

    @abstractmethod
    def verify(self, data: bytes, signature: bytes, pub_key=None, *args, **kwargs) -> bool:
        """
        Verify a signature (with or without explicitly passed public key).
        """
        pass

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext using the private key or a derived key.
        """
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using the private key or a derived key.
        """
        pass