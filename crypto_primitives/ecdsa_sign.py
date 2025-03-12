try:
    import ecdsa
except ImportError:
    raise ImportError("Please install 'ecdsa' library (pip install ecdsa) to use ECDSA functionality.")

from .abstract import KeyCryptoPrimitive


class ECDSASignaturePrimitive(KeyCryptoPrimitive):
    """
    ECDSA signature generation/verification using the ecdsa library.
    """

    def __init__(self):
        self.private_key = None  # ecdsa.SigningKey
        self.public_key = None   # ecdsa.VerifyingKey

    def generate_key(self):
        """
        Generate a new ECDSA private key and store both private/public keys in memory.
        """
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key = self.private_key.get_verifying_key()

    def sign(self, data: bytes) -> bytes:
        """
        Sign the given data with the ECDSA private key.
        """
        if not self.private_key:
            raise ValueError("Private key not generated or set.")
        signature = self.private_key.sign(data)
        return signature

    def verify(self, data: bytes, signature: bytes, pub_key=None) -> bool:
        """
        Verify the signature using the provided public key (or the internally stored public key).
        :param data: raw bytes that were signed
        :param signature: signature bytes
        :param pub_key: ecdsa.VerifyingKey (if not provided, we use self.public_key)
        """
        if pub_key is None:
            if not self.public_key:
                raise ValueError("No public key available for verification.")
            pub_key = self.public_key

        try:
            pub_key.verify(signature, data)
            return True
        except ecdsa.BadSignatureError:
            return False

    def get_public_pem(self) -> str:
        """
        Return the public key as a PEM-encoded string.
        """
        if not self.public_key:
            raise ValueError("Public key not available (generate_key or set_key first).")
        # to_pem() returns bytes; we decode to str for convenience
        return self.public_key.to_pem().decode("ascii")

    def load_pub_key_from_pem(self, pem_str: str):
        """
        Load a PEM-encoded public key and store it as self.public_key.
        """
        self.public_key = ecdsa.VerifyingKey.from_pem(pem_str)
