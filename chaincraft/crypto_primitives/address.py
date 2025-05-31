# crypto_primitives/address.py

import hashlib
import os
from typing import Tuple, Optional

try:
    import ecdsa
except ImportError:
    raise ImportError(
        "Please install 'ecdsa' library (pip install ecdsa) to use ECDSA functionality."
    )

from .sign import ECDSASignaturePrimitive


def generate_key_pair() -> Tuple[ecdsa.SigningKey, ecdsa.VerifyingKey]:
    """
    Generate a new ECDSA key pair for use with Ethereum-style addresses.

    Returns:
        tuple: (private_key, public_key)
    """
    primitive = ECDSASignaturePrimitive()
    primitive.generate_key()
    return primitive.private_key, primitive.public_key


def public_key_to_address(public_key: ecdsa.VerifyingKey) -> str:
    """
    Convert a public key to an Ethereum-style address.

    Args:
        public_key: ECDSA public key

    Returns:
        str: Ethereum-style address (0x + 40 hex chars)
    """
    # Get the public key in uncompressed form (65 bytes)
    pub_key_bytes = public_key.to_string("uncompressed")

    # Remove the first byte (0x04 prefix for uncompressed keys)
    pub_key_bytes = pub_key_bytes[1:]

    # Compute Keccak-256 hash
    keccak_hash = hashlib.sha3_256(pub_key_bytes).digest()

    # Take the last 20 bytes and convert to hex
    address = keccak_hash[-20:].hex()

    # Add 0x prefix for Ethereum-style address
    return f"0x{address}"


def private_key_to_address(private_key: ecdsa.SigningKey) -> str:
    """
    Convert a private key to an Ethereum-style address.

    Args:
        private_key: ECDSA private key

    Returns:
        str: Ethereum-style address (0x + 40 hex chars)
    """
    public_key = private_key.get_verifying_key()
    return public_key_to_address(public_key)


def generate_new_address() -> Tuple[str, ecdsa.SigningKey]:
    """
    Generate a new random Ethereum-style address and its corresponding private key.

    Returns:
        tuple: (address, private_key)
    """
    private_key, _ = generate_key_pair()
    address = private_key_to_address(private_key)
    return address, private_key


def is_valid_address(address: str) -> bool:
    """
    Check if an address is a valid Ethereum-style address.

    Args:
        address: Ethereum-style address to validate

    Returns:
        bool: True if valid, False otherwise
    """
    if not isinstance(address, str):
        return False

    # Check format (0x prefix + 40 hex chars)
    if not address.startswith("0x") or len(address) != 42:
        return False

    # Check if it's a valid hex string
    try:
        int(address[2:], 16)
        return True
    except ValueError:
        return False


def recover_public_key(
    message_hash: bytes, signature: bytes
) -> Optional[ecdsa.VerifyingKey]:
    """
    Recover the public key from a signature and message hash (similar to ecrecover in Ethereum).

    Args:
        message_hash: 32-byte hash of the message that was signed
        signature: Signature bytes (typically 65 bytes with r, s, v components)

    Returns:
        ecdsa.VerifyingKey or None if recovery fails
    """
    if len(signature) != 65:
        raise ValueError("Signature must be 65 bytes (r, s, v)")

    # Split the signature into r, s, v components
    r = int.from_bytes(signature[:32], byteorder="big")
    s = int.from_bytes(signature[32:64], byteorder="big")
    v = signature[64]  # recovery id (0 or 1)

    try:
        # Recover the public key
        public_key = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
            signature=signature[:64],  # just r and s
            digest=message_hash,
            curve=ecdsa.SECP256k1,
            sigdecode=ecdsa.util.sigdecode_string,
        )[
            v
        ]  # Use v as index to select the correct key from the two candidates

        return public_key
    except Exception as e:
        print(f"Error recovering public key: {e}")
        return None
