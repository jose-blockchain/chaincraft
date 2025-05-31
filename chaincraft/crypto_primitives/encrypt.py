from cryptography.fernet import Fernet
from .abstract import KeyCryptoPrimitive

class SymmetricEncryption(KeyCryptoPrimitive):
    def __init__(self, key=None):
        """
        Initialize the encryption class.
        If a key is provided, use it; otherwise, generate a new key.
        """
        if key is None:
            self.key = Fernet.generate_key()
        else:
            self.key = key.encode() if isinstance(key, str) else key
        
        self.fernet = Fernet(self.key)
    
    def generate_key(self):
        """Generate a new encryption key."""
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        return self.key
    
    def sign(self, data: bytes) -> bytes:
        """Encrypt data (acting as a 'sign' operation)."""
        return self.fernet.encrypt(data)
    
    def verify(self, data: bytes, signature: bytes, pub_key=None) -> bool:
        """Verify by decrypting and checking the original value."""
        try:
            decrypted = self.fernet.decrypt(signature)
            return decrypted == data
        except:
            return False
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt the given plaintext string and return the encrypted value as a string."""
        ciphertext = self.fernet.encrypt(plaintext)
        return ciphertext.decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt the given ciphertext string and return the original plaintext."""
        return  self.fernet.decrypt(ciphertext)
    
    def get_key(self) -> str:
        """Return the encryption key as a string."""
        return self.key.decode()

# Usage Example
if __name__ == "__main__":
    encryptor = SymmetricEncryption()
    key = encryptor.get_key()
    print(f"Generated Key: {key}")
    
    message = "Hello, Chaincraft!"
    encrypted_message = encryptor.encrypt(message)
    print(f"Encrypted: {encrypted_message}")
    
    decrypted_message = encryptor.decrypt(encrypted_message)
    print(f"Decrypted: {decrypted_message}")
