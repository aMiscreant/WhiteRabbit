import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class OnionEncryptor:
    def __init__(self, keys: list[bytes]):
        self.keys = keys  # list of 32-byte keys (bytes objects)

    def encrypt(self, data: bytes) -> bytes:
        payload = data
        # Encrypt layers starting from last hop key backward
        for key in reversed(self.keys):
            nonce = os.urandom(12)
            chacha = ChaCha20Poly1305(key)
            ciphertext = chacha.encrypt(nonce, payload, None)
            payload = nonce + ciphertext
        return payload

    def decrypt(self, data: bytes) -> bytes:
        payload = data
        # Decrypt layers in forward order (from first hop to last)
        for key in self.keys:
            nonce = payload[:12]
            ciphertext = payload[12:]
            chacha = ChaCha20Poly1305(key)
            payload = chacha.decrypt(nonce, ciphertext, None)
        return payload
