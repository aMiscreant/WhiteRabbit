# relay/encryptor.py
import os
from typing import List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import logging

logger = logging.getLogger("OnionEncryptor")
logging.basicConfig(level=logging.INFO)


class OnionEncryptor:
    """
    Onion layer builder using AES-GCM. Keys must be 32 bytes (AES-256).
    The wire format for each layer is: nonce(12) || ciphertext
    Layers are stacked from outermost -> innermost when encrypting.
    """

    def __init__(self, keys: List[bytes]):
        # Validate keys
        if not all(isinstance(k, (bytes, bytearray)) and len(k) == 32 for k in keys):
            raise ValueError("All keys must be 32-byte bytes objects")
        self.keys = keys

    def encrypt(self, data: bytes) -> bytes:
        payload = data
        # Encrypt layers starting from last hop key backward
        for key in reversed(self.keys):
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, payload, None)
            payload = nonce + ciphertext
        return payload

    def decrypt(self, data: bytes) -> bytes:
        payload = data
        # Decrypt layers in forward order (from first hop to last)
        for key in self.keys:
            if len(payload) < 12:
                raise ValueError("Malformed payload: too short for nonce")
            nonce = payload[:12]
            ciphertext = payload[12:]
            aesgcm = AESGCM(key)
            payload = aesgcm.decrypt(nonce, ciphertext, None)
        return payload
