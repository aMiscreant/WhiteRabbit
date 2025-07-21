import os
import json
import base64
import secrets
import hashlib
import logging
from typing import List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests

class RelayClient:
    def __init__(self, hops: List[str]):
        """
        Args:
            hops: Ordered list of relay URLs (e.g., onion addresses or HTTPS endpoints)
        """
        self.hops = hops
        self.session_keys = [self._generate_session_key() for _ in hops]  # one AES-GCM key per hop
        self.logger = logging.getLogger("RelayClient")
        self.logger.setLevel(logging.DEBUG)

    def _generate_session_key(self) -> bytes:
        return secrets.token_bytes(32)  # AES-256 key

    def _encrypt_layer(self, data: bytes, key: bytes) -> bytes:
        # AES-GCM encrypt one "layer" for onion routing
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct  # prefix nonce for decryption

    def _decrypt_layer(self, data: bytes, key: bytes) -> bytes:
        aesgcm = AESGCM(key)
        nonce = data[:12]
        ct = data[12:]
        return aesgcm.decrypt(nonce, ct, None)

    def _build_onion_packet(self, file_data: bytes) -> bytes:
        """
        Encrypt data in layers starting from last hop backwards.
        """
        payload = file_data
        for key in reversed(self.session_keys):
            payload = self._encrypt_layer(payload, key)
        return payload

    def _send_to_hop(self, url: str, data: bytes) -> bool:
        """
        POST encrypted data to relay server.
        Expects JSON {"payload": base64-encoded string}.
        """
        try:
            resp = requests.post(url, json={"payload": base64.b64encode(data).decode()}, timeout=30)
            resp.raise_for_status()
            return True
        except Exception as e:
            self.logger.error(f"Failed to send to hop {url}: {e}")
            return False

    def send_file(self, file_path: str) -> bool:
        try:
            # Read file as bytes
            with open(file_path, "rb") as f:
                file_data = f.read()

            # Build layered encryption onion packet
            onion_packet = self._build_onion_packet(file_data)

            # Send onion packet to first hop URL
            success = self._send_to_hop(self.hops[0], onion_packet)
            return success

        except Exception as e:
            self.logger.error(f"Failed to send file: {e}")
            return False

    def _receive_from_hop(self, url: str, file_id: str) -> bytes:
        """
        GET file data by ID from relay.
        """
        try:
            resp = requests.get(f"{url}/file/{file_id}", timeout=30)
            resp.raise_for_status()
            data = resp.json().get("payload")
            if not data:
                raise ValueError("No payload in response")
            return base64.b64decode(data)
        except Exception as e:
            self.logger.error(f"Failed to receive from hop {url}: {e}")
            return b""

    def receive_file(self, file_id: str, output_path: str) -> bool:
        try:
            # Fetch onion-encrypted payload from last hop backwards
            payload = self._receive_from_hop(self.hops[-1], file_id)
            if not payload:
                return False

            # Decrypt layers in order (from first to last hop)
            for key in self.session_keys:
                payload = self._decrypt_layer(payload, key)

            # Write decrypted file bytes
            with open(output_path, "wb") as f:
                f.write(payload)

            return True

        except Exception as e:
            self.logger.error(f"Failed to receive file: {e}")
            return False
