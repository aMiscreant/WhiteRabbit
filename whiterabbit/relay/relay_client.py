# relay/relay_client.py
import os
import json
import base64
import secrets
import logging
from typing import List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import requests

logger = logging.getLogger("RelayClient")
logging.basicConfig(level=logging.DEBUG)


class RelayClient:
    def __init__(self, hops: List[str], master_secret: Optional[str] = None):
        """
        Args:
            hops: Ordered list of relay URLs (first hop = hops[0], last hop = hops[-1])
            master_secret: if provided, used to deterministically derive per-hop AES keys.
                           otherwise will look for WHITERABBIT_MASTER_SECRET env var.
                           If still missing, a deterministic weak fallback is used for local tests.
        """
        self.hops = hops
        self.master_secret = master_secret or os.environ.get("WHITERABBIT_MASTER_SECRET")
        if not self.master_secret:
            logger.warning("WHITERABBIT_MASTER_SECRET not set; using local fallback derived secret (dev only)")
            # fallback deterministic local secret — NOT recommended for production
            self.master_secret = "whiterabbit-local-dev-secret"

        self.session_keys = [self._derive_session_key(i) for i in range(len(hops))]
        self.logger = logging.getLogger("RelayClient")
        self.logger.setLevel(logging.DEBUG)

    def _derive_session_key(self, hop_index: int) -> bytes:
        """
        Derive a 32-byte key per hop using HKDF-SHA256 from the master secret and hop index.
        """
        info = f"relay-hop-{hop_index}".encode()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(self.master_secret.encode())

    def _encrypt_layer(self, data: bytes, key: bytes) -> bytes:
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
        payload = file_data
        for key in reversed(self.session_keys):
            payload = self._encrypt_layer(payload, key)
        return payload

    def _send_to_hop(self, url: str, data: bytes) -> bool:
        try:
            resp = requests.post(url.rstrip("/") + "/upload",
                                 json={"payload": base64.b64encode(data).decode()},
                                 timeout=30)
            resp.raise_for_status()
            return True
        except Exception as e:
            self.logger.error(f"Failed to send to hop {url}: {e}")
            return False

    def send_file(self, file_path: str) -> bool:
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            onion_packet = self._build_onion_packet(file_data)
            success = self._send_to_hop(self.hops[0], onion_packet)
            return success

        except Exception as e:
            self.logger.error(f"Failed to send file: {e}")
            return False

    def _receive_from_hop(self, url: str, file_id: str) -> bytes:
        try:
            resp = requests.get(url.rstrip("/") + f"/file/{file_id}", timeout=30)
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
            payload = self._receive_from_hop(self.hops[-1], file_id)
            if not payload:
                return False

            # REMOVE decryption loop
            # for key in self.session_keys:
            #     payload = self._decrypt_layer(payload, key)

            with open(output_path, "wb") as f:
                f.write(payload)

            return True

        except Exception as e:
            self.logger.error(f"Failed to receive file: {e}")
            return False

