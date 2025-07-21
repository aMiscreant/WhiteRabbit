import os
import base64
import secrets
import logging
from flask import Flask, request, jsonify, abort
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests
from threading import Thread

app = Flask(__name__)
logger = logging.getLogger("RelayServer")
logging.basicConfig(level=logging.DEBUG)

class RelayServer:
    def __init__(self, address: str, port: int, hop_index: int, total_hops: int, next_hop_url: str = None):
        """
        Args:
            address: bind address (e.g., '0.0.0.0')
            port: listening port
            hop_index: this server's position in the relay chain (0-based)
            total_hops: total hops in the relay chain
            next_hop_url: URL of next hop in chain (None if final hop)
        """
        self.address = address
        self.port = port
        self.hop_index = hop_index
        self.total_hops = total_hops
        self.next_hop_url = next_hop_url
        self.key = self._generate_session_key()  # AES-256 key unique per hop
        self.files_dir = "stored_files"
        os.makedirs(self.files_dir, exist_ok=True)

    def _generate_session_key(self) -> bytes:
        # For demo, generate a fixed key per hop index for client-server sync
        # Replace with secure key exchange in production!
        seed = f"relayserver-key-{self.hop_index}".encode()
        return secrets.token_bytes(32)  # you can use hashlib + seed to derive key if you want determinism

    def _decrypt_layer(self, data: bytes) -> bytes:
        aesgcm = AESGCM(self.key)
        nonce = data[:12]
        ct = data[12:]
        return aesgcm.decrypt(nonce, ct, None)

    def _encrypt_layer(self, data: bytes) -> bytes:
        aesgcm = AESGCM(self.key)
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct

    def start(self):
        # Run Flask app in a background thread
        def run():
            app.config['relay_server_instance'] = self
            app.run(host=self.address, port=self.port)

        self.thread = Thread(target=run, daemon=True)
        self.thread.start()
        logger.info(f"RelayServer started on {self.address}:{self.port}")

    def stop(self):
        # Flask doesn't have a built-in stop method — usually handled externally
        logger.info("Stopping RelayServer not implemented")

    def handle_upload(self, payload_b64: str):
        try:
            payload = base64.b64decode(payload_b64)
            logger.debug(f"Received payload length: {len(payload)} bytes")

            # Decrypt one layer
            decrypted = self._decrypt_layer(payload)
            logger.debug(f"Decrypted one layer, size: {len(decrypted)} bytes")

            if self.hop_index < self.total_hops - 1:
                # Forward to next hop
                if not self.next_hop_url:
                    raise RuntimeError("Next hop URL missing for non-final relay")

                resp = requests.post(self.next_hop_url + "/upload",
                                     json={"payload": base64.b64encode(decrypted).decode()},
                                     timeout=30)
                resp.raise_for_status()
                return resp.json()

            else:
                # Final hop: store file and return ID
                file_id = secrets.token_hex(16)
                file_path = os.path.join(self.files_dir, file_id)
                with open(file_path, "wb") as f:
                    f.write(decrypted)
                logger.info(f"Stored file with ID {file_id}")
                return {"status": "stored", "file_id": file_id}

        except Exception as e:
            logger.error(f"Error handling upload: {e}")
            abort(500, description=f"Server error: {e}")

    def handle_download(self, file_id: str):
        try:
            file_path = os.path.join(self.files_dir, file_id)
            if not os.path.isfile(file_path):
                abort(404, description="File not found")
            with open(file_path, "rb") as f:
                data = f.read()
            logger.info(f"Serving file {file_id} of size {len(data)} bytes")
            return jsonify({"payload": base64.b64encode(data).decode()})
        except Exception as e:
            logger.error(f"Error handling download: {e}")
            abort(500, description=f"Server error: {e}")


relay_server_instance = None

@app.route("/upload", methods=["POST"])
def upload():
    data = request.get_json()
    if not data or "payload" not in data:
        return jsonify({"error": "Missing payload"}), 400
    return relay_server_instance.handle_upload(data["payload"])

@app.route("/file/<file_id>", methods=["GET"])
def download(file_id):
    return relay_server_instance.handle_download(file_id)
