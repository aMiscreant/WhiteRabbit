# relay/relay_server.py
import os
import base64
import secrets
import logging
from flask import Flask, request, jsonify, abort
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import requests
from threading import Thread

app = Flask(__name__)
logger = logging.getLogger("RelayServer")
logging.basicConfig(level=logging.DEBUG)


class RelayServer:
    def __init__(self, address: str, port: int, hop_index: int, total_hops: int, next_hop_url: str = None):
        """
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
        """
        Deterministically derive a 32-byte key using HKDF from WHITERABBIT_MASTER_SECRET and hop_index.
        If env var is missing, fall back to a weaker deterministic derivation (dev only).
        """
        master = os.environ.get("WHITERABBIT_MASTER_SECRET")
        if not master:
            logger.warning("WHITERABBIT_MASTER_SECRET not set; using local fallback secret (dev only).")
            master = "whiterabbit-local-dev-secret"

        info = f"relay-hop-{self.hop_index}".encode()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(master.encode())

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
        # Run Flask app in a background thread (dev/testing only)
        def run():
            app.config['relay_server_instance'] = self
            app.run(host=self.address, port=self.port)

        self.thread = Thread(target=run, daemon=True)
        self.thread.start()
        logger.info(f"RelayServer started on {self.address}:{self.port} (hop {self.hop_index}/{self.total_hops})")

    def stop(self):
        logger.info("Stopping RelayServer not implemented (use process manager)")

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
                    logger.error("Next hop URL missing for non-final relay")
                    return {"error": "Server configuration error"}, 500

                if not self.next_hop_url.startswith("https://"):
                    logger.warning("Forwarding to non-HTTPS next hop (not recommended)")

                resp = requests.post(
                    self.next_hop_url.rstrip("/") + "/upload",
                    json={"payload": base64.b64encode(decrypted).decode()},
                    timeout=30,
                    verify=True
                )
                resp.raise_for_status()
                return resp.json()

            else:
                # final hop: basic size check and store file
                MAX_STORE_BYTES = int(os.environ.get("WHITERABBIT_MAX_STORE_BYTES", 50 * 1024 * 1024))
                if len(decrypted) > MAX_STORE_BYTES:
                    logger.warning("Incoming file exceeds max allowed size.")
                    return {"error": "File too large"}, 413

                file_id = secrets.token_hex(16)
                file_path = os.path.join(self.files_dir, file_id)
                with open(file_path, "wb") as f:
                    f.write(decrypted)
                logger.info(f"Stored file with ID {file_id} size {len(decrypted)} bytes")
                return {"status": "stored", "file_id": file_id}

        except Exception:
            logger.exception("Error handling upload")
            return {"error": "Server error"}, 500

    def handle_download(self, file_id: str):
        try:
            file_path = os.path.join(self.files_dir, file_id)
            if not os.path.isfile(file_path):
                return {"error": "File not found"}, 404
            with open(file_path, "rb") as f:
                data = f.read()
            logger.info(f"Serving file {file_id} of size {len(data)} bytes")
            return {"payload": base64.b64encode(data).decode()}
        except Exception:
            logger.exception("Error handling download")
            return {"error": "Server error"}, 500


relay_server_instance = None


@app.route("/upload", methods=["POST"])
def upload():
    data = request.get_json()
    if not data or "payload" not in data:
        return jsonify({"error": "Missing payload"}), 400
    inst = app.config.get('relay_server_instance') or relay_server_instance
    if not inst:
        return jsonify({"error": "Server not configured"}), 500
    result = inst.handle_upload(data["payload"])
    if isinstance(result, tuple):
        body, code = result
        return jsonify(body), code
    return jsonify(result)


@app.route("/file/<file_id>", methods=["GET"])
def download(file_id):
    inst = app.config.get('relay_server_instance') or relay_server_instance
    if not inst:
        return jsonify({"error": "Server not configured"}), 500
    result = inst.handle_download(file_id)
    if isinstance(result, tuple):
        body, code = result
        return jsonify(body), code
    return jsonify(result)


@app.route("/__shutdown", methods=["POST"])
def _shutdown():
    inst = app.config.get('relay_server_instance') or relay_server_instance
    if not inst:
        return {"error": "No instance"}, 500
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return {"error": "Forbidden"}, 403
    func = request.environ.get('werkzeug.server.shutdown')
    if func:
        func()
        return {"status": "shutting down"}
    return {"error": "Cannot shutdown"}, 500
