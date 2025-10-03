<p align="center">
  <img src="docs/logo.png" alt="WhiteRabbit Logo" width="200"/>
</p>

# WhiteRabbit 🐇🕳️  
**Anonymize. Obfuscate. Vanish.**

WhiteRabbit is a Python toolkit for secure, high-fidelity data laundering.  
It scrubs, obfuscates, and securely relays files through multi-hop encrypted networks — ideal for whistleblowers, forensic evasion, and paranoid privacy freaks.

---

## Features

| Module | Description |
|--------|-------------|
| `scrub/` | Remove EXIF metadata, reset timestamps, and normalize file structure. |
| `obfuscate/` | Visually alter files via re-encoding, noise injection, and pixel shifting. |
| `relay/` | Multi-hop relay network with onion-style encryption for file transport. |
| `secure_delete/` | Shred files using multi-pass overwrite. |
| `utils/` | Logging and utility tools with obfuscation in mind. |

---

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
git clone https://github.com/yourname/whiterabbit.git
cd whiterabbit
python setup.py install
```

---

```g
whiterabbit/
├── __init__.py
├── scrub/
│   ├── exif_cleaner.py
│   ├── timestamp_reset.py
│   └── encoder.py
├── obfuscate/
│   ├── pixel_shuffle.py
│   └── noise_injector.py
├── relay/
│   ├── relay_client.py
│   ├── encryptor.py
│   └── relay_server.py
├── secure_delete/
│   └── shredder.py
├── utils/
│   └── logger.py
└── main.py

```

---

### Examples


- File sample_with_exif.jpg shredded with 3 pass.

```python

python main.py shred sample_with_exif.jpg
# 🐇 WhiteRabbit secure file tool invoked.
...
```

- Start the relay server.

```python
python main.py start-relay --host 127.0.0.1 --port 5000 --hop-index 0 --total-hops 1
🐇 WhiteRabbit secure file tool invoked.
...
```

- Send file to the relay server.

```python
python main.py send myfile.txt --hops http://127.0.0.1:5000
🐇 WhiteRabbit secure file tool invoked.
...
```

- Receive file from the relay server.
        Note: the receive string will be outputted by the relay server.
        
        DEBUG:RelayServer:Received payload length: 48 bytes
        DEBUG:RelayServer:Decrypted one layer, size: 20 bytes
        INFO:RelayServer:Stored file with ID 767cf1769bd3962fa6910c7a08d707ce size 20 bytes


```python
python main.py receive 767cf1769bd3962fa6910c7a08d707ce recovered.txt --hops http://127.0.0.1:5000
🐇 WhiteRabbit secure file tool invoked.
...
```

---