<p align="center">
  <img src="docs/logo.png" alt="WhiteRabbit Logo" width="200"/>
</p>

# WhiteRabbit 🐇🕳️  
**Anonymize. Obfuscate. Vanish.**

WhiteRabbit is a Python toolkit for secure, high-fidelity data laundering.  
It scrubs, obfuscates, and securely relays files through multi-hop encrypted networks — forensic evasion, and paranoid privacy freaks.

---

## 🔐 Features

| Module | Description |
|--------|-------------|
| `scrub/` | Remove EXIF metadata, reset timestamps, and normalize file structure. |
| `obfuscate/` | Visually alter files via re-encoding, noise injection, and pixel shifting. |
| `relay/` | Multi-hop relay network with onion-style encryption for file transport. |
| `secure_delete/` | Shred files using multi-pass overwrite. |
| `utils/` | Logging and utility tools with obfuscation in mind. |

---

## 📦 Installation

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

```python

python main.py shred sample_with_exif.jpg
# 🐇 WhiteRabbit secure file tool invoked.
# File sample_with_exif.jpg shredded with 3 pass
```
