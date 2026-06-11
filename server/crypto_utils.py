"""Fernet encryption for credential secrets at rest.

Automatically generates a key file on first use.
Key file location: data/encryption.key (alongside findings.db).
"""

import logging
from pathlib import Path

logger = logging.getLogger("dristi-crypto")

try:
    from cryptography.fernet import Fernet

    HAS_CRYPTO = True
except ImportError:
    Fernet = None  # type: ignore[assignment]
    HAS_CRYPTO = False
    logger.warning("cryptography not installed — credentials stored in plaintext. " "Install with: pip install dristi-server[encrypt]")


def _get_key_path() -> Path:
    base = Path(__file__).parent / "data"
    base.mkdir(parents=True, exist_ok=True)
    return base / "encryption.key"


def _load_or_create_key() -> bytes:
    key_path = _get_key_path()
    if key_path.exists():
        return key_path.read_bytes()
    key = Fernet.generate_key()
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    logger.info("Generated new encryption key at %s", key_path)
    return key


def _get_fernet():
    return Fernet(_load_or_create_key())


def encrypt_secret(plaintext: str) -> str:
    if not HAS_CRYPTO or not plaintext:
        return plaintext
    try:
        f = _get_fernet()
        return f.encrypt(plaintext.encode()).decode()
    except Exception as e:
        logger.error("Encryption failed: %s", e)
        return plaintext


def decrypt_secret(ciphertext: str) -> str:
    if not HAS_CRYPTO or not ciphertext:
        return ciphertext
    try:
        f = _get_fernet()
        return f.decrypt(ciphertext.encode()).decode()
    except Exception:
        return ciphertext
