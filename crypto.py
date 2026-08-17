"""AES-256-GCM secret encryption backed by data/master.key (0600, auto-created)."""
import base64
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("leadflow.crypto")

PREFIX = "enc:v1:"
_NONCE_LEN = 12

_key_cache = {}  # path str -> bytes


def _master_key_path():
    from leadflow.db import data_dir
    return data_dir() / "master.key"


def _load_master_key():
    # type: () -> bytes
    path = _master_key_path()
    key = _key_cache.get(str(path))
    if key is not None:
        return key
    if path.exists():
        with open(str(path), "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError("master.key is corrupt (expected 32 bytes)")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        key = os.urandom(32)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        logger.info("generated new master key at %s", path)
    _key_cache[str(path)] = key
    return key


def is_encrypted(s):
    # type: (object) -> bool
    return isinstance(s, str) and s.startswith(PREFIX)


def encrypt(plaintext):
    # type: (str) -> str
    """Encrypt a string -> 'enc:v1:' + b64(nonce + ciphertext)."""
    key = _load_master_key()
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def decrypt(token):
    # type: (str) -> str
    """Decrypt a token produced by encrypt()."""
    if not is_encrypted(token):
        raise ValueError("not an encrypted token")
    raw = base64.b64decode(token[len(PREFIX):])
    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    key = _load_master_key()
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
