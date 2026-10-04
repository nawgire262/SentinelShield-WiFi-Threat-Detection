import base64
import hashlib
import hmac
import json
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    AES = None
    get_random_bytes = None


class TelemetryCryptoError(Exception):
    pass


def generate_key_material():
    if get_random_bytes is None:
        raise TelemetryCryptoError("PyCryptodome is required for encryption")
    return get_random_bytes(32)


def encrypt_csv(path, key, output_path=None):
    if AES is None:
        raise TelemetryCryptoError("PyCryptodome is required for AES-GCM encryption")

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Telemetry file not found: {path}")

    plaintext = path.read_bytes()
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    sealed = nonce + tag + ciphertext

    if output_path is None:
        output_path = path.with_suffix(path.suffix + ".enc")
    else:
        output_path = Path(output_path)

    output_path.write_bytes(sealed)
    return output_path


def decrypt_csv(path, key, output_path=None):
    if AES is None:
        raise TelemetryCryptoError("PyCryptodome is required for AES-GCM encryption")

    path = Path(path)
    data = path.read_bytes()
    if len(data) < 28:
        raise TelemetryCryptoError("Encrypted payload too small")

    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    if output_path is None:
        output_path = path.with_suffix('')
    else:
        output_path = Path(output_path)

    output_path.write_bytes(plaintext)
    return output_path


def append_hash_chain(path, previous_hash=None):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Telemetry file not found: {path}")

    content = path.read_bytes()
    digest = hashlib.sha256(content).digest()
    if previous_hash:
        if isinstance(previous_hash, str):
            previous_hash = base64.b64decode(previous_hash.encode("utf-8"))
        elif not isinstance(previous_hash, (bytes, bytearray)):
            raise TypeError("previous_hash must be bytes or base64 string")
        digest = hashlib.sha256(previous_hash + digest).digest()
    return base64.b64encode(digest).decode("utf-8")


def sign_message(message, secret_key):
    if isinstance(message, str):
        message = message.encode("utf-8")
    return hmac.new(secret_key, message, hashlib.sha256).hexdigest()


def verify_signature(message, signature, secret_key):
    if isinstance(message, str):
        message = message.encode("utf-8")
    expected = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
