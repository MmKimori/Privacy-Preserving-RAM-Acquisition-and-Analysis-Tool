from __future__ import annotations

import os
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def _pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def derive_key(key_material: bytes) -> bytes:
    """Derive a 32-byte key for AES-256 from input bytes."""
    from hashlib import sha256
    return sha256(key_material).digest()


def aes256_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """Encrypt using AES-256-CBC. Returns (iv, ciphertext)."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(_pad(plaintext))
    return iv, ciphertext


def aes256_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-CBC ciphertext and remove padding."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return _unpad(cipher.decrypt(ciphertext))
