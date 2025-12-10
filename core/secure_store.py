from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from .crypto import aes256_decrypt, aes256_encrypt


class SecretKeyManager:


    def __init__(self, key_name: str, base_dir: Path | None = None) -> None:
        self._base_dir = (base_dir or (Path.home() / ".ram_acq" / "keys")).expanduser().resolve()
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._key_path = self._base_dir / f"{key_name}.key"

    def load_key(self) -> bytes:
        if not self._key_path.exists():
            self._key_path.write_bytes(os.urandom(32))
        key = self._key_path.read_bytes()
        if len(key) != 32:
            raise ValueError(f"Key at {self._key_path} must be exactly 32 bytes.")
        return key


class EncryptedJsonStore:


    def __init__(self, file_path: Path, key: bytes) -> None:
        self._file_path = file_path.expanduser().resolve()
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        self._key = key

    def read(self, default: Any) -> Any:
        if not self._file_path.exists():
            return default
        raw = self._file_path.read_text(encoding="utf-8")
        if not raw.strip():
            return default

        try:
            envelope = json.loads(raw)
            iv_b64 = envelope["iv"]
            ciphertext_b64 = envelope["ciphertext"]
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            plaintext = aes256_decrypt(iv, ciphertext, self._key).decode("utf-8")
            return json.loads(plaintext)
        except Exception:
            # Assume legacy plaintext JSON, re-encrypt on next write
            try:
                legacy = json.loads(raw)
            except json.JSONDecodeError:
                return default
            self.write(legacy)
            return legacy

    def write(self, value: Any) -> None:
        payload = json.dumps(value, indent=2, default=str)
        iv, ciphertext = aes256_encrypt(payload.encode("utf-8"), self._key)
        envelope = {
            "iv": base64.b64encode(iv).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        self._file_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")


