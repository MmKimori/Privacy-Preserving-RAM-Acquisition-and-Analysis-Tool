from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Iterable

from .secure_store import EncryptedJsonStore, SecretKeyManager


class EncryptedUserStore:
    """Encrypted persistence for authentication users."""

    def __init__(self, store_path: Path | None = None) -> None:
        default_dir = Path.home() / ".ram_acq"
        encrypted_path = store_path or (default_dir / "users.json.enc")
        self._store_path = encrypted_path.expanduser().resolve()
        key_manager = SecretKeyManager("users", base_dir=default_dir / "keys")
        self._secure_store = EncryptedJsonStore(self._store_path, key_manager.load_key())
        self._lock = Lock()
        if not self._store_path.exists():
            self._secure_store.write({"users": []})

    def list_users(self) -> list[dict]:
        with self._lock:
            data = self._secure_store.read({"users": []})
            users = data.get("users", [])
            return list(users)

    def save_users(self, users: Iterable[dict]) -> None:
        with self._lock:
            payload = {"users": list(users)}
            self._secure_store.write(payload)


