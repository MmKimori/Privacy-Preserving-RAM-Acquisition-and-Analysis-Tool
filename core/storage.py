from __future__ import annotations

from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Iterable

from .models import MemoryImage
from .secure_store import EncryptedJsonStore, SecretKeyManager


class EvidenceStore:
    """Minimal JSON-backed store for captured RAM images."""

    def __init__(self, db_path: Path | None = None) -> None:
        default_dir = Path.home() / ".ram_acq"
        encrypted_path = db_path or (default_dir / "evidence.json.enc")
        self._db_path = encrypted_path.expanduser().resolve()
        key_manager = SecretKeyManager("evidence", base_dir=default_dir / "keys")
        self._secure_store = EncryptedJsonStore(self._db_path, key_manager.load_key())
        self._lock = Lock()
        if not self._db_path.exists():
            self._secure_store.write([])

    def list_images(self) -> list[MemoryImage]:
        data = self._read()
        return [self._to_model(entry) for entry in data]

    def add_image(self, image: MemoryImage) -> None:
        payload = {
            "image_id": image.image_id,
            "sha256": image.sha256,
            "recovered_by": image.recovered_by,
            "captured_at": image.captured_at.isoformat(),
            "case_id": image.case_id,
            "path": image.path,
            "size_bytes": image.size_bytes,
        }
        with self._lock:
            data = self._read()
            data.append(payload)
            self._write(data)

    def clear(self) -> None:
        with self._lock:
            self._write([])

    def _read(self) -> list[dict]:
        return list(self._secure_store.read([]))

    def _write(self, data: Iterable[dict]) -> None:
        self._secure_store.write(list(data))

    def _to_model(self, payload: dict) -> MemoryImage:
        return MemoryImage(
            image_id=payload["image_id"],
            sha256=payload["sha256"],
            recovered_by=payload["recovered_by"],
            captured_at=datetime.fromisoformat(payload["captured_at"]),
            case_id=payload["case_id"],
            path=payload["path"],
            size_bytes=int(payload.get("size_bytes", 0)),
        )

