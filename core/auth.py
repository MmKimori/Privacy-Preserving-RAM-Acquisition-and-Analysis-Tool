from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Optional
from uuid import uuid4

from .models import User
from .user_store import EncryptedUserStore


class AuthService:
    """Authentication backed by an encrypted JSON credential store."""

    def __init__(self, user_store: EncryptedUserStore | None = None) -> None:
        self._user_store = user_store or EncryptedUserStore()
        self._records = self._load_users()
        if not self._records:
            self._seed_defaults()
            self._records = self._load_users()

    def authenticate(self, username: str, password: str) -> Optional[User]:
        record = self._records.get(username)
        if record is None:
            return None

        salt = base64.b64decode(record["salt"])
        expected_hash = record["password_hash"]
        computed_hash = self._hash_password(password, salt)
        if not hmac.compare_digest(expected_hash, computed_hash):
            return None

        return User(
            user_id=record["user_id"],
            name=record["name"],
            role=record["role"],
        )

    def list_users(self) -> list[dict]:
        return [record.copy() for record in self._records.values()]

    def upsert_user(
        self,
        *,
        username: str,
        name: str,
        role: str,
        password: str | None = None,
        full_access: bool = False,
    ) -> None:
        username = username.strip()
        if not username:
            raise ValueError("Username is required.")
        record = self._records.get(username)
        if record is None and not password:
            raise ValueError("Password is required for new users.")

        if password:
            salt = secrets.token_bytes(16)
            password_hash = self._hash_password(password, salt)
        else:
            salt = base64.b64decode(record["salt"])
            password_hash = record["password_hash"]

        user_id = record["user_id"] if record else f"u_{uuid4().hex}"
        new_record = {
            "username": username,
            "name": name or username,
            "role": role,
            "user_id": user_id,
            "salt": base64.b64encode(salt).decode("ascii"),
            "password_hash": password_hash,
            "full_access": full_access,
        }
        self._records[username] = new_record
        self._persist()

    def delete_user(self, username: str) -> None:
        record = self._records.get(username)
        if record is None:
            raise ValueError(f"User '{username}' does not exist.")

        if record["role"].lower() == "admin":
            admin_count = sum(1 for entry in self._records.values() if entry["role"].lower() == "admin")
            if admin_count <= 1:
                raise ValueError("At least one admin account must remain.")

        del self._records[username]
        self._persist()

    def _load_users(self) -> dict[str, dict]:
        users = {}
        for entry in self._user_store.list_users():
            username = entry.get("username")
            if not username:
                continue
            users[username] = entry
        return users

    def _seed_defaults(self) -> None:
        defaults = [
            self._create_user_record(
                username="admin",
                name="Administrator",
                role="Admin",
                password="admin123",
                user_id="u_admin",
                full_access=True,
            ),
            self._create_user_record(
                username="investigator",
                name="Investigator",
                role="Investigator",
                password="invest123",
                user_id="u_inv",
            ),
        ]
        self._user_store.save_users(defaults)
        self._records = {entry["username"]: entry for entry in defaults}

    def _create_user_record(
        self,
        *,
        username: str,
        name: str,
        role: str,
        password: str,
        user_id: str,
        full_access: bool = False,
    ) -> dict:
        salt = secrets.token_bytes(16)
        return {
            "username": username,
            "name": name,
            "role": role,
            "user_id": user_id,
            "salt": base64.b64encode(salt).decode("ascii"),
            "password_hash": self._hash_password(password, salt),
            "full_access": full_access,
        }

    def _hash_password(self, password: str, salt: bytes) -> str:
        return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()

    def _persist(self) -> None:
        self._user_store.save_users(self._records.values())


