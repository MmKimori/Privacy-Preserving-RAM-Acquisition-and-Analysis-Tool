from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class User:
    user_id: str
    name: str
    role: str  # Admin | Investigator | Viewer | WarrantOfficer


@dataclass(frozen=True)
class MemoryImage:
    image_id: str
    sha256: str
    recovered_by: str  # user_id
    captured_at: datetime
    case_id: str
    path: str
    size_bytes: int


