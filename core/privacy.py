from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class PrivacyCategory:
    key: str
    label: str
    description: str
    plugin: str
    plugin_rationale: str


PRIVACY_CATEGORIES: Sequence[PrivacyCategory] = [
    PrivacyCategory(
        key="financial",
        label="Financial Details",
        description="Complete credit card numbers, banking credentials, balances, "
        "and transaction activity unrelated to the investigation.",
        plugin="windows.filescan",
        plugin_rationale="Scans file objects that commonly reference exported bank statements and payment caches.",
    ),
    PrivacyCategory(
        key="health",
        label="Health & Medical Information",
        description="Medical histories, diagnoses, therapy notes, or prescription details.",
        plugin="windows.dumpfiles",
        plugin_rationale="Carves cached documents (PDF/EMR exports) that often hold medical information.",
    ),
    PrivacyCategory(
        key="communications",
        label="Personal Communications",
        description="Private chat logs, diary entries, or intimate letters that have no probative value.",
        plugin="windows.strings",
        plugin_rationale="Extracts printable strings that expose chat transcripts and diary fragments in memory.",
    ),
    PrivacyCategory(
        key="credentials",
        label="Credentials / Logins",
        description="Passwords or tokens for unrelated services such as personal email or social accounts.",
        plugin="windows.lsadump",
        plugin_rationale="Dumps LSA secrets and DPAPI blobs that contain cached user credentials.",
    ),
    PrivacyCategory(
        key="sexual",
        label="Sexual Orientation / Preferences",
        description="Explicit material or conversations about private sexual activity or orientation.",
        plugin="windows.memdump",
        plugin_rationale="Dumps process memory to review applications that cached explicit or personal content.",
    ),
    PrivacyCategory(
        key="beliefs",
        label="Political or Religious Beliefs",
        description="Data about political party membership, religious affiliation, or ideology discussions not linked to a crime.",
        plugin="windows.registry.printkey",
        plugin_rationale="Inspects registry keys (shellbags/MRUs) that show organizations, groups, or reading history.",
    ),
]

_PRIVACY_CATEGORY_INDEX = {category.key: category for category in PRIVACY_CATEGORIES}

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP]"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "[MAC]"),
    (re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"), "[JWT]"),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "[AWS_KEY]"),
    # Long contiguous hex strings (hashes, keys)
    (re.compile(r"\b[0-9A-Fa-f]{32,}\b"), "[HEX_SECRET]"),
    # Repeated hex byte dumps (e.g., DPAPI / NL$KM blocks)
    (re.compile(r"(?:\b[0-9A-Fa-f]{2}\s+){8,}\b[0-9A-Fa-f]{2}\b"), "[HEX_BLOCK]"),
]


def mask_privacy_sensitive(text: str) -> str:
    masked = text
    for pattern, replacement in _PATTERNS:
        masked = pattern.sub(replacement, masked)
    return masked


def get_privacy_category(key: str) -> PrivacyCategory | None:
    return _PRIVACY_CATEGORY_INDEX.get(key)


