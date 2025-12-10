from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Sequence


@dataclass(frozen=True)
class PluginEntry:
    name: str
    description: str


@dataclass(frozen=True)
class PluginSection:
    title: str
    plugins: Sequence[PluginEntry]


_VOL3_SECTIONS: list[PluginSection] = [
    PluginSection(
        "Getting Started",
        [
            PluginEntry("windows.info", "OS build, kernel, KDBG offset and symbol hints"),
            PluginEntry("windows.pslist", "Enumerate active processes via EPROCESS list"),
            PluginEntry("windows.pstree", "Show parent/child process tree"),
            PluginEntry("windows.cmdline", "Display process command lines"),
            PluginEntry("windows.envars", "Dump process environment variables"),
        ],
    ),
    PluginSection(
        "Registry & Services",
        [
            PluginEntry("windows.registry.hivelist", "List registry hives located in memory"),
            PluginEntry("windows.registry.printkey", "Display registry key values recursively"),
            PluginEntry("windows.svcscan", "Enumerate registered services / drivers"),
            PluginEntry("windows.driverscan", "Enumerate kernel drivers"),
        ],
    ),
    PluginSection(
        "Malware & Injection",
        [
            PluginEntry("windows.malfind", "Scan for injected code, RWX pages"),
            PluginEntry("windows.dlllist", "List loaded DLLs per process"),
            PluginEntry("windows.modscan", "Find hidden/unlinked kernel modules"),
            PluginEntry("windows.handles", "Enumerate kernel object handles"),
        ],
    ),
    PluginSection(
        "Network & Connections",
        [
            PluginEntry("windows.netstat", "Active TCP/UDP endpoints with owning PID"),
            PluginEntry("windows.etw", "Event Tracing for Windows sessions"),
        ],
    ),
    PluginSection(
        "Credentials",
        [
            PluginEntry("windows.hashdump", "Dump SAM hashes (requires SYSTEM/SAM hives)"),
            PluginEntry("windows.lsadump", "Extract LSA secrets / cached creds"),
            PluginEntry("windows.cachedump", "Dump cached domain logons"),
        ],
    ),
    PluginSection(
        "Sensitive Data Discovery",
        [
            PluginEntry("windows.filescan", "Enumerate file objects to surface financial or personal documents"),
            PluginEntry("windows.dumpfiles", "Recover cached documents (medical, chat exports, explicit material)"),
            PluginEntry("windows.strings", "Extract ASCII/Unicode strings that expose chats, card numbers, or diaries"),
            PluginEntry("windows.memdump", "Dump process memory for applications caching private conversations"),
            PluginEntry("windows.registry.shellbags", "Review folder navigation history revealing ideology/affiliations"),
        ],
    ),
]

_VOL2_SECTIONS: list[PluginSection] = [
    PluginSection(
        "Getting Started",
        [
            PluginEntry("imageinfo", "Identify profile suggestions and KDBG offset"),
            PluginEntry("pslist", "Enumerate active processes via linked lists"),
            PluginEntry("pstree", "Process hierarchy tree"),
            PluginEntry("psscan", "Pool scan for hidden/unlinked EPROCESS"),
            PluginEntry("dlllist", "List loaded DLLs per process"),
        ],
    ),
    PluginSection(
        "Registry & Services",
        [
            PluginEntry("hivelist", "List registry hives in memory"),
            PluginEntry("printkey", "Dump registry keys/values"),
            PluginEntry("svcscan", "Enumerate services/drivers"),
            PluginEntry("envars", "Show process environment variables"),
        ],
    ),
    PluginSection(
        "Malware & Injection",
        [
            PluginEntry("malfind", "Detect injected code / hidden DLLs"),
            PluginEntry("modscan", "Pool scan for kernel modules"),
            PluginEntry("ldrmodules", "Check DLL load order anomalies"),
            PluginEntry("apihooks", "Detect API hooks in SSDT/IAT/EAT"),
        ],
    ),
    PluginSection(
        "Network & Connections",
        [
            PluginEntry("netscan", "Enumerate TCP/UDP sockets (Vista+)"),
            PluginEntry("connscan", "Scan for historic TCP connections (XP/2003)"),
            PluginEntry("connections", "Enumerate active TCP connections"),
        ],
    ),
    PluginSection(
        "Credentials",
        [
            PluginEntry("hashdump", "Dump SAM credential hashes"),
            PluginEntry("cachedump", "Dump cached domain logons"),
            PluginEntry("lsadump", "Extract LSA secrets"),
            PluginEntry("vaultcmd", "Show Windows Vault credential entries"),
        ],
    ),
]


def get_plugin_sections(version: Literal["v2", "v3"]) -> Sequence[PluginSection]:
    if version == "v2":
        return _VOL2_SECTIONS
    return _VOL3_SECTIONS


