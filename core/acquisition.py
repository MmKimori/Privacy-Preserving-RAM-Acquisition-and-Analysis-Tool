from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Sequence

from .models import MemoryImage


class AcquisitionError(RuntimeError):
    """Raised when a memory acquisition task fails."""


@dataclass(frozen=True)
class AcquisitionConfig:
    case_id: str
    operator_id: str
    output_dir: Path
    tool_path: Path | None = None  # Path to WinPmem executable
    extra_args: Sequence[str] | None = None
    label: str | None = None


@dataclass(frozen=True)
class AcquisitionResult:
    image: MemoryImage
    log: str
    command: Sequence[str]


class MemoryAcquisitionService:
    """Co-ordinates RAM image capture and hashing."""

    def __init__(self, chunk_size: int = 4 * 1024 * 1024) -> None:
        self._chunk_size = chunk_size

    def acquire(self, config: AcquisitionConfig) -> AcquisitionResult:
        if not config.case_id.strip():
            raise AcquisitionError("Case ID is required.")

        output_dir = config.output_dir.expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.utcnow()
        image_id = config.label or f"{config.case_id}_{timestamp.strftime('%Y%m%d_%H%M%S')}"
        image_path = output_dir / f"{image_id}.raw"

        command, log = self._capture_image(image_path, config)
        sha256 = self._hash_file(image_path)
        size_bytes = image_path.stat().st_size

        image = MemoryImage(
            image_id=image_id,
            sha256=sha256,
            recovered_by=config.operator_id,
            captured_at=timestamp,
            case_id=config.case_id,
            path=str(image_path),
            size_bytes=size_bytes,
        )

        summary = [
            log.strip(),
            f"Saved at : {image.path}",
            f"SHA-256  : {image.sha256}",
            f"Size     : {size_bytes / (1024 * 1024):.2f} MiB",
        ]

        return AcquisitionResult(image=image, log="\n".join(filter(None, summary)), command=command)

    def _capture_image(self, image_path: Path, config: AcquisitionConfig) -> tuple[Sequence[str], str]:
        """Capture memory image using WinPmem."""
        tool_path = config.tool_path
        extra_args = list(config.extra_args or [])

        if not tool_path:
            raise AcquisitionError(
                "WinPmem path is required for acquisition.\n"
                "Specify the executable path before running memory capture."
            )

        tool_path_obj = Path(tool_path) if isinstance(tool_path, str) else tool_path
        if not tool_path_obj.exists():
            raise AcquisitionError(
                f"WinPmem executable not found at: {tool_path_obj}\n"
                "Provide a valid path to winpmem.exe before starting acquisition."
            )

        command: list[str] = [str(tool_path_obj)]

        # WinPmem 2.0.1 uses positional arguments: winpmem.exe [options] [output_path]
        # Newer versions may support --output flag, but we'll use positional for compatibility
        has_output_flag = any(arg in ("--output", "-o") for arg in extra_args)
        has_positional_output = any(
            i < len(extra_args) - 1 and extra_args[i] not in ("--output", "-o", "-d", "-I", "-u", "-W", "-0", "-1", "-2", "-h")
            for i in range(len(extra_args))
        )

        # Add extra args first (options like -2, -W, etc.)
        command.extend(extra_args)

        # Add output path as positional argument if not already specified
        if not has_output_flag and not has_positional_output:
            command.append(str(image_path))

        # WinPmem can take a long time for large memory dumps
        # Use unbuffered output and longer timeout
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=3600,  # 1 hour timeout for large memory dumps
            bufsize=1,  # Line buffered
        )
        combined_output = "\n".join(
            part.strip()
            for part in (completed.stdout, completed.stderr)
            if part and part.strip()
        ).strip()

        # Check if image was created even if exit code is non-zero
        # Sometimes WinPmem returns error code but still creates the file
        image_created = image_path.exists() and image_path.stat().st_size > 0
        image_size = image_path.stat().st_size if image_created else 0

        if completed.returncode != 0:
            if image_created:
                # Image was created despite error code - might be a warning or partial
                # Check if it looks like a complete dump (should be several GB for typical systems)
                size_mb = image_size / (1024 * 1024)
                if size_mb < 100:  # Less than 100MB is suspiciously small
                    error_msg = (
                        f"WinPmem exited with code {completed.returncode} and created a very small file "
                        f"({size_mb:.2f} MB). This may be a partial or incomplete dump.\n\n"
                        f"WinPmem Output:\n{combined_output}\n\n"
                        f"Possible causes:\n"
                        f"  • Acquisition was interrupted\n"
                        f"  • Insufficient disk space\n"
                        f"  • Permission issues during write\n"
                        f"  • System instability during acquisition\n\n"
                        f"Try running WinPmem again or check disk space."
                    )
                    raise AcquisitionError(error_msg)
                else:
                    # File looks reasonable - might be complete despite error code
                    warning_msg = (
                        f"WinPmem completed with exit code {completed.returncode}, "
                        f"but memory image was created ({size_mb:.2f} MB).\n\n"
                        f"Output:\n{combined_output}\n\n"
                        f"Note: The image may be complete. Verify the file size matches your system's RAM."
                    )
                    return command, warning_msg
            else:
                # Real error - no image created
                error_msg = self._format_winpmem_error(completed.returncode, combined_output)
                raise AcquisitionError(error_msg)

        if not image_created:
            raise AcquisitionError(
                "Acquisition completed but no RAM image was produced.\n\n"
                f"WinPmem Output:\n{combined_output}"
            )

        return command, combined_output or "WinPmem acquisition completed successfully."

    def _format_winpmem_error(self, exit_code: int, output: str) -> str:
        """Format WinPmem error messages with helpful diagnostics."""
        # Convert unsigned 32-bit exit code to signed if needed
        signed_code = exit_code
        if exit_code > 2147483647:  # > INT_MAX
            signed_code = exit_code - 4294967296  # Convert to signed
        
        base_msg = f"WinPmem failed with exit code {exit_code}"
        if signed_code != exit_code:
            base_msg += f" (signed: {signed_code})"
        
        lines = [base_msg]
        
        if output:
            lines.append("")
            lines.append("WinPmem Output:")
            lines.append(output)
        
        lines.append("")
        lines.append("Troubleshooting:")
        
        # Common error codes
        if signed_code == -1 or exit_code == 4294967295:
            lines.append("   Exit code -1 typically indicates:")
            lines.append("     • Missing Administrator/Elevated privileges")
            lines.append("     • Driver loading failure")
            lines.append("     • Antivirus/Security software blocking")
            lines.append("     • Incompatible Windows version")
            lines.append("")
            lines.append("  Solutions:")
            lines.append("  1. Run the application as Administrator:")
            lines.append("     - Right-click Python/VS Code → 'Run as administrator'")
            lines.append("     - Or use: Right-click → Run as administrator")
            lines.append("")
            lines.append("  2. Temporarily disable antivirus/security software")
            lines.append("  3. Check Windows compatibility:")
            lines.append("     - WinPmem works on Windows 7/8/10/11 (x64)")
            lines.append("     - Ensure you're using 64-bit Windows")
            lines.append("")
            lines.append("  4. Try different WinPmem arguments:")
            lines.append("     --format raw")
            lines.append("     --format elf")
            lines.append("     --format aff4")
            lines.append("")
            lines.append("  5. Download latest WinPmem from:")
            lines.append("     https://github.com/Velocidex/WinPmem/releases")
        elif signed_code == 1:
            lines.append("   Exit code 1: General error or incomplete acquisition")
            lines.append("     • Check WinPmem output above for details")
            lines.append("     • Verify output directory is writable")
            lines.append("     • Ensure sufficient disk space (RAM dumps can be large)")
            lines.append("     • Check if acquisition was interrupted")
            lines.append("     • If output shows progress (0%, 10%, etc.), it may have been:")
            lines.append("       - Interrupted by user or system")
            lines.append("       - Timed out (large memory dumps take time)")
            lines.append("       - Disk space exhausted")
            lines.append("     • Try running WinPmem directly from command line to see full output")
        elif signed_code == 2:
            lines.append("   Exit code 2: Invalid arguments")
            lines.append("     • Check 'WinPmem Args' field for syntax errors")
            lines.append("     • Try: --format raw --volume 1")
        else:
            lines.append(f"   Exit code {signed_code}: Unknown error")
            lines.append("     • Check WinPmem output above for details")
            lines.append("     • Verify WinPmem executable is not corrupted")
            lines.append("     • Try downloading WinPmem again")
        
        lines.append("")
        lines.append("For more help, see WinPmem documentation:")
        lines.append("  https://github.com/Velocidex/WinPmem")
        
        return "\n".join(lines)

    def _hash_file(self, image_path: Path) -> str:
        digest = hashlib.sha256()
        with image_path.open("rb") as fh:
            while chunk := fh.read(self._chunk_size):
                digest.update(chunk)
        return digest.hexdigest()

