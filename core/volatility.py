from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Literal, Sequence


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_VOLATILITY2_PATH = (
    PROJECT_ROOT
    / "tools"
    / "volatility2"
    / "volatility_2.6_win64_standalone"
    / "volatility_2.6_win64_standalone.exe"
)


class VolatilityError(RuntimeError):
    """Raised when a Volatility 3 command fails."""


class VolatilityRunner:
    def __init__(
        self,
        volatility3_path: str | None = None,
        volatility2_path: str | None = None,
        python_exec: str | None = None,
    ) -> None:
        self.volatility3_path = volatility3_path
        default_vol2 = DEFAULT_VOLATILITY2_PATH if DEFAULT_VOLATILITY2_PATH.exists() else None
        if volatility2_path is not None:
            self.volatility2_path = volatility2_path
        elif default_vol2 is not None:
            self.volatility2_path = str(default_vol2)
        else:
            self.volatility2_path = None
        self._python_exec = python_exec or sys.executable

    def run(
        self,
        image_path: Path,
        plugin: str,
        extra_args: Sequence[str] | None = None,
        volatility_path: str | None = None,
        version: Literal["v3", "v2"] = "v3",
    ) -> str:
        if not plugin.strip():
            raise VolatilityError("A Volatility plugin name is required.")
        image = Path(image_path).expanduser().resolve()
        if not image.exists():
            raise VolatilityError(f"Memory image not found: {image}")

        version_key = (version or "v3").lower()
        if version_key not in {"v3", "v2"}:
            raise VolatilityError(f"Unsupported Volatility version: {version}")

        version_label = "Volatility 3" if version_key == "v3" else "Volatility 2"
        resolved_path = volatility_path
        if resolved_path is None:
            resolved_path = self.volatility3_path if version_key == "v3" else self.volatility2_path

        normalized_plugin = self._normalize_plugin_name(plugin, version_key)

        def _run_command(cmd: list[str]) -> tuple[subprocess.CompletedProcess[str], str]:
            completed_proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=600)
            stdout_text = completed_proc.stdout.strip()
            stderr_text = completed_proc.stderr.strip()
            merged = "\n".join(part for part in (stdout_text, stderr_text) if part).strip()
            return completed_proc, merged

        if version_key == "v3":
            command = self._build_command_v3(resolved_path)
            import os

            if os.getenv("LOCALAPPDATA"):
                cache_path = os.path.join(os.getenv("LOCALAPPDATA"), "volatility3", "cache")
            else:
                cache_path = os.path.expanduser(os.path.join("~", ".local", "share", "volatility3", "cache"))
            os.makedirs(cache_path, exist_ok=True)
            command.extend(["-f", str(image)])
            if not extra_args or "--cache-path" not in extra_args:
                command.extend(["--cache-path", cache_path])
            command.append(normalized_plugin)
            if extra_args:
                command.extend(extra_args)
            completed, combined = _run_command(command)
        else:
            base_command = self._build_command_v2(resolved_path)
            command = base_command + ["-f", str(image), normalized_plugin]
            if extra_args:
                command.extend(extra_args)
            completed, combined = _run_command(command)

            if completed.returncode != 0 and "you must specify something to do" in combined.lower():
                # Some Volatility 2 builds expect the plugin immediately after the executable.
                retry_command = list(base_command)
                retry_command.append(normalized_plugin)
                retry_command.extend(["-f", str(image)])
                if extra_args:
                    retry_command.extend(extra_args)
                completed, combined = _run_command(retry_command)

        if completed.returncode != 0:
            # Check for invalid plugin errors
            if "invalid choice" in combined.lower() or "error: argument PLUGIN" in combined.lower():
                # Invalid plugin detected
                error_msg = (
                    f"⚠️ Invalid Plugin Error:\n\n"
                    f"The plugin '{plugin}' is not available in your {version_label} installation.\n\n"
                    f"Error details:\n{combined}\n\n"
                    "Common reasons:\n"
                    "1. Plugin name is misspelled or incorrect\n"
                    "2. Plugin is not available for the selected Volatility version\n"
                    "3. Plugin requires additional dependencies\n"
                    "4. Plugin name changed in newer versions\n\n"
                    "Solutions:\n"
                    "1. Verify the plugin name is correct (case-sensitive)\n"
                    "2. Check documentation for the selected Volatility version to confirm availability\n"
                    "3. Try running: vol.exe --help (or volatility.exe --help) to see available plugins\n"
                    "4. Some plugins exist only in Volatility 2 (e.g., windows.vaults) or only in Volatility 3\n\n"
                    "Note: Plugins like 'windows.vaults' and 'windows.vaultcmd' require Volatility 2."
                )
                raise VolatilityError(error_msg)
            if "You must specify something to do" in combined:
                raise VolatilityError(
                    f"{version_label} did not receive a plugin to run.\n\n"
                    "Make sure you selected a plugin (e.g., windows.info) and that it is not a separator line."
                )
            
            # Check for symbol file issues
            if "Unsatisfied requirement" in combined or "symbol" in combined.lower():
                # Symbol file issue
                error_msg = (
                    f"{version_label} exited with code {completed.returncode}.\n\n"
                    f"{combined}\n\n"
                    "⚠️ Symbol File Issue Detected:\n"
                    "Volatility needs Windows symbol files (PDB) to analyze memory images.\n\n"
                    "Solutions:\n"
                    "1. Let Volatility download symbols automatically (recommended):\n"
                    "   - Volatility will download symbols on first use\n"
                    "   - This may take several minutes\n"
                    "   - Ensure you have internet connection\n"
                    "   - The cache update progress you see is normal\n\n"
                    "2. Download symbols manually:\n"
                    "   - Run: vol.exe -f <image> windows.info --offline\n"
                    "   - Or use: vol.exe --single-location <symbol_path>\n\n"
                    "3. Check symbol cache location:\n"
                    "   - Default: ~/.local/share/volatility3/symbols\n"
                    "   - Or check: vol.exe --cache-path\n\n"
                    "4. For offline analysis, download symbols first:\n"
                    "   - Use: vol.exe -f <image> windows.info\n"
                    "   - This will download required symbols\n"
                    "   - Then you can use --offline for subsequent runs\n\n"
                    "Note: The 'Updating caches' progress is normal - let it complete."
                )
                raise VolatilityError(error_msg)
            # Other errors
            raise VolatilityError(f"{version_label} exited with code {completed.returncode}.\n{combined}")

        return combined

    def probe(self, volatility_path: str | None = None, version: Literal["v3", "v2"] = "v3") -> str:
        """Probe Volatility installation by running --help to verify it works."""
        version_key = (version or "v3").lower()
        if version_key not in {"v3", "v2"}:
            raise VolatilityError(f"Unsupported Volatility version: {version}")

        version_label = "Volatility 3" if version_key == "v3" else "Volatility 2"
        resolved_path = volatility_path
        if resolved_path is None:
            resolved_path = self.volatility3_path if version_key == "v3" else self.volatility2_path

        if version_key == "v3":
            command = self._build_command_v3(resolved_path)
        else:
            command = self._build_command_v2(resolved_path)

        command = command + ["--help"]
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
        stdout = completed.stdout.strip()
        stderr = completed.stderr.strip()
        
        # --help typically returns non-zero, but we want to see the usage output
        combined = "\n".join(part for part in (stdout, stderr) if part).strip()
        
        if "Volatility" in combined or "usage:" in combined.lower() or "PLUGIN" in combined:
            # Success - we got the help/usage output
            version_info = ""
            if "Volatility" in combined:
                # Extract version if present
                lines = combined.split("\n")
                for line in lines:
                    if "Volatility" in line and "Framework" in line:
                        version_info = line.strip()
                        break
            
            result = f"{version_label} is installed and working.\n\n"
            if version_info:
                result += f"{version_info}\n\n"
            result += f"Command: {' '.join(command)}\n\n"
            result += f"Usage information:\n{combined[:500]}"  # First 500 chars of usage
            return result
        
        if completed.returncode != 0:
            raise VolatilityError(
                f"Unable to probe {version_label} (exit {completed.returncode}).\n"
                f"{combined}".strip()
            )
        return combined or f"{version_label} responded without output."

    def get_default_path(self, version: Literal["v3", "v2"]) -> str | None:
        version_key = (version or "v3").lower()
        if version_key not in {"v3", "v2"}:
            return None

        if version_key == "v3":
            if self.volatility3_path:
                return self.volatility3_path
            try:
                return self._build_command_v3(None)[0]
            except VolatilityError:
                return None
        else:
            if self.volatility2_path:
                return self.volatility2_path
            try:
                return self._build_command_v2(None)[0]
            except VolatilityError:
                return None

    def _normalize_plugin_name(self, plugin: str, version_key: str) -> str:
        if version_key == "v2" and "." in plugin:
            return plugin.split(".")[-1]
        return plugin

    def _build_command_v3(self, volatility_path: str | None) -> list[str]:
        if volatility_path:
            resolved = Path(volatility_path).expanduser().resolve()
            if not resolved.exists():
                raise VolatilityError(f"Configured Volatility 3 path does not exist: {resolved}")
            return [str(resolved)]

        # Try to locate a system-wide binary first
        for candidate in ("volatility3", "vol", "vol.py"):
            found = shutil.which(candidate)
            if found:
                return [found]

        # Try to find volatility3 in Python Scripts directory
        python_exe = Path(self._python_exec)
        if python_exe.exists():
            # Look for volatility3.exe or vol.exe in Scripts directory
            scripts_dir = python_exe.parent / "Scripts"
            if scripts_dir.exists():
                # Check for vol.exe first (common on Windows)
                for script_name in ("vol.exe", "volatility3.exe", "vol", "volatility3"):
                    script_path = scripts_dir / script_name
                    if script_path.exists():
                        return [str(script_path)]
            
            # Also check in user site-packages Scripts (Windows Store Python)
            try:
                import site
                user_site = site.getusersitepackages()
                if user_site:
                    user_scripts = Path(user_site).parent / "Scripts"
                    if user_scripts.exists():
                        # Check for vol.exe first (common on Windows)
                        for script_name in ("vol.exe", "volatility3.exe", "vol", "volatility3"):
                            script_path = user_scripts / script_name
                            if script_path.exists():
                                return [str(script_path)]
            except Exception:
                pass

        # Last resort: provide helpful error with specific path
        try:
            import site
            user_site = site.getusersitepackages()
            if user_site:
                user_scripts = Path(user_site).parent / "Scripts"
                suggested_path = user_scripts / "vol.exe"
                if suggested_path.exists():
                    raise VolatilityError(
                        f"Volatility 3 found at: {suggested_path}\n"
                        f"But auto-detection failed. Please enter this path manually in the 'Volatility Path' field:\n\n"
                        f"{suggested_path}"
                    )
        except Exception:
            pass
        
        raise VolatilityError(
            "Volatility 3 not found. Please specify the path manually.\n\n"
            "Options:\n"
            "1. Find vol.exe or volatility3.exe in your Python Scripts directory:\n"
            f"   {python_exe.parent / 'Scripts'}\n"
            "   Or for Windows Store Python:\n"
            "   C:\\Users\\<YourUser>\\AppData\\Local\\Packages\\PythonSoftwareFoundation.Python.*\\LocalCache\\local-packages\\Python*\\Scripts\n\n"
            "2. Install Volatility 3 if not installed:\n"
            "   python -m pip install volatility3\n\n"
            "3. After installation, find vol.exe (or volatility3.exe) and enter its path in the 'Volatility Path' field."
        )

    def _build_command_v2(self, volatility_path: str | None) -> list[str]:
        if volatility_path:
            resolved = Path(volatility_path).expanduser().resolve()
            if not resolved.exists():
                raise VolatilityError(f"Configured Volatility 2 path does not exist: {resolved}")
            return [str(resolved)]

        for candidate in ("volatility", "volatility.exe", "volatility2", "volatility2.exe"):
            found = shutil.which(candidate)
            if found:
                return [found]

        python_exe = Path(self._python_exec)
        if python_exe.exists():
            scripts_dir = python_exe.parent / "Scripts"
            if scripts_dir.exists():
                for script_name in ("volatility.exe", "volatility", "volatility2.exe", "volatility2"):
                    script_path = scripts_dir / script_name
                    if script_path.exists():
                        return [str(script_path)]

        raise VolatilityError(
            "Volatility 2 not found. Please specify the path manually or install it:\n"
            "  - Download from https://github.com/volatilityfoundation/volatility\n"
            "  - Or install via pip: python -m pip install volatility\n"
        )

