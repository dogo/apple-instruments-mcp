from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RecordingTarget:
    label: str
    device_id: str | None = None
    bundle_id: str | None = None
    launch_path: str | None = None
    launch_args: str | None = None
    process_name: str | None = None
    pid: int | None = None
    all_processes: bool = False

    @classmethod
    def build(
        cls,
        *,
        bundle_id: str | None = None,
        device_id: str | None = None,
        launch_path: str | None = None,
        launch_args: str | None = None,
        process_name: str | None = None,
        pid: int | None = None,
        all_processes: bool = False,
    ) -> RecordingTarget:
        choices = [
            bool(bundle_id),
            bool(launch_path),
            bool(process_name),
            pid is not None,
            all_processes,
        ]
        if sum(choices) != 1:
            raise ValueError(
                "Select exactly one target: bundle_id, launch_path, process_name, pid, or all_processes."
            )

        if bundle_id:
            label = bundle_id
        elif launch_path:
            label = launch_path
        elif process_name:
            label = process_name
        elif pid is not None:
            label = f"pid:{pid}"
        else:
            label = "all processes"

        return cls(
            label=label,
            device_id=device_id,
            bundle_id=bundle_id,
            launch_path=launch_path,
            launch_args=launch_args,
            process_name=process_name,
            pid=pid,
            all_processes=all_processes,
        )

    def xctrace_args(self) -> list[str]:
        args: list[str] = []
        if self.device_id:
            args.extend(["--device", self.device_id])

        if self.all_processes:
            args.append("--all-processes")
            return args

        if self.pid is not None:
            args.extend(["--attach", str(self.pid)])
            return args

        if self.process_name:
            args.extend(["--attach", self.process_name])
            return args

        launch_target = self.launch_path or self.bundle_id
        if not launch_target:
            raise ValueError("Missing launch target.")

        args.extend(["--launch", "--", launch_target])
        if self.launch_args:
            args.extend(shlex.split(self.launch_args))
        return args

    def validate(self) -> list[str]:
        """Pre-flight checks that don't need a subprocess. Returns reasons the target looks invalid."""
        errors: list[str] = []

        if self.launch_path:
            expanded = Path(os.path.expanduser(self.launch_path))
            if not expanded.exists():
                errors.append(f"launch_path does not exist on this Mac: {self.launch_path}")

        if self.pid is not None:
            if self.pid <= 0:
                errors.append(f"pid must be a positive integer (got {self.pid}).")
            else:
                try:
                    os.kill(self.pid, 0)
                except ProcessLookupError:
                    errors.append(f"No process with pid {self.pid} is currently running.")
                except PermissionError:
                    # Process exists but we can't signal it; xctrace may still attach with proper rights.
                    pass

        if self.bundle_id and not re.fullmatch(r"[A-Za-z0-9._-]+", self.bundle_id):
            errors.append(
                f"bundle_id '{self.bundle_id}' contains characters xctrace does not accept "
                "(use reverse-DNS style, letters/digits/dots/hyphens only)."
            )

        return errors


def format_target_error(target: RecordingTarget, template: str, error: str) -> str:
    msg = error.lower()
    lines = [f"Error profiling with template '{template}' against {target.label}: {error}", ""]

    bundle_missing = ("not installed" in msg or "could not find application" in msg) and target.bundle_id
    if bundle_missing:
        lines.append(f"Bundle ID '{target.bundle_id}' is not installed on the selected device/simulator.")
        if target.device_id:
            lines.append(
                f"- Confirm with `xcrun simctl listapps {target.device_id}` (simulators) or Devices & Simulators."
            )
        lines.append("- Install the app first via Xcode or `xcrun simctl install`.")
        return "\n".join(lines)

    if "no such process" in msg or "no process" in msg:
        lines.append(f"Process is not running (target: {target.label}).")
        if target.pid is not None:
            lines.append(f"- Confirm with `ps -p {target.pid}` before launching the profiler.")
        if target.process_name:
            lines.append(f"- Find a live PID with `pgrep -f {target.process_name}`.")
        return "\n".join(lines)

    device_unresolved = "device" in msg and (
        "not found" in msg
        or "could not find" in msg
        or "could not be found" in msg
        or "unknown" in msg
    )
    if device_unresolved:
        lines.append("xctrace could not resolve the device/simulator.")
        lines.append("- Run the list_devices tool to see what's visible right now.")
        if target.device_id:
            lines.append(f"- Boot the simulator first: `xcrun simctl boot {target.device_id}`.")
        else:
            lines.append("- Pass device_id from list_devices, or omit it to profile host macOS.")
        return "\n".join(lines)

    if "no such file" in msg and target.launch_path:
        lines.append(f"xctrace rejected the launch_path: {target.launch_path}")
        lines.append("- For macOS apps, point at the `.app` bundle directory, not the binary inside.")
        lines.append("- For CLI tools, use an absolute path to the executable.")
        return "\n".join(lines)

    if "xcode" in msg or "xcrun: error" in msg or "command line tools" in msg:
        lines.append("Xcode command-line tools look unavailable.")
        lines.append("- Run `xcode-select --install`, or open Xcode once to accept the license.")
        lines.append("- Confirm with `xcrun xctrace help`.")
        return "\n".join(lines)

    lines.append("Common causes for this target:")
    if target.bundle_id:
        lines.extend(
            [
                "- App not installed on the selected device/simulator.",
                "- Simulator not booted: `xcrun simctl boot <UDID>`.",
                "- Physical device: enable UI Automation in Settings > Developer.",
            ]
        )
    elif target.launch_path:
        lines.extend(
            [
                "- launch_path is invalid or not a runnable macOS binary/.app.",
                "- Binary lacks signing/entitlements Instruments needs for the chosen template.",
            ]
        )
    elif target.pid is not None or target.process_name:
        lines.extend(
            [
                "- Process is no longer running (it may have exited before profiling started).",
                "- Process is sandboxed; xctrace may need elevated rights to attach.",
            ]
        )
    elif target.all_processes:
        lines.extend(
            [
                "- This template doesn't support --all-processes (try a process_name target).",
                "- Recording all processes typically requires `sudo`.",
            ]
        )
    lines.append("- Xcode CLI tools missing: `xcode-select --install`.")
    return "\n".join(lines)
