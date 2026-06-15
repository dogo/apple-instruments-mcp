from __future__ import annotations

import asyncio
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from apple_instruments_mcp.analysis.targets import RecordingTarget

PREFLIGHT_TIMEOUT_SECONDS = 5.0


async def run_command(*args: str, timeout: float | None = None) -> str:
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise RuntimeError(f"Command timed out: {' '.join(args)}") from None

    output = stdout.decode("utf-8", errors="replace")
    if process.returncode != 0:
        raise RuntimeError(output.strip() or f"Command failed: {' '.join(args)}")
    return output


async def list_devices() -> str:
    return await run_command("xcrun", "xctrace", "list", "devices")


async def list_templates() -> str:
    return await run_command("xcrun", "xctrace", "list", "templates")


def parse_xctrace_listing(output: str) -> dict[str, list[dict[str, str]]]:
    sections: dict[str, list[dict[str, str]]] = {}
    current_section = "items"

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.endswith(":") and not line.startswith("-"):
            current_section = line[:-1].strip().lower().replace(" ", "_")
            sections.setdefault(current_section, [])
            continue

        item = {"name": line}
        parenthetical = re.findall(r"\(([^()]+)\)", line)
        if parenthetical:
            item["details"] = ", ".join(parenthetical)
            candidate_id = parenthetical[-1]
            if re.fullmatch(r"[A-Fa-f0-9-]{8,}", candidate_id):
                item["id"] = candidate_id

        sections.setdefault(current_section, []).append(item)

    return sections


def list_as_json(output: str) -> str:
    return json.dumps(parse_xctrace_listing(output), indent=2, sort_keys=True)


def build_record_command(
    template: str,
    target: RecordingTarget,
    time_limit_seconds: int,
    output_path: Path,
) -> list[str]:
    args = [
        "xcrun",
        "xctrace",
        "record",
        "--template",
        template,
        "--time-limit",
        f"{time_limit_seconds}s",
        "--output",
        str(output_path),
    ]
    args.extend(target.xctrace_args())
    return args


def format_command(args: list[str]) -> str:
    return shlex.join(args)


async def record_trace(
    template: str,
    target: RecordingTarget,
    time_limit_seconds: int,
    output_path: Path,
) -> None:
    timeout = time_limit_seconds + 30
    args = build_record_command(template, target, time_limit_seconds, output_path)
    await run_command(*args, timeout=timeout)


@dataclass(frozen=True)
class PreflightFinding:
    severity: str  # "blocker" | "warning"
    message: str
    hints: tuple[str, ...] = ()


def _find_simulator_state(simctl_json: str, device_id: str) -> str | None:
    """Return the boot state for device_id from `simctl list devices -j` output, or None if not a simulator."""
    try:
        payload = json.loads(simctl_json)
    except json.JSONDecodeError:
        return None
    target_udid = device_id.lower()
    for entries in (payload.get("devices") or {}).values():
        for entry in entries or []:
            if str(entry.get("udid", "")).lower() == target_udid:
                return str(entry.get("state", "Unknown"))
    return None


async def preflight_ios_target(device_id: str, bundle_id: str) -> list[PreflightFinding]:
    """Pre-flight an iOS simulator target before xctrace record.

    Returns findings the caller should surface. Physical devices (not in simctl list) return [].
    """
    findings: list[PreflightFinding] = []

    try:
        simctl_output = await run_command(
            "xcrun", "simctl", "list", "devices", "-j", timeout=PREFLIGHT_TIMEOUT_SECONDS
        )
    except RuntimeError as exc:
        message = str(exc)
        if "timed out" in message.lower():
            findings.append(
                PreflightFinding(
                    "blocker",
                    "CoreSimulator did not respond to `simctl list devices` within "
                    f"{int(PREFLIGHT_TIMEOUT_SECONDS)}s.",
                    (
                        "The CoreSimulator service is likely wedged.",
                        "Try: `killall -9 com.apple.CoreSimulator.CoreSimulatorService` then retry.",
                    ),
                )
            )
        else:
            findings.append(PreflightFinding("warning", f"`simctl list devices` failed: {message}"))
        return findings

    state = _find_simulator_state(simctl_output, device_id)
    if state is None:
        return []  # not a simulator (likely physical device); skip simctl checks

    if state != "Booted":
        findings.append(
            PreflightFinding(
                "blocker",
                f"Simulator {device_id} is in state '{state}', not Booted.",
                (f"Boot first: `xcrun simctl boot {device_id}`",),
            )
        )
        return findings

    try:
        await run_command(
            "xcrun",
            "simctl",
            "get_app_container",
            device_id,
            bundle_id,
            "app",
            timeout=PREFLIGHT_TIMEOUT_SECONDS,
        )
    except RuntimeError as exc:
        message = str(exc)
        lowered = message.lower()
        if "timed out" in lowered:
            findings.append(
                PreflightFinding(
                    "blocker",
                    f"CoreSimulator did not respond to `simctl get_app_container {device_id} {bundle_id}` "
                    f"within {int(PREFLIGHT_TIMEOUT_SECONDS)}s.",
                    (
                        "The simulator process is likely wedged. This is a CoreSimulator state issue, "
                        "not an Instruments template issue.",
                        f"Try: `xcrun simctl shutdown {device_id} && xcrun simctl boot {device_id}`",
                        "If that doesn't help: `killall -9 com.apple.CoreSimulator.CoreSimulatorService` then retry.",
                    ),
                )
            )
        elif "no such" in lowered or "not installed" in lowered or "no app" in lowered or "unable to find" in lowered:
            findings.append(
                PreflightFinding(
                    "blocker",
                    f"App '{bundle_id}' is not installed on simulator {device_id}.",
                    (
                        f"List installed apps: `xcrun simctl listapps {device_id}`",
                        f"Install: `xcrun simctl install {device_id} /path/to/App.app`",
                    ),
                )
            )
        else:
            findings.append(
                PreflightFinding("warning", f"`simctl get_app_container` failed: {message}")
            )
    return findings


def format_preflight_findings(template: str, target_label: str, findings: list[PreflightFinding]) -> str:
    lines = [f"Refusing to record with template '{template}' against {target_label}: pre-flight failed.", ""]
    for finding in findings:
        marker = "-" if finding.severity == "blocker" else "*"
        lines.append(f"{marker} {finding.message}")
        for hint in finding.hints:
            lines.append(f"  - {hint}")
    return "\n".join(lines)


async def export_xml(
    trace_path: Path,
    output_xml_path: Path,
    *,
    xpath: str | None = None,
    toc: bool = False,
) -> None:
    if not xpath and not toc:
        raise ValueError("export_xml requires either xpath or toc=True")
    args = [
        "xcrun",
        "xctrace",
        "export",
        "--input",
        str(trace_path),
        "--output",
        str(output_xml_path),
    ]
    if xpath:
        args.extend(["--xpath", xpath])
    else:
        args.append("--toc")
    await run_command(*args)
