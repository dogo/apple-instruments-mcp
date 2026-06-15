from __future__ import annotations

import asyncio
import contextlib
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from apple_instruments_mcp.analysis.targets import RecordingTarget

PREFLIGHT_TIMEOUT_SECONDS = 5.0
RECORD_STARTUP_TIMEOUT_SECONDS = 15.0
RECORD_TEARDOWN_GRACE_SECONDS = 15.0
RECORD_POLL_INTERVAL_SECONDS = 0.5
RECORD_STARTED_MARKER = "starting recording"


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


async def _quiet_run(*args: str, timeout: float | None = None) -> tuple[int, str]:
    """Run a command without raising; return (returncode, stdout). On timeout returncode is -1."""
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        return -1, ""
    return process.returncode if process.returncode is not None else 0, stdout.decode(
        "utf-8", errors="replace"
    )


async def find_stale_xctrace_pids() -> list[int]:
    """Return PIDs of running `xctrace` processes (exact name match)."""
    code, out = await _quiet_run("pgrep", "-x", "xctrace", timeout=2.0)
    # pgrep exits 0 when matches found, 1 when none, anything else is an error we ignore.
    if code not in (0, 1):
        return []
    return [int(token) for token in out.split() if token.isdigit()]


async def kill_stale_xctrace_processes() -> int:
    """Force-kill any running `xctrace` processes left over from prior runs. Returns count."""
    pids = await find_stale_xctrace_pids()
    if not pids:
        return 0
    await _quiet_run("kill", "-9", *[str(pid) for pid in pids], timeout=2.0)
    return len(pids)


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
    args = build_record_command(template, target, time_limit_seconds, output_path)
    await kill_stale_xctrace_processes()
    try:
        await _run_record_with_watchdog(args, time_limit_seconds)
    except RuntimeError:
        await kill_stale_xctrace_processes()
        raise


async def _terminate(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        process.kill()
    except ProcessLookupError:
        return
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(process.wait(), timeout=2.0)


async def _run_record_with_watchdog(
    args: list[str],
    time_limit_seconds: int,
    *,
    startup_timeout: float = RECORD_STARTUP_TIMEOUT_SECONDS,
    teardown_grace: float = RECORD_TEARDOWN_GRACE_SECONDS,
    poll_interval: float = RECORD_POLL_INTERVAL_SECONDS,
) -> None:
    """Spawn xctrace, stream its output, and bail out with a precise diagnosis on wedge.

    Two-phase watchdog:
      * Startup phase: process must print the `Starting recording` line within
        `startup_timeout` seconds, otherwise we report it never began recording.
      * Teardown phase: once we've seen that line, the process must exit within
        `time_limit_seconds + teardown_grace` seconds, otherwise we report it
        started but did not honor --time-limit.
    """
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    await _watchdog_loop(
        process,
        time_limit_seconds=time_limit_seconds,
        startup_timeout=startup_timeout,
        teardown_grace=teardown_grace,
        poll_interval=poll_interval,
    )


async def _watchdog_loop(
    process: asyncio.subprocess.Process,
    *,
    time_limit_seconds: int,
    startup_timeout: float,
    teardown_grace: float,
    poll_interval: float,
) -> None:
    stdout = process.stdout
    assert stdout is not None
    lines: list[str] = []
    started = False
    started_at: float | None = None
    loop = asyncio.get_running_loop()
    spawned_at = loop.time()

    async def read_lines() -> None:
        nonlocal started, started_at
        while True:
            chunk = await stdout.readline()
            if not chunk:
                return
            text = chunk.decode("utf-8", errors="replace")
            lines.append(text)
            if not started and RECORD_STARTED_MARKER in text.lower():
                started = True
                started_at = loop.time()

    reader = asyncio.create_task(read_lines())
    try:
        while not reader.done():
            await asyncio.wait({reader}, timeout=poll_interval)
            if reader.done():
                break
            now = loop.time()
            if started and started_at is not None:
                if now - started_at > time_limit_seconds + teardown_grace:
                    last = next(
                        (line.strip() for line in reversed(lines) if line.strip()),
                        "(no further output)",
                    )
                    await _terminate(process)
                    raise RuntimeError(
                        f"xctrace started recording but did not finish within "
                        f"{time_limit_seconds}s + {int(teardown_grace)}s grace. "
                        f"Last output: {last}"
                    )
            elif now - spawned_at > startup_timeout:
                await _terminate(process)
                raise RuntimeError(
                    f"xctrace did not begin recording within {int(startup_timeout)}s "
                    "(never reported `Starting recording`)."
                )
        await process.wait()
        if process.returncode != 0:
            output = "".join(lines).strip()
            raise RuntimeError(
                output or f"xctrace exited with status {process.returncode}"
            )
    finally:
        if not reader.done():
            reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await reader


@dataclass(frozen=True)
class PreflightFinding:
    severity: str  # "blocker" | "warning"
    message: str
    hints: tuple[str, ...] = ()


@dataclass(frozen=True)
class PreflightReport:
    findings: list[PreflightFinding]
    timings: dict[str, float]

    @property
    def blockers(self) -> list[PreflightFinding]:
        return [f for f in self.findings if f.severity == "blocker"]


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


async def probe_xctrace_health() -> PreflightFinding | None:
    """Fast probe of the xctrace CLI itself. Returns a blocker if it doesn't respond in time."""
    try:
        await run_command(
            "xcrun", "xctrace", "list", "devices", timeout=PREFLIGHT_TIMEOUT_SECONDS
        )
    except RuntimeError as exc:
        message = str(exc)
        if "timed out" in message.lower():
            return PreflightFinding(
                "blocker",
                f"`xctrace list devices` did not respond within {int(PREFLIGHT_TIMEOUT_SECONDS)}s.",
                (
                    "xctrace or its IPC channel appears wedged.",
                    "Try: `pkill -9 xctrace` then retry.",
                    "If persistent, open Instruments.app once to reset the tracing layer.",
                ),
            )
        return PreflightFinding("warning", f"`xctrace list devices` failed: {message}")
    return None


async def preflight_ios_target(device_id: str, bundle_id: str) -> PreflightReport:
    """Pre-flight an iOS simulator target before xctrace record.

    Returns findings the caller should surface plus per-probe wall-clock timings.
    Physical devices (not in simctl list) return an empty findings list with whatever
    probe timings were recorded before the device-type check.
    """
    findings: list[PreflightFinding] = []
    timings: dict[str, float] = {}
    loop = asyncio.get_running_loop()

    started = loop.time()
    xctrace_finding = await probe_xctrace_health()
    timings["xctrace_list_devices"] = loop.time() - started
    if xctrace_finding is not None:
        findings.append(xctrace_finding)
        if xctrace_finding.severity == "blocker":
            return PreflightReport(findings=findings, timings=timings)

    started = loop.time()
    try:
        simctl_output = await run_command(
            "xcrun", "simctl", "list", "devices", "-j", timeout=PREFLIGHT_TIMEOUT_SECONDS
        )
    except RuntimeError as exc:
        timings["simctl_list_devices"] = loop.time() - started
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
        return PreflightReport(findings=findings, timings=timings)
    timings["simctl_list_devices"] = loop.time() - started

    state = _find_simulator_state(simctl_output, device_id)
    if state is None:
        # not a simulator (likely physical device); skip simctl checks
        return PreflightReport(findings=[], timings=timings)

    if state != "Booted":
        findings.append(
            PreflightFinding(
                "blocker",
                f"Simulator {device_id} is in state '{state}', not Booted.",
                (f"Boot first: `xcrun simctl boot {device_id}`",),
            )
        )
        return PreflightReport(findings=findings, timings=timings)

    started = loop.time()
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
        timings["simctl_get_app_container"] = loop.time() - started
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
        return PreflightReport(findings=findings, timings=timings)
    timings["simctl_get_app_container"] = loop.time() - started
    return PreflightReport(findings=findings, timings=timings)


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
