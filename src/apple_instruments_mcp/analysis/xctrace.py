from __future__ import annotations

import asyncio
import contextlib
import json
import re
import shlex
import signal
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from apple_instruments_mcp.analysis.targets import RecordingTarget

PREFLIGHT_TIMEOUT_SECONDS = 5.0
RECORD_STARTUP_TIMEOUT_SECONDS = 15.0
RECORD_TEARDOWN_GRACE_SECONDS = 15.0
RECORD_POLL_INTERVAL_SECONDS = 0.5
RECORD_STARTED_MARKER = "starting recording"
_WEDGE_ERROR_MARKERS = (
    "started recording but did not finish",
    "did not begin recording within",
    "instruments tap disconnected",
)
_TAP_WEDGE_OUTPUT_MARKERS = (
    "device disconnected while trying to set tap configuration",
    "device disconnected while trying to start tap",
    "was not claimed by a tap plug-in",
)


def _command_failure_message(
    args: tuple[str, ...], returncode: int | None, output: str
) -> str:
    if returncode is None:
        outcome = "failed without reporting an exit status"
    elif returncode < 0:
        signal_number = -returncode
        try:
            signal_name = signal.Signals(signal_number).name
        except ValueError:
            signal_name = "UNKNOWN"
        outcome = f"terminated by signal {signal_name} ({signal_number})"
    else:
        outcome = f"exited with status {returncode}"

    message = f"Command {outcome}: {shlex.join(args)}"
    detail = output.strip()
    return f"{message}\n{detail}" if detail else message


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
        raise RuntimeError(_command_failure_message(args, process.returncode, output))
    return output


async def list_devices() -> str:
    return await run_command("xcrun", "xctrace", "list", "devices")


async def list_templates() -> str:
    return await run_command("xcrun", "xctrace", "list", "templates")


async def list_instruments() -> str:
    return await run_command("xcrun", "xctrace", "list", "instruments")


def count_xctrace_listing_items(output: str) -> int:
    """Count data lines in `xctrace list <thing>` output, skipping section
    headers (`== Foo ==` or trailing-colon `Foo:` styles) and blank lines.
    """
    count = 0
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("==") and line.endswith("=="):
            continue
        if line.endswith(":"):
            continue
        count += 1
    return count


def parse_xctrace_listing(output: str) -> dict[str, list[dict[str, str]]]:
    sections: dict[str, list[dict[str, str]]] = {}
    current_section = "items"

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        equals_header = re.fullmatch(r"==\s*(.+?)\s*==", line)
        if equals_header is not None:
            current_section = equals_header.group(1).strip().lower().replace(" ", "_")
            sections.setdefault(current_section, [])
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


def _find_xctrace_target_section(output: str, device_id: str) -> str | None:
    """Return the xctrace listing section containing ``device_id``.

    This distinction matters for physical devices: CoreDevice/devicectl may
    call a paired device available while xctrace still places it under
    ``Devices Offline`` and cannot record from it.
    """
    target_id = device_id.casefold()
    for section, items in parse_xctrace_listing(output).items():
        for item in items:
            item_id = item.get("id", "").casefold()
            if item_id == target_id or target_id in item.get("name", "").casefold():
                return section
    return None


def list_as_json(output: str) -> str:
    return json.dumps(parse_xctrace_listing(output), indent=2, sort_keys=True)


def build_record_command(
    template: str | None,
    target: RecordingTarget,
    time_limit_seconds: int,
    output_path: Path,
    *,
    instruments: Sequence[str] = (),
) -> list[str]:
    """Build the `xcrun xctrace record` argv.

    Exactly one of `template` and `instruments` must be supplied — `template`
    is a `.tracetemplate` name (e.g. "Time Profiler", "App Launch"), and
    `instruments` is a list of individual instrument names passed via
    repeated `--instrument` flags (e.g. ["Time Profiler", "Allocations"]).
    """
    has_instruments = bool(instruments)
    if (template is None) == (not has_instruments):
        raise ValueError(
            "build_record_command requires exactly one of template or instruments."
        )
    args = [
        "xcrun",
        "xctrace",
        "record",
        "--time-limit",
        f"{time_limit_seconds}s",
        "--output",
        str(output_path),
        "--no-prompt",
    ]
    if template is not None:
        args.extend(["--template", template])
    else:
        for instrument in instruments:
            args.extend(["--instrument", instrument])
    args.extend(target.xctrace_args())
    return args


def format_command(args: list[str]) -> str:
    return shlex.join(args)


def _is_wedge_error(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in _WEDGE_ERROR_MARKERS)


def _trace_bundle_finalized(trace_path: Path) -> bool:
    """A `.trace` bundle is finalized when its `Trace*.run/` holds artifacts
    other than the boilerplate `RunIssues.storedata`. Empty or RunIssues-only
    bundles are the signature of a wedged or aborted recording.
    """
    if not trace_path.is_dir():
        return False
    for run_dir in trace_path.glob("Trace*.run"):
        if not run_dir.is_dir():
            continue
        for entry in run_dir.iterdir():
            if entry.name != "RunIssues.storedata":
                return True
    return False


async def record_trace(
    template: str | None,
    target: RecordingTarget,
    time_limit_seconds: int,
    output_path: Path,
    *,
    instruments: Sequence[str] = (),
) -> None:
    args = build_record_command(
        template, target, time_limit_seconds, output_path, instruments=instruments
    )
    try:
        await _run_record_with_watchdog(args, time_limit_seconds)
    except RuntimeError as exc:
        # xctrace can exit non-zero with a perfectly valid trace bundle — e.g. a
        # `--launch` target killed at --time-limit returns its own exit status
        # while the recording finishes normally on disk. Trust the bundle as
        # ground truth, unless the failure is a wedge (no usable bundle then).
        if not _is_wedge_error(str(exc)) and _trace_bundle_finalized(output_path):
            return
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
    tap_wedge_line: str | None = None
    loop = asyncio.get_running_loop()
    spawned_at = loop.time()

    async def read_lines() -> None:
        nonlocal started, started_at, tap_wedge_line
        while True:
            chunk = await stdout.readline()
            if not chunk:
                return
            text = chunk.decode("utf-8", errors="replace")
            lines.append(text)
            lowered = text.lower()
            if not started and RECORD_STARTED_MARKER in text.lower():
                started = True
                started_at = loop.time()
            if tap_wedge_line is None and any(
                marker in lowered for marker in _TAP_WEDGE_OUTPUT_MARKERS
            ):
                tap_wedge_line = text.strip()

    reader = asyncio.create_task(read_lines())
    try:
        while not reader.done():
            await asyncio.wait({reader}, timeout=poll_interval)
            if tap_wedge_line is not None:
                await _terminate(process)
                raise RuntimeError(
                    "xctrace Instruments tap disconnected before recording completed. "
                    f"Last output: {tap_wedge_line}"
                )
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
    _, finding = await _probe_xctrace_devices()
    return finding


async def _probe_xctrace_devices() -> tuple[str | None, PreflightFinding | None]:
    """Return the device listing together with any xctrace health finding."""
    try:
        output = await run_command(
            "xcrun", "xctrace", "list", "devices", timeout=PREFLIGHT_TIMEOUT_SECONDS
        )
    except RuntimeError as exc:
        message = str(exc)
        lowered = message.lower()
        if "timed out" in lowered:
            return None, PreflightFinding(
                "blocker",
                f"`xctrace list devices` did not respond within {int(PREFLIGHT_TIMEOUT_SECONDS)}s.",
                (
                    "xctrace or its IPC channel appears wedged.",
                    "Check `pgrep -fl xctrace` and stop only a hung xctrace process you own, then retry.",
                    "For a physical device, open Xcode and keep the device unlocked until it appears under `Devices`.",
                    "Opening Instruments.app alone does not perform Xcode's persistent device preparation.",
                ),
            )
        if "operation not permitted" in lowered and (
            "com.apple.dt.instrumentscli" in lowered
            or "cannot create temporary directory for instruments analysis core" in lowered
        ):
            return None, PreflightFinding(
                "blocker",
                "`xctrace` cannot write its Instruments CLI state from this process "
                "(sandbox restriction).",
                (
                    "Run the MCP server outside the restrictive sandbox, or grant its process write access to `~/Library/Caches/com.apple.dt.InstrumentsCLI`.",
                    "This failure occurs before device preparation or recording begins.",
                ),
            )
        return None, PreflightFinding("warning", f"`xctrace list devices` failed: {message}")
    return output, None


async def preflight_device_target(device_id: str) -> PreflightReport:
    """Check whether ``device_id`` is ready for any xctrace recording.

    This probe intentionally has no bundle/app assumptions so it also covers
    device-targeted PID, process-name, and all-process recordings.
    """
    findings: list[PreflightFinding] = []
    timings: dict[str, float] = {}
    loop = asyncio.get_running_loop()

    started = loop.time()
    xctrace_output, xctrace_finding = await _probe_xctrace_devices()
    timings["xctrace_list_devices"] = loop.time() - started
    if xctrace_finding is not None:
        findings.append(xctrace_finding)
        if xctrace_finding.severity == "blocker":
            return PreflightReport(findings=findings, timings=timings)

    xctrace_section = (
        _find_xctrace_target_section(xctrace_output, device_id)
        if xctrace_output is not None
        else None
    )
    if xctrace_section == "devices_offline":
        findings.append(
            PreflightFinding(
                "blocker",
                f"`xctrace` sees target {device_id} under `Devices Offline`; "
                "CoreDevice/devicectl availability does not make it record-ready.",
                (
                    "Open Xcode (not Instruments), keep the device unlocked, and wait until it appears under `Devices`.",
                    "Verify readiness with `xcrun xctrace list devices` before retrying.",
                    "Opening Instruments.app alone does not establish Xcode's persistent device preparation.",
                ),
            )
        )

    return PreflightReport(findings=findings, timings=timings)


async def preflight_ios_target(device_id: str, bundle_id: str) -> PreflightReport:
    """Pre-flight an iOS simulator target before xctrace record.

    Returns findings the caller should surface plus per-probe wall-clock timings.
    Physical devices are also checked against xctrace's own online/offline
    sections; CoreDevice availability alone is not sufficient for recording.
    """
    device_report = await preflight_device_target(device_id)
    findings = list(device_report.findings)
    timings = dict(device_report.timings)
    if device_report.blockers:
        return PreflightReport(findings=findings, timings=timings)

    loop = asyncio.get_running_loop()

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
        return PreflightReport(findings=findings, timings=timings)

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
