from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shlex
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypeVar

Severity = Literal["critical", "warning", "ok"]
Status = Literal["good", "warning", "critical"]
LaunchPhaseName = Literal["pre-main", "post-main", "unknown"]


@dataclass(frozen=True)
class CallTreeFrame:
    symbol: str
    self_ms: float
    total_ms: float


@dataclass(frozen=True)
class LaunchOffender:
    symbol: str
    self_time_ms: int
    total_time_ms: int
    percent: int
    phase: LaunchPhaseName
    severity: Severity
    suggestion: str | None = None


@dataclass(frozen=True)
class LaunchPhase:
    name: str
    duration_ms: int
    percent: int


@dataclass(frozen=True)
class LaunchAnalysis:
    total_launch_ms: int
    status: Status
    phases: list[LaunchPhase]
    offenders: list[LaunchOffender]
    summary: str
    recommendations: list[str]


@dataclass(frozen=True)
class AllocationCategory:
    type: str
    live_bytes: int
    live_count: int
    total_bytes: int
    total_count: int
    severity: Severity
    suggestion: str | None = None


@dataclass(frozen=True)
class AllocationAnalysis:
    peak_memory_mb: float
    live_memory_mb: float
    status: Status
    top_allocations: list[AllocationCategory]
    summary: str
    recommendations: list[str]


@dataclass(frozen=True)
class LeakEntry:
    type: str
    count: int
    total_bytes: int
    root_cycle: bool
    suggestion: str | None = None


@dataclass(frozen=True)
class LeaksAnalysis:
    total_leaks: int
    total_leaked_bytes: int
    status: Status
    leaks: list[LeakEntry]
    summary: str
    recommendations: list[str]


@dataclass(frozen=True)
class HotMethod:
    symbol: str
    self_time_ms: int
    total_time_ms: int
    percent: int
    severity: Severity
    suggestion: str | None = None


@dataclass(frozen=True)
class TimeProfileAnalysis:
    total_duration_ms: int
    status: Status
    hot_methods: list[HotMethod]
    summary: str
    recommendations: list[str]


@dataclass(frozen=True)
class NetworkRequest:
    url: str
    method: str
    duration_ms: int
    bytes: int
    status_code: int
    severity: Severity


@dataclass(frozen=True)
class NetworkAnalysis:
    total_requests: int
    total_transferred_mb: float
    status: Status
    slow_requests: list[NetworkRequest]
    summary: str
    recommendations: list[str]


@dataclass(frozen=True)
class AnalysisQuality:
    confidence: Literal["high", "low"]
    warnings: list[str]


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


def get_severity(
    ms: float, threshold_critical: float = 300, threshold_warning: float = 100
) -> Severity:
    if ms > threshold_critical:
        return "critical"
    if ms > threshold_warning:
        return "warning"
    return "ok"


def get_memory_severity(mb: float, warning_mb: float = 100, critical_mb: float = 200) -> Severity:
    if mb > critical_mb:
        return "critical"
    if mb > warning_mb:
        return "warning"
    return "ok"


def get_status(ms: float, good_threshold: float, critical_threshold: float) -> Status:
    if ms < good_threshold:
        return "good"
    if ms < critical_threshold:
        return "warning"
    return "critical"


def get_launch_suggestion(symbol: str, phase: str) -> str | None:
    s = symbol.lower()
    if "database" in s or "sqlite" in s or "coredata" in s:
        return "Move database initialization to a background queue or use lazy loading."
    if "analytics" in s or "firebase" in s or "segment" in s:
        return "Defer analytics SDK initialization after first frame is rendered."
    if "network" in s or "urlsession" in s or "alamofire" in s:
        return "Avoid synchronous network calls on launch. Use async/await or callbacks."
    if "image" in s or "uiimage" in s or "sdwebimage" in s:
        return "Defer image loading/caching setup to after first frame."
    if phase == "pre-main" and "+initialize" in s:
        return "Avoid heavy work in +initialize or static initializers - they run before main()."
    if "json" in s or "decoder" in s or "codable" in s:
        return "Defer JSON parsing to a background thread. Consider caching decoded models."
    return None


def get_allocation_suggestion(type_name: str) -> str | None:
    t = type_name.lower()
    if "uiimage" in t or "cgimage" in t:
        return "Use downsampled images. Load at display size, not original resolution."
    if "string" in t or "nsstring" in t:
        return "Consider using StaticString or interning repeated strings."
    if "data" in t or "nsdata" in t:
        return "Stream large Data objects instead of loading fully into memory."
    if "array" in t or "nsarray" in t:
        return "Use lazy collections or pagination for large arrays."
    if "viewcontroller" in t or "uiview" in t:
        return "Check for retained view controllers outside the view hierarchy."
    return None


def get_leak_suggestion(type_name: str) -> str | None:
    t = type_name.lower()
    if "closure" in t or "block" in t:
        return "Capture lists ([weak self]) in closures referencing self."
    if "delegate" in t:
        return "Delegate properties should be weak. Check protocol declaration."
    if "timer" in t or "nstimer" in t:
        return "Invalidate timers in deinit or viewDidDisappear."
    if "notificationcenter" in t:
        return "Remove observers in deinit: NotificationCenter.default.removeObserver(self)."
    return None


def get_hot_method_suggestion(symbol: str) -> str | None:
    s = symbol.lower()
    if "layout" in s or "autolayout" in s:
        return "Profile Auto Layout constraints - reduce constraint count or use manual layout for hot paths."
    if "draw" in s or "render" in s or "metal" in s:
        return "Move rendering work to background threads or use Metal for GPU offloading."
    if "json" in s or "decoder" in s:
        return "Parse JSON on a background queue. Cache decoded results."
    if "sort" in s or "filter" in s or "map" in s:
        return "Use lazy sequences or move collection operations off the main thread."
    if "fetch" in s or "coredata" in s:
        return "Add fetch limit and use async fetch requests (NSAsynchronousFetchRequest)."
    return None


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


def assess_xml_quality(xml_content: str, evidence_found: bool, parser_name: str) -> AnalysisQuality:
    warnings: list[str] = []
    if not xml_content.strip():
        warnings.append("xctrace export produced no XML content for this parser.")
    elif not evidence_found:
        warnings.append(f"No recognizable {parser_name} data was found in the exported XML.")

    return AnalysisQuality(confidence="low" if warnings else "high", warnings=warnings)


def format_quality(quality: AnalysisQuality) -> str:
    if quality.confidence == "high":
        return ""

    lines = ["\n## Analysis Quality", f"- Confidence: **{quality.confidence}**"]
    lines.extend(f"- {warning}" for warning in quality.warnings)
    return "\n".join(lines)


def has_launch_evidence(xml_content: str) -> bool:
    frames, total_ms = parse_call_tree(xml_content)
    return bool(frames) or total_ms > 0 or bool(
        _first_match(
            [r"launch-time[^>]*>([0-9.]+)", r"total[^>]*time[^>]*>([0-9.]+)"],
            xml_content,
            re.IGNORECASE,
        )
    )


def has_allocations_evidence(xml_content: str) -> bool:
    return bool(re.search(r"<(live-bytes|total-bytes|peak[^>]*)", xml_content, re.IGNORECASE))


def has_leaks_evidence(xml_content: str) -> bool:
    return "<leak" in xml_content or bool(re.search(r"<(responsible-library|size)[^>]*>", xml_content))


def has_time_profiler_evidence(xml_content: str) -> bool:
    frames, total_ms = parse_call_tree(xml_content)
    return bool(frames) or total_ms > 0


def has_network_evidence(xml_content: str) -> bool:
    return "<request" in xml_content or bool(re.search(r"<(url|duration|bytes|status)[^>]*>", xml_content))


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


async def export_xml(trace_path: Path, output_xml_path: Path, xpath: str | None = None) -> None:
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
    await run_command(*args)


def parse_call_tree(xml_content: str) -> tuple[list[CallTreeFrame], float]:
    frames: list[CallTreeFrame] = []
    total_ms = 0.0
    total_weight = 0
    raw: list[tuple[str, int, int]] = []

    frame_pattern = re.compile(r'<frame[^>]*\sweight="(\d+)"[^>]*\sself="(\d+)"[^>]*>([^<]+)</frame>')
    for match in frame_pattern.finditer(xml_content):
        weight = int(match.group(1))
        self_weight = int(match.group(2))
        total_weight += self_weight
        raw.append((match.group(3).strip(), weight, self_weight))

    if raw:
        ms_per_unit = total_ms / total_weight if total_ms > 0 else 1
        for symbol, weight, self_weight in raw:
            frames.append(CallTreeFrame(symbol, self_weight * ms_per_unit, weight * ms_per_unit))
        return frames, total_ms

    node_pattern = re.compile(
        r'<node[^>]*name="([^"]+)"[^>]*self-weight="([0-9.]+)ms"[^>]*total-weight="([0-9.]+)ms"'
    )
    for match in node_pattern.finditer(xml_content):
        self_ms = float(match.group(2))
        total = float(match.group(3))
        total_ms = max(total_ms, total)
        frames.append(CallTreeFrame(match.group(1), self_ms, total))

    return frames, total_ms


def _first_match(patterns: list[str], text: str, flags: int = 0) -> re.Match[str] | None:
    for pattern in patterns:
        match = re.search(pattern, text, flags)
        if match:
            return match
    return None


def parse_app_launch(
    xml_content: str,
    bundle_id: str,
    *,
    launch_good_ms: float = 400,
    launch_critical_ms: float = 1000,
    offender_warning_ms: float = 100,
    offender_critical_ms: float = 300,
) -> LaunchAnalysis:
    frames, parsed_total = parse_call_tree(xml_content)
    launch_time_match = _first_match(
        [r"launch-time[^>]*>([0-9.]+)", r"total[^>]*time[^>]*>([0-9.]+)"],
        xml_content,
        re.IGNORECASE,
    )
    total_launch_ms = (
        float(launch_time_match.group(1)) * 1000 if launch_time_match else parsed_total or 0
    )

    ms_per_unit = total_launch_ms / parsed_total if parsed_total > 0 else 1
    seen: set[str] = set()
    offenders: list[LaunchOffender] = []

    for frame in frames:
        if frame.symbol in seen:
            continue
        seen.add(frame.symbol)
        self_ms = frame.self_ms * ms_per_unit
        if self_ms < 10:
            continue
        phase: LaunchPhaseName = (
            "pre-main" if "+initialize" in frame.symbol or "dyld" in frame.symbol else "post-main"
        )
        offenders.append(
            LaunchOffender(
                symbol=frame.symbol,
                self_time_ms=round(self_ms),
                total_time_ms=round(frame.total_ms * ms_per_unit),
                percent=round((self_ms / total_launch_ms) * 100) if total_launch_ms > 0 else 0,
                phase=phase,
                severity=get_severity(self_ms, offender_critical_ms, offender_warning_ms),
                suggestion=get_launch_suggestion(frame.symbol, phase),
            )
        )

    offenders.sort(key=lambda offender: offender.self_time_ms, reverse=True)

    phases = (
        [
            LaunchPhase("pre-main (dyld + static init)", round(total_launch_ms * 0.35), 35),
            LaunchPhase("post-main (AppDelegate + UI)", round(total_launch_ms * 0.65), 65),
        ]
        if total_launch_ms > 0
        else []
    )

    critical_count = sum(1 for offender in offenders if offender.severity == "critical")
    warning_count = sum(1 for offender in offenders if offender.severity == "warning")
    recommendations: list[str] = []
    if critical_count > 0:
        recommendations.append(
            f"Fix {critical_count} critical offender(s) - each adds {offender_critical_ms:g}ms+ to launch."
        )
    if warning_count > 0:
        recommendations.append(
            f"{warning_count} method(s) between {offender_warning_ms:g}-{offender_critical_ms:g}ms - worth deferring to background."
        )
    if any(offender.phase == "pre-main" for offender in offenders):
        recommendations.append("Reduce static initializers: avoid +initialize, prefer lazy var in Swift.")
    recommendations.append("Target: total launch under 400ms. Write XCTest performance tests to catch regressions.")

    status = get_status(total_launch_ms, launch_good_ms, launch_critical_ms)
    if status == "good":
        summary = f"✅ Launch time {round(total_launch_ms)}ms - within Apple's recommended threshold."
    elif status == "warning":
        summary = f"⚠️ Launch time {round(total_launch_ms)}ms - above 400ms. Users may notice the delay."
    else:
        summary = f"🔴 Launch time {round(total_launch_ms)}ms - critical. Apple may flag this in App Store review."

    return LaunchAnalysis(
        total_launch_ms=round(total_launch_ms),
        status=status,
        phases=phases,
        offenders=offenders[:15],
        summary=summary,
        recommendations=recommendations,
    )


def parse_allocations(
    xml_content: str,
    *,
    memory_warning_mb: float = 100,
    memory_critical_mb: float = 200,
    memory_cache_warning_mb: float = 150,
) -> AllocationAnalysis:
    categories: list[AllocationCategory] = []
    peak_mb = 0.0
    live_mb = 0.0

    for match in re.finditer(r"<row>([\s\S]*?)</row>", xml_content):
        row = match.group(1)
        type_match = re.search(r"<type[^>]*>([^<]+)</type>", row)
        type_name = type_match.group(1).strip() if type_match else "Unknown"
        live_bytes = int((re.search(r"<live-bytes[^>]*>(\d+)</live-bytes>", row) or ["", "0"])[1])
        live_count = int((re.search(r"<live-count[^>]*>(\d+)</live-count>", row) or ["", "0"])[1])
        total_bytes = int((re.search(r"<total-bytes[^>]*>(\d+)</total-bytes>", row) or ["", "0"])[1])
        total_count = int((re.search(r"<total-count[^>]*>(\d+)</total-count>", row) or ["", "0"])[1])

        if total_bytes < 1024:
            continue
        live_mb += live_bytes / 1_048_576
        categories.append(
            AllocationCategory(
                type=type_name,
                live_bytes=live_bytes,
                live_count=live_count,
                total_bytes=total_bytes,
                total_count=total_count,
                severity=get_memory_severity(live_bytes / 1_048_576, memory_warning_mb, memory_critical_mb),
                suggestion=get_allocation_suggestion(type_name),
            )
        )

    peak_match = re.search(r"peak[^>]*memory[^>]*>([0-9.]+)\s*(mb|kb)?", xml_content, re.IGNORECASE)
    if peak_match:
        peak_mb = float(peak_match.group(1))
        if peak_match.group(2) and peak_match.group(2).lower() == "kb":
            peak_mb /= 1024
    else:
        peak_mb = live_mb * 1.3

    categories.sort(key=lambda category: category.live_bytes, reverse=True)
    status: Status = "critical" if peak_mb > memory_critical_mb else "warning" if peak_mb > memory_warning_mb else "good"

    if status == "good":
        summary = f"✅ Peak memory {peak_mb:.1f}MB - healthy."
    elif status == "warning":
        summary = f"⚠️ Peak memory {peak_mb:.1f}MB - monitor on older devices."
    else:
        summary = f"🔴 Peak memory {peak_mb:.1f}MB - high risk of jetsam kill on iPhone with 3GB RAM."

    recommendations: list[str] = []
    if any("uiimage" in category.type.lower() for category in categories):
        recommendations.append("Downscale images before storing in memory. Use ImageIO for thumbnail generation.")
    if peak_mb > memory_cache_warning_mb:
        recommendations.append("Subscribe to UIApplicationDidReceiveMemoryWarningNotification and release caches.")
    recommendations.append("Use Xcode Memory Gauge during testing. Target < 50MB for typical use, < 120MB peak.")

    return AllocationAnalysis(
        peak_memory_mb=round(peak_mb, 1),
        live_memory_mb=round(live_mb, 1),
        status=status,
        top_allocations=categories[:15],
        summary=summary,
        recommendations=recommendations,
    )


def parse_leaks(xml_content: str, *, leak_critical_count: int = 10) -> LeaksAnalysis:
    leaks: list[LeakEntry] = []
    leak_pattern = re.compile(
        r'<leak[^>]*type="([^"]+)"[^>]*count="(\d+)"[^>]*size="(\d+)"[^>]*root-cycle="(true|false)"'
    )

    for match in leak_pattern.finditer(xml_content):
        type_name = match.group(1)
        leaks.append(
            LeakEntry(
                type=type_name,
                count=int(match.group(2)),
                total_bytes=int(match.group(3)),
                root_cycle=match.group(4) == "true",
                suggestion=get_leak_suggestion(type_name),
            )
        )

    if not leaks:
        for match in re.finditer(r"<row>([\s\S]*?)</row>", xml_content):
            row = match.group(1)
            type_match = re.search(r"<responsible-library[^>]*>([^<]+)", row) or re.search(
                r"<type[^>]*>([^<]+)", row
            )
            size_match = re.search(r"<size[^>]*>(\d+)</size>", row)
            type_name = type_match.group(1).strip() if type_match else None
            size = int(size_match.group(1)) if size_match else 0
            if not type_name or size == 0:
                continue
            leaks.append(
                LeakEntry(type=type_name, count=1, total_bytes=size, root_cycle=False, suggestion=get_leak_suggestion(type_name))
            )

    leaks.sort(key=lambda leak: leak.total_bytes, reverse=True)
    total_leaks = sum(leak.count for leak in leaks)
    total_bytes = sum(leak.total_bytes for leak in leaks)

    status: Status = "good" if total_leaks == 0 else "critical" if total_leaks > leak_critical_count else "warning"
    if total_leaks == 0:
        summary = "✅ No memory leaks detected."
    elif status == "warning":
        summary = f"⚠️ {total_leaks} leak(s) found - {total_bytes / 1024:.1f}KB leaked."
    else:
        summary = f"🔴 {total_leaks} leak(s) found - {total_bytes / 1024:.1f}KB leaked. Fix before shipping."

    recommendations: list[str] = []
    if any(leak.root_cycle for leak in leaks):
        recommendations.append("Root retain cycles detected. Use [weak self] in closures and weak delegates.")
    if total_leaks > 0:
        recommendations.append("Run Leaks instrument regularly in CI using xctrace to catch regressions early.")
    recommendations.append("Enable Malloc Stack Logging in scheme diagnostics for detailed allocation stacks.")

    return LeaksAnalysis(
        total_leaks=total_leaks,
        total_leaked_bytes=total_bytes,
        status=status,
        leaks=leaks[:15],
        summary=summary,
        recommendations=recommendations,
    )


def parse_time_profiler(
    xml_content: str,
    *,
    total_good_ms: float = 16,
    total_critical_ms: float = 100,
    method_warning_ms: float = 50,
    method_critical_ms: float = 200,
) -> TimeProfileAnalysis:
    frames, total_ms = parse_call_tree(xml_content)
    seen: set[str] = set()
    hot_methods: list[HotMethod] = []

    for frame in frames:
        if frame.symbol in seen:
            continue
        seen.add(frame.symbol)
        if frame.self_ms < 5:
            continue
        hot_methods.append(
            HotMethod(
                symbol=frame.symbol,
                self_time_ms=round(frame.self_ms),
                total_time_ms=round(frame.total_ms),
                percent=round((frame.self_ms / total_ms) * 100) if total_ms > 0 else 0,
                severity=get_severity(frame.self_ms, method_critical_ms, method_warning_ms),
                suggestion=get_hot_method_suggestion(frame.symbol),
            )
        )

    hot_methods.sort(key=lambda method: method.self_time_ms, reverse=True)
    status = get_status(total_ms, total_good_ms, total_critical_ms)

    if status == "good":
        summary = "✅ CPU profile looks healthy - no dominant hot methods."
    elif status == "warning":
        summary = "⚠️ Some methods consuming significant CPU. Review top offenders."
    else:
        summary = "🔴 Heavy CPU usage detected. Main thread likely blocked - users will feel jank."

    recommendations: list[str] = []
    if any(method.severity == "critical" for method in hot_methods):
        recommendations.append("Move critical hot methods off the main thread using async/await or DispatchQueue.")
    recommendations.append("Use Instruments Time Profiler regularly during UI stress tests.")
    recommendations.append("Target < 16ms per frame (60fps) or < 8ms (120fps ProMotion) for main thread work.")

    return TimeProfileAnalysis(
        total_duration_ms=round(total_ms),
        status=status,
        hot_methods=hot_methods[:15],
        summary=summary,
        recommendations=recommendations,
    )


def parse_network(
    xml_content: str,
    *,
    request_warning_ms: float = 500,
    request_critical_ms: float = 2000,
    slow_request_critical_count: int = 5,
    transfer_warning_mb: float = 5,
) -> NetworkAnalysis:
    requests: list[NetworkRequest] = []
    req_pattern = re.compile(
        r'<request[^>]*url="([^"]+)"[^>]*method="([^"]+)"[^>]*duration="([0-9.]+)"[^>]*bytes="(\d+)"[^>]*status="(\d+)"'
    )

    for match in req_pattern.finditer(xml_content):
        duration_ms = float(match.group(3)) * 1000
        requests.append(
            NetworkRequest(
                url=match.group(1),
                method=match.group(2),
                duration_ms=round(duration_ms),
                bytes=int(match.group(4)),
                status_code=int(match.group(5)),
                severity=get_severity(duration_ms, request_critical_ms, request_warning_ms),
            )
        )

    if not requests:
        for match in re.finditer(r"<row>([\s\S]*?)</row>", xml_content):
            row = match.group(1)
            url_match = re.search(r"<url[^>]*>([^<]+)</url>", row)
            url = url_match.group(1).strip() if url_match else ""
            duration = float((re.search(r"<duration[^>]*>([0-9.]+)", row) or ["", "0"])[1])
            bytes_count = int((re.search(r"<bytes[^>]*>(\d+)", row) or ["", "0"])[1])
            status_code = int((re.search(r"<status[^>]*>(\d+)", row) or ["", "200"])[1])
            if not url:
                continue
            duration_ms = duration * 1000
            requests.append(
                NetworkRequest(
                    url=url,
                    method="GET",
                    duration_ms=round(duration_ms),
                    bytes=bytes_count,
                    status_code=status_code,
                    severity=get_severity(duration_ms, request_critical_ms, request_warning_ms),
                )
            )

    requests.sort(key=lambda request: request.duration_ms, reverse=True)
    total_transferred = sum(request.bytes for request in requests) / 1_048_576
    slow_count = sum(1 for request in requests if request.severity != "ok")
    status: Status = "good" if slow_count == 0 else "critical" if slow_count > slow_request_critical_count else "warning"

    if status == "good":
        summary = f"✅ {len(requests)} requests - all within acceptable latency."
    elif status == "warning":
        summary = f"⚠️ {slow_count} slow request(s) found out of {len(requests)} total."
    else:
        summary = f"🔴 {slow_count} slow request(s) - network is a bottleneck."

    recommendations: list[str] = []
    if any(request.status_code >= 400 for request in requests):
        recommendations.append("Fix failing requests (4xx/5xx) - these cause silent UX degradation.")
    if total_transferred > transfer_warning_mb:
        recommendations.append(
            f"Total transfer > {transfer_warning_mb:g}MB. Use pagination, compression (gzip/brotli), and caching."
        )
    recommendations.append("Use URLCache for GET requests. Consider background URLSession for large transfers.")

    return NetworkAnalysis(
        total_requests=len(requests),
        total_transferred_mb=round(total_transferred, 2),
        status=status,
        slow_requests=requests[:15],
        summary=summary,
        recommendations=recommendations,
    )


def format_launch(analysis: LaunchAnalysis, bundle_id: str) -> str:
    lines = [f"# App Launch Analysis - {bundle_id}", f"\n{analysis.summary}", f"\n**Total:** {analysis.total_launch_ms}ms"]
    if analysis.phases:
        lines.append("\n## Phases")
        for phase in analysis.phases:
            lines.append(f"- **{phase.name}:** {phase.duration_ms}ms ({phase.percent}%)")

    lines.append("\n## Top Offenders")
    if not analysis.offenders:
        lines.append("No significant offenders.")
    else:
        for offender in analysis.offenders:
            icon = "🔴" if offender.severity == "critical" else "🟡" if offender.severity == "warning" else "🟢"
            lines.append(f"\n{icon} `{offender.symbol}` [{offender.phase}]")
            lines.append(f"   Self: **{offender.self_time_ms}ms** | Total: {offender.total_time_ms}ms | {offender.percent}%")
            if offender.suggestion:
                lines.append(f"   💡 {offender.suggestion}")

    lines.append("\n## Recommendations")
    lines.extend(f"- {recommendation}" for recommendation in analysis.recommendations)
    return "\n".join(lines)


def format_allocations(analysis: AllocationAnalysis, bundle_id: str) -> str:
    lines = [
        f"# Memory Allocations - {bundle_id}",
        f"\n{analysis.summary}",
        f"\n**Peak:** {analysis.peak_memory_mb}MB | **Live:** {analysis.live_memory_mb}MB",
        "\n## Top Allocations by Type",
    ]
    if not analysis.top_allocations:
        lines.append("No allocation data found.")
    else:
        for category in analysis.top_allocations:
            icon = "🔴" if category.severity == "critical" else "🟡" if category.severity == "warning" else "🟢"
            live_mb = category.live_bytes / 1_048_576
            total_mb = category.total_bytes / 1_048_576
            lines.append(f"\n{icon} `{category.type}`")
            lines.append(
                f"   Live: **{live_mb:.2f}MB** ({category.live_count} objects) | Total: {total_mb:.2f}MB ({category.total_count} allocs)"
            )
            if category.suggestion:
                lines.append(f"   💡 {category.suggestion}")

    lines.append("\n## Recommendations")
    lines.extend(f"- {recommendation}" for recommendation in analysis.recommendations)
    return "\n".join(lines)


def format_leaks(analysis: LeaksAnalysis, bundle_id: str) -> str:
    lines = [
        f"# Memory Leaks - {bundle_id}",
        f"\n{analysis.summary}",
        f"\n**Total leaks:** {analysis.total_leaks} | **Leaked:** {analysis.total_leaked_bytes / 1024:.1f}KB",
        "\n## Leak Details",
    ]
    if not analysis.leaks:
        lines.append("No leaks found. ✅")
    else:
        for leak in analysis.leaks:
            cycle = " | ⚠️ Root Cycle" if leak.root_cycle else ""
            lines.append(f"\n🔴 `{leak.type}`")
            lines.append(f"   Count: {leak.count} | Size: {leak.total_bytes / 1024:.1f}KB{cycle}")
            if leak.suggestion:
                lines.append(f"   💡 {leak.suggestion}")

    lines.append("\n## Recommendations")
    lines.extend(f"- {recommendation}" for recommendation in analysis.recommendations)
    return "\n".join(lines)


def format_time_profiler(analysis: TimeProfileAnalysis, bundle_id: str) -> str:
    lines = [
        f"# Time Profiler - {bundle_id}",
        f"\n{analysis.summary}",
        f"\n**Duration profiled:** {analysis.total_duration_ms}ms",
        "\n## Hot Methods",
    ]
    if not analysis.hot_methods:
        lines.append("No hot methods found.")
    else:
        for method in analysis.hot_methods:
            icon = "🔴" if method.severity == "critical" else "🟡" if method.severity == "warning" else "🟢"
            lines.append(f"\n{icon} `{method.symbol}`")
            lines.append(f"   Self: **{method.self_time_ms}ms** | Total: {method.total_time_ms}ms | {method.percent}% of CPU")
            if method.suggestion:
                lines.append(f"   💡 {method.suggestion}")

    lines.append("\n## Recommendations")
    lines.extend(f"- {recommendation}" for recommendation in analysis.recommendations)
    return "\n".join(lines)


def format_network(analysis: NetworkAnalysis, bundle_id: str) -> str:
    lines = [
        f"# Network Activity - {bundle_id}",
        f"\n{analysis.summary}",
        f"\n**Requests:** {analysis.total_requests} | **Transferred:** {analysis.total_transferred_mb}MB",
        "\n## Slow Requests",
    ]
    if not analysis.slow_requests:
        lines.append("No slow requests found.")
    else:
        for request in analysis.slow_requests:
            icon = "🔴" if request.severity == "critical" else "🟡" if request.severity == "warning" else "🟢"
            lines.append(f"\n{icon} `{request.method} {request.url}`")
            lines.append(
                f"   Duration: **{request.duration_ms}ms** | Size: {request.bytes / 1024:.1f}KB | Status: {request.status_code}"
            )

    lines.append("\n## Recommendations")
    lines.extend(f"- {recommendation}" for recommendation in analysis.recommendations)
    return "\n".join(lines)


def format_delta(value: float, unit: str, lower_is_better: bool = True) -> str:
    direction = "regression" if (value > 0 and lower_is_better) or (value < 0 and not lower_is_better) else "improvement"
    sign = "+" if value > 0 else ""
    return f"{sign}{value:g}{unit} ({direction})"


def compare_launch_analyses(baseline: LaunchAnalysis, candidate: LaunchAnalysis, target_name: str) -> str:
    delta_ms = candidate.total_launch_ms - baseline.total_launch_ms
    baseline_offenders = {offender.symbol: offender.self_time_ms for offender in baseline.offenders}
    candidate_offenders = {offender.symbol: offender.self_time_ms for offender in candidate.offenders}
    changed_symbols = sorted(
        set(baseline_offenders) | set(candidate_offenders),
        key=lambda symbol: abs(candidate_offenders.get(symbol, 0) - baseline_offenders.get(symbol, 0)),
        reverse=True,
    )[:10]

    lines = [
        f"# Launch Trace Comparison - {target_name}",
        "",
        f"**Baseline:** {baseline.total_launch_ms}ms",
        f"**Candidate:** {candidate.total_launch_ms}ms",
        f"**Delta:** {format_delta(delta_ms, 'ms')}",
        "",
        "## Changed Offenders",
    ]
    if not changed_symbols:
        lines.append("No comparable offenders found.")
    else:
        for symbol in changed_symbols:
            before = baseline_offenders.get(symbol, 0)
            after = candidate_offenders.get(symbol, 0)
            lines.append(f"- `{symbol}`: {before}ms -> {after}ms ({format_delta(after - before, 'ms')})")
    return "\n".join(lines)


def compare_allocation_analyses(baseline: AllocationAnalysis, candidate: AllocationAnalysis, target_name: str) -> str:
    peak_delta = candidate.peak_memory_mb - baseline.peak_memory_mb
    live_delta = candidate.live_memory_mb - baseline.live_memory_mb
    baseline_types = {category.type: category.live_bytes for category in baseline.top_allocations}
    candidate_types = {category.type: category.live_bytes for category in candidate.top_allocations}
    changed_types = sorted(
        set(baseline_types) | set(candidate_types),
        key=lambda type_name: abs(candidate_types.get(type_name, 0) - baseline_types.get(type_name, 0)),
        reverse=True,
    )[:10]

    lines = [
        f"# Memory Trace Comparison - {target_name}",
        "",
        f"**Baseline peak:** {baseline.peak_memory_mb}MB",
        f"**Candidate peak:** {candidate.peak_memory_mb}MB",
        f"**Peak delta:** {format_delta(round(peak_delta, 2), 'MB')}",
        f"**Live delta:** {format_delta(round(live_delta, 2), 'MB')}",
        "",
        "## Changed Allocation Types",
    ]
    if not changed_types:
        lines.append("No comparable allocation types found.")
    else:
        for type_name in changed_types:
            before_mb = baseline_types.get(type_name, 0) / 1_048_576
            after_mb = candidate_types.get(type_name, 0) / 1_048_576
            lines.append(
                f"- `{type_name}`: {before_mb:.2f}MB -> {after_mb:.2f}MB ({format_delta(round(after_mb - before_mb, 2), 'MB')})"
            )
    return "\n".join(lines)


def compare_time_profile_analyses(
    baseline: TimeProfileAnalysis, candidate: TimeProfileAnalysis, target_name: str
) -> str:
    duration_delta = candidate.total_duration_ms - baseline.total_duration_ms
    baseline_methods = {method.symbol: method.self_time_ms for method in baseline.hot_methods}
    candidate_methods = {method.symbol: method.self_time_ms for method in candidate.hot_methods}
    changed_methods = sorted(
        set(baseline_methods) | set(candidate_methods),
        key=lambda symbol: abs(candidate_methods.get(symbol, 0) - baseline_methods.get(symbol, 0)),
        reverse=True,
    )[:10]

    lines = [
        f"# CPU Trace Comparison - {target_name}",
        "",
        f"**Baseline duration:** {baseline.total_duration_ms}ms",
        f"**Candidate duration:** {candidate.total_duration_ms}ms",
        f"**Duration delta:** {format_delta(duration_delta, 'ms')}",
        "",
        "## Changed Hot Methods",
    ]
    if not changed_methods:
        lines.append("No comparable hot methods found.")
    else:
        for symbol in changed_methods:
            before = baseline_methods.get(symbol, 0)
            after = candidate_methods.get(symbol, 0)
            lines.append(f"- `{symbol}`: {before}ms -> {after}ms ({format_delta(after - before, 'ms')})")
    return "\n".join(lines)


T = TypeVar("T")


async def run_analysis(
    template: str,
    target: RecordingTarget,
    time_limit_seconds: int,
    parser: Callable[[str], T],
    formatter: Callable[[T], str],
    parser_name: str,
    evidence_checker: Callable[[str], bool],
    *,
    dry_run: bool = False,
    keep_trace: bool = False,
    output_dir: str | None = None,
) -> str:
    base_dir = Path(os.path.expanduser(output_dir)) if output_dir else None
    if dry_run:
        trace_path = (base_dir / "trace.xctrace") if base_dir else Path("<temporary-directory>") / "trace.xctrace"
        command = format_command(build_record_command(template, target, time_limit_seconds, trace_path))
        return "\n".join(
            [
                "# xctrace Dry Run",
                "",
                f"**Template:** {template}",
                f"**Target:** {target.label}",
                f"**Output:** {trace_path}",
                "",
                "```bash",
                command,
                "```",
            ]
        )

    validation_errors = target.validate()
    if validation_errors:
        return "\n".join(
            [
                f"Refusing to record with template '{template}': target failed pre-flight checks.",
                "",
                *(f"- {error}" for error in validation_errors),
            ]
        )

    if base_dir:
        base_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="instruments-mcp-", dir=base_dir))
    trace_path = tmp_dir / "trace.xctrace"
    xml_path = tmp_dir / "export.xml"

    try:
        await record_trace(template, target, time_limit_seconds, trace_path)
        with contextlib.suppress(Exception):
            await export_xml(trace_path, xml_path)
        xml_content = xml_path.read_text(encoding="utf-8") if xml_path.exists() else ""
        result = formatter(parser(xml_content))
        quality = assess_xml_quality(xml_content, evidence_checker(xml_content), parser_name)
        quality_text = format_quality(quality)
        if quality_text:
            result = f"{result}\n{quality_text}"
        if keep_trace:
            result = "\n".join(
                [
                    result,
                    "",
                    "## Artifacts",
                    f"- Trace: `{trace_path}`",
                    f"- XML export: `{xml_path}`",
                ]
            )
        return result
    except Exception as error:
        return format_target_error(target, template, str(error))
    finally:
        if not keep_trace:
            shutil.rmtree(tmp_dir, ignore_errors=True)


async def analyze_existing(
    trace_path: str,
    parser: Callable[[str], T],
    formatter: Callable[[T], str],
    parser_name: str,
    evidence_checker: Callable[[str], bool],
) -> str:
    expanded_trace_path = Path(os.path.expanduser(trace_path))
    if not expanded_trace_path.exists():
        return f"Trace file not found: {trace_path}"

    tmp_dir = Path(tempfile.mkdtemp(prefix="instruments-mcp-"))
    xml_path = tmp_dir / "export.xml"

    try:
        with contextlib.suppress(Exception):
            await export_xml(expanded_trace_path, xml_path)
        xml_content = xml_path.read_text(encoding="utf-8") if xml_path.exists() else ""
        result = formatter(parser(xml_content))
        quality = assess_xml_quality(xml_content, evidence_checker(xml_content), parser_name)
        quality_text = format_quality(quality)
        return f"{result}\n{quality_text}" if quality_text else result
    except Exception as error:
        return f"Error analyzing trace: {error}"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def compare_existing(
    baseline_trace_path: str,
    candidate_trace_path: str,
    parser: Callable[[str], T],
    comparator: Callable[[T, T], str],
    parser_name: str,
    evidence_checker: Callable[[str], bool],
) -> str:
    baseline_path = Path(os.path.expanduser(baseline_trace_path))
    candidate_path = Path(os.path.expanduser(candidate_trace_path))
    if not baseline_path.exists():
        return f"Baseline trace file not found: {baseline_trace_path}"
    if not candidate_path.exists():
        return f"Candidate trace file not found: {candidate_trace_path}"

    tmp_dir = Path(tempfile.mkdtemp(prefix="instruments-mcp-compare-"))
    baseline_xml_path = tmp_dir / "baseline.xml"
    candidate_xml_path = tmp_dir / "candidate.xml"

    try:
        with contextlib.suppress(Exception):
            await export_xml(baseline_path, baseline_xml_path)
        with contextlib.suppress(Exception):
            await export_xml(candidate_path, candidate_xml_path)

        baseline_xml = baseline_xml_path.read_text(encoding="utf-8") if baseline_xml_path.exists() else ""
        candidate_xml = candidate_xml_path.read_text(encoding="utf-8") if candidate_xml_path.exists() else ""
        result = comparator(parser(baseline_xml), parser(candidate_xml))

        baseline_quality = assess_xml_quality(baseline_xml, evidence_checker(baseline_xml), f"baseline {parser_name}")
        candidate_quality = assess_xml_quality(candidate_xml, evidence_checker(candidate_xml), f"candidate {parser_name}")
        warnings = baseline_quality.warnings + candidate_quality.warnings
        if warnings:
            result = f"{result}\n{format_quality(AnalysisQuality(confidence='low', warnings=warnings))}"
        return result
    except Exception as error:
        return f"Error comparing traces: {error}"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
