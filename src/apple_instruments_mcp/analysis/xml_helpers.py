from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import defaultdict

from apple_instruments_mcp.analysis.models import (
    CallTreeFrame,
    SampleFrame,
    TimeProfileSample,
)

_MAIN_THREAD_HINTS = ("main thread", "com.apple.main-thread")

_NS_PER_MS = 1_000_000

# Leaf symbols where the thread is parked in a kernel wait. Instruments hides these
# in the Time Profiler view by default ("Hide System Libraries"). Counting them as
# CPU work would massively inflate totals on traces that keep recording after the
# app is idle (workers parked in mach_msg2_trap / semaphore_wait dominate the sample
# stream). When a row's leaf is one of these, we drop the whole sample.
_IDLE_LEAF_SYMBOLS = frozenset(
    {
        "mach_msg2_trap",
        "mach_msg_trap",
        "mach_msg_overwrite_trap",
        "start_wqthread",
        "_pthread_wqthread",
        "semaphore_wait_trap",
        "semaphore_timedwait_trap",
        "__ulock_wait",
        "__psynch_cvwait",
        "__psynch_mutexwait",
        "kevent",
        "kevent_id",
        "kevent_qos",
        "__select",
        "__pselect",
        "poll",
        "ppoll",
        "_pthread_cond_wait",
    }
)


def _build_id_map(root: ET.Element) -> dict[str, ET.Element]:
    return {elem.get("id"): elem for elem in root.iter() if elem.get("id")}  # type: ignore[misc]


def _resolve(elem: ET.Element, id_map: dict[str, ET.Element]) -> ET.Element:
    ref = elem.get("ref")
    if ref is not None:
        return id_map.get(ref, elem)
    return elem


def _frame_binary(frame_elem: ET.Element, id_map: dict[str, ET.Element]) -> str:
    """Best-effort binary name for a frame. xctrace's export shape varies:
    sometimes a `binary` attribute, sometimes a `<binary name="...">` child,
    sometimes a sibling `binary` element referenced by ref. Return "" when
    none of these are present."""
    binary_attr = frame_elem.get("binary")
    if binary_attr:
        return binary_attr
    binary_child = frame_elem.find("binary")
    if binary_child is not None:
        resolved = _resolve(binary_child, id_map)
        name = resolved.get("name")
        if name:
            return name
    return ""


def _frame_binary_metadata(
    frame_elem: ET.Element, id_map: dict[str, ET.Element]
) -> tuple[str, str, str]:
    """Extract (uuid, load_addr, arch) from the frame's binary element.

    All three are needed by `symbolicate` to feed `atos`. Empty strings mean
    the field wasn't on the binary element — typical for traces from older
    xctrace versions or when symbol tables already named every frame.
    """
    binary_child = frame_elem.find("binary")
    if binary_child is None:
        return "", "", ""
    resolved = _resolve(binary_child, id_map)
    uuid = resolved.get("UUID") or resolved.get("uuid") or ""
    load_addr = resolved.get("load-addr") or resolved.get("loadAddress") or ""
    arch = resolved.get("arch") or resolved.get("architecture") or ""
    return uuid, load_addr, arch


def _thread_descriptor(row: ET.Element, id_map: dict[str, ET.Element]) -> tuple[str, bool]:
    """Extract (thread_name, is_main_thread) from a row. xctrace stores thread
    info under various shapes; we look for an explicit name first, then fall
    back to the formatted display name."""
    thread_elem = row.find("thread")
    if thread_elem is None:
        return "", False
    resolved = _resolve(thread_elem, id_map)
    name = resolved.get("name") or resolved.get("fmt") or ""
    if not name:
        name_child = resolved.find("name")
        if name_child is not None:
            name_resolved = _resolve(name_child, id_map)
            name = (name_resolved.text or "").strip()
    if not name:
        name_attr_child = resolved.find("thread-name")
        if name_attr_child is not None:
            name_resolved = _resolve(name_attr_child, id_map)
            name = (name_resolved.text or "").strip()
    is_main = any(hint in name.lower() for hint in _MAIN_THREAD_HINTS) if name else False
    return name, is_main


def _sample_time_ns(row: ET.Element, id_map: dict[str, ET.Element]) -> int | None:
    """Return the sample offset in nanoseconds.

    Current xctrace exports use `sample-time`; older fixtures and some template
    shapes use `start-time`.
    """
    elem = row.find("sample-time")
    if elem is None:
        elem = row.find("start-time")
    if elem is None:
        return None
    resolved = _resolve(elem, id_map)
    try:
        return int((resolved.text or "0").strip())
    except (AttributeError, ValueError):
        return None


def parse_time_profile_samples(
    xml_content: str,
) -> tuple[list[TimeProfileSample], float]:
    """Parse xctrace's time-profile export into per-sample records.

    Each &lt;row&gt; is one sample (a periodic snapshot of a single running thread).
    Returns the list of samples plus the total Running-state weight in
    milliseconds. Idle leaf samples and non-Running thread states are dropped
    here — they're noise for any downstream view (hot methods, hangs, scope).
    """
    if not xml_content.strip():
        return [], 0.0
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return [], 0.0

    id_map = _build_id_map(root)
    samples: list[TimeProfileSample] = []
    total_duration_ns = 0

    for row in root.iter("row"):
        weight_elem = row.find("weight")
        backtrace_elem = row.find("tagged-backtrace")
        if weight_elem is None or backtrace_elem is None:
            continue

        state_elem = row.find("thread-state")
        if state_elem is not None:
            state_resolved = _resolve(state_elem, id_map)
            state_text = (state_resolved.text or "").strip()
            if state_text and state_text != "Running":
                continue

        weight_resolved = _resolve(weight_elem, id_map)
        try:
            weight = int((weight_resolved.text or "0").strip())
        except (AttributeError, ValueError):
            continue
        if weight <= 0:
            continue

        tagged_resolved = _resolve(backtrace_elem, id_map)
        backtrace_inner = tagged_resolved.find("backtrace")
        if backtrace_inner is None:
            continue
        backtrace_inner = _resolve(backtrace_inner, id_map)

        sample_frames: list[SampleFrame] = []
        for frame_elem in backtrace_inner.findall("frame"):
            frame_resolved = _resolve(frame_elem, id_map)
            name = frame_resolved.get("name")
            if not name or name == "<deduplicated_symbol>":
                continue
            uuid, load_addr, arch = _frame_binary_metadata(frame_resolved, id_map)
            sample_frames.append(
                SampleFrame(
                    symbol=name,
                    binary=_frame_binary(frame_resolved, id_map),
                    addr=frame_resolved.get("addr") or "",
                    binary_uuid=uuid,
                    binary_load_addr=load_addr,
                    arch=arch,
                )
            )

        if not sample_frames:
            continue
        if sample_frames[0].symbol in _IDLE_LEAF_SYMBOLS:
            continue

        thread_name, is_main = _thread_descriptor(row, id_map)
        total_duration_ns += weight
        samples.append(
            TimeProfileSample(
                weight_ns=weight,
                frames=tuple(sample_frames),
                time_ns=_sample_time_ns(row, id_map),
                thread_name=thread_name,
                is_main_thread=is_main,
            )
        )

    return samples, total_duration_ns / _NS_PER_MS


def parse_time_profile_xml(xml_content: str) -> tuple[list[CallTreeFrame], float]:
    """Aggregate per-sample records into self/total weight per symbol.

    Kept as the legacy entry point for callers that only want the call-tree
    view; new code should prefer `parse_time_profile_samples`.
    """
    samples, total_ms = parse_time_profile_samples(xml_content)
    if not samples:
        return [], total_ms

    self_ns: dict[str, int] = defaultdict(int)
    total_ns: dict[str, int] = defaultdict(int)
    binary_for: dict[str, str] = {}

    for sample in samples:
        leaf = sample.frames[0]
        self_ns[leaf.symbol] += sample.weight_ns
        binary_for.setdefault(leaf.symbol, leaf.binary)

        seen: set[str] = set()
        for frame in sample.frames:
            if frame.symbol in seen:
                continue
            seen.add(frame.symbol)
            total_ns[frame.symbol] += sample.weight_ns
            binary_for.setdefault(frame.symbol, frame.binary)

    symbols = set(total_ns) | set(self_ns)
    frames = [
        CallTreeFrame(
            symbol=symbol,
            self_ms=self_ns.get(symbol, 0) / _NS_PER_MS,
            total_ms=total_ns.get(symbol, 0) / _NS_PER_MS,
            binary=binary_for.get(symbol, ""),
        )
        for symbol in symbols
    ]
    return frames, total_ms
