from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from apple_instruments_mcp.analysis.models import LeakEntry, LeaksAnalysis, Status
from apple_instruments_mcp.analysis.severity import get_leak_suggestion

XPATH_LEAKS_DETAILS = '/trace-toc/run[@number="1"]/tracks/track[@name="Leaks"]/details/detail[@name="Leaks"]'


def has_leaks_evidence(xml_content: str) -> bool:
    return (
        "<leak" in xml_content
        or bool(re.search(r"<(responsible-library|size)[^>]*>", xml_content))
        or bool(re.search(r'<row[^>]+(?:leak|size|bytes|category|responsible)', xml_content, re.IGNORECASE))
    )


def parse_leaks(xml_content: str, *, leak_critical_count: int = 10) -> LeaksAnalysis:
    leaks: list[LeakEntry] = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        root = None

    if root is not None:
        for row in root.iter("row"):
            type_name = (
                row.attrib.get("type")
                or row.attrib.get("leaked-object")
                or row.attrib.get("category")
                or row.attrib.get("responsible-library")
                or row.attrib.get("responsible-caller")
                or row.attrib.get("responsible-frame")
            )
            size_value = (
                row.attrib.get("size")
                or row.attrib.get("bytes")
                or row.attrib.get("persistent-bytes")
                or row.attrib.get("total-bytes")
            )
            if not type_name or not size_value:
                continue
            count = int(
                row.attrib.get("count")
                or row.attrib.get("count-persistent")
                or row.attrib.get("count-total")
                or 1
            )
            size = int(size_value)
            root_cycle = (row.attrib.get("root-cycle") or row.attrib.get("cycle") or "false").lower() == "true"
            if count <= 0 or size <= 0:
                continue
            leaks.append(
                LeakEntry(
                    type=type_name,
                    count=count,
                    total_bytes=size,
                    root_cycle=root_cycle,
                    suggestion=get_leak_suggestion(type_name),
                )
            )

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
                LeakEntry(
                    type=type_name,
                    count=1,
                    total_bytes=size,
                    root_cycle=False,
                    suggestion=get_leak_suggestion(type_name),
                )
            )

    grouped: dict[tuple[str, bool], LeakEntry] = {}
    for leak in leaks:
        key = (leak.type, leak.root_cycle)
        existing = grouped.get(key)
        if existing:
            grouped[key] = LeakEntry(
                type=leak.type,
                count=existing.count + leak.count,
                total_bytes=existing.total_bytes + leak.total_bytes,
                root_cycle=existing.root_cycle or leak.root_cycle,
                suggestion=existing.suggestion or leak.suggestion,
            )
        else:
            grouped[key] = leak

    leaks = list(grouped.values())
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
