from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from apple_instruments_mcp.analysis.models import (
    NetworkAnalysis,
    NetworkRequest,
    Status,
)
from apple_instruments_mcp.analysis.severity import get_severity

XPATH_NETWORK_CONNECTIONS = '/trace-toc/run[@number="1"]/data/table[@schema="network-connection-detected"]'


def has_network_evidence(xml_content: str) -> bool:
    return (
        "<request" in xml_content
        or "com-apple-cfnetwork-task-intervals" in xml_content
        or "network-connection-detected" in xml_content
        or bool(re.search(r"<(url|duration|bytes|status)[^>]*>", xml_content))
    )


def _indexed_rows(xml_content: str) -> list[dict[str, tuple[str, str, str]]]:
    """Return xctrace rows keyed by schema mnemonic, resolving id/ref values."""
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return []

    rows: list[dict[str, tuple[str, str, str]]] = []
    references: dict[str, ET.Element] = {}
    for node in root.findall(".//node"):
        schema = node.find("schema")
        if schema is None:
            continue
        columns = [col.findtext("mnemonic", "") for col in schema.findall("col")]
        for row in node.findall("row"):
            values: dict[str, tuple[str, str, str]] = {}
            for index, raw_child in enumerate(list(row)):
                child = references.get(raw_child.attrib["ref"], raw_child) if "ref" in raw_child.attrib else raw_child
                if "id" in raw_child.attrib:
                    references[raw_child.attrib["id"]] = raw_child
                if index >= len(columns):
                    continue
                values[columns[index]] = (
                    child.tag,
                    child.attrib.get("fmt", ""),
                    (child.text or "").strip(),
                )
            rows.append(values)
    return rows


def _parse_duration_ms(text: str) -> int:
    if not text:
        return 0
    try:
        return round(float(text) / 1_000_000)
    except ValueError:
        return 0


def _parse_int(text: str) -> int:
    try:
        return int(text)
    except ValueError:
        return 0


def parse_network(
    xml_content: str,
    *,
    request_warning_ms: float = 500,
    request_critical_ms: float = 2000,
    slow_request_critical_count: int = 5,
    transfer_warning_mb: float = 5,
) -> NetworkAnalysis:
    requests: list[NetworkRequest] = []
    connection_level = False

    for row in _indexed_rows(xml_content):
        url = row.get("url", ("", "", ""))[1]
        if url:
            method = row.get("http-method", ("", "GET", ""))[1] or "GET"
            duration_ms = _parse_duration_ms(row.get("duration", ("", "", ""))[2])
            successful = row.get("successful", ("", "1", "1"))[2]
            status_code = 200 if successful not in {"0", "false", "False"} else 0
            requests.append(
                NetworkRequest(
                    url=url,
                    method=method,
                    duration_ms=duration_ms,
                    bytes=0,
                    status_code=status_code,
                    severity=get_severity(duration_ms, request_critical_ms, request_warning_ms),
                )
            )
            continue

        remote = row.get("remote-address", ("", "", ""))[1]
        protocol = row.get("kind", ("", "network", ""))[1]
        if remote:
            connection_level = True
            bytes_count = _parse_int(row.get("recv-buffer-size", ("", "", ""))[2])
            requests.append(
                NetworkRequest(
                    url=remote,
                    method=protocol.upper(),
                    duration_ms=0,
                    bytes=bytes_count,
                    status_code=0,
                    severity="ok",
                )
            )

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

    if connection_level:
        grouped: dict[tuple[str, str], int] = {}
        for request in requests:
            key = (request.method, request.url)
            grouped[key] = grouped.get(key, 0) + request.bytes
        requests = [
            NetworkRequest(
                url=url,
                method=method,
                duration_ms=0,
                bytes=bytes_count,
                status_code=0,
                severity="ok",
            )
            for (method, url), bytes_count in grouped.items()
        ]

    sort_key = (lambda request: request.bytes) if connection_level else (lambda request: request.duration_ms)
    requests.sort(key=sort_key, reverse=True)
    total_transferred = sum(request.bytes for request in requests) / 1_048_576
    slow_count = sum(1 for request in requests if request.severity != "ok")
    failed_count = sum(
        1 for request in requests if request.status_code >= 400 or (request.status_code == 0 and not connection_level)
    )
    status: Status = "good" if slow_count == 0 else "critical" if slow_count > slow_request_critical_count else "warning"

    if connection_level:
        summary = (
            f"✅ {len(requests)} network endpoint(s) observed. "
            "HTTP request timing/status rows were not exported for this trace."
        )
    elif status == "good":
        summary = f"✅ {len(requests)} requests - all within acceptable latency."
    elif status == "warning":
        summary = f"⚠️ {slow_count} slow request(s) found out of {len(requests)} total."
    else:
        summary = f"🔴 {slow_count} slow request(s) - network is a bottleneck."

    recommendations: list[str] = []
    if connection_level:
        recommendations.append(
            "This trace only exposed socket-level Network rows. Record while exercising HTTP flows to get URLSession timing/status details."
        )
    if failed_count:
        recommendations.append("Fix failing requests (4xx/5xx) - these cause silent UX degradation.")
    if total_transferred > transfer_warning_mb:
        if connection_level:
            recommendations.append(
                f"Receive buffers > {transfer_warning_mb:g}MB. Use an HTTP-level trace to confirm payload size before optimizing transfer volume."
            )
        else:
            recommendations.append(
                f"Total transfer > {transfer_warning_mb:g}MB. Use pagination, compression (gzip/brotli), and caching."
            )
    if not connection_level:
        recommendations.append("Use URLCache for GET requests. Consider background URLSession for large transfers.")

    return NetworkAnalysis(
        total_requests=len(requests),
        total_transferred_mb=round(total_transferred, 2),
        status=status,
        slow_requests=requests[:15],
        summary=summary,
        recommendations=recommendations,
    )


def format_network(analysis: NetworkAnalysis, bundle_id: str) -> str:
    connection_level = any(request.status_code == 0 and request.duration_ms == 0 for request in analysis.slow_requests)
    lines = [
        f"# Network Activity - {bundle_id}",
        f"\n{analysis.summary}",
        (
            f"\n**Endpoints:** {analysis.total_requests} | **Receive Buffer:** {analysis.total_transferred_mb}MB"
            if connection_level
            else f"\n**Requests:** {analysis.total_requests} | **Transferred:** {analysis.total_transferred_mb}MB"
        ),
        "\n## Observed Connections" if connection_level else "\n## Slow Requests",
    ]
    if not analysis.slow_requests:
        lines.append("No network activity found.")
    else:
        for request in analysis.slow_requests:
            icon = "🔴" if request.severity == "critical" else "🟡" if request.severity == "warning" else "🟢"
            lines.append(f"\n{icon} `{request.method} {request.url}`")
            if connection_level:
                lines.append(f"   Receive buffer: **{request.bytes / 1024:.1f}KB**")
            else:
                lines.append(
                    f"   Duration: **{request.duration_ms}ms** | Size: {request.bytes / 1024:.1f}KB | Status: {request.status_code}"
                )

    lines.append("\n## Recommendations")
    lines.extend(f"- {recommendation}" for recommendation in analysis.recommendations)
    return "\n".join(lines)
