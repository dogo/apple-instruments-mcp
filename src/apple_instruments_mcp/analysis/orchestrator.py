from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from apple_instruments_mcp.analysis.models import AnalysisQuality
from apple_instruments_mcp.analysis.quality import assess_xml_quality, format_quality
from apple_instruments_mcp.analysis.targets import RecordingTarget, format_target_error
from apple_instruments_mcp.analysis.xctrace import (
    build_record_command,
    export_xml,
    format_command,
    record_trace,
)

T = TypeVar("T")


_UNSUPPORTED_TEMPLATES: dict[str, str] = {
    "allocations": "Allocations",
    "leaks": "Leaks",
}


def unsupported_template_report(template_kind: str, target_label: str) -> str:
    """Stable error report for template views without a supported parser."""
    pretty = _UNSUPPORTED_TEMPLATES.get(template_kind, template_kind.title())
    return "\n".join(
        [
            f"# {pretty} Analysis - {target_label}",
            "",
            f"## {pretty} is not available in this parser",
            "",
            f"This version does not have a validated parser for the exported {pretty} view.",
            "Open the trace in Instruments.app for full detail, or inspect the trace table",
            "of contents with `xcrun xctrace export --toc` to find an exportable detail.",
            "",
            "## Workarounds",
            "",
            *(
                [
                    "- Open the trace in Instruments.app for the full Allocations / VM Tracker view.",
                    "- For programmatic memory snapshots, use Xcode's Memory Graph Debugger.",
                    "- For runtime heap inspection on macOS, the `heap <pid>` command-line tool.",
                ]
                if template_kind == "allocations"
                else [
                    "- Open the trace in Instruments.app for the full Leaks view.",
                    "- For runtime leak inspection on macOS, the `leaks <pid>` command-line tool.",
                ]
            ),
        ]
    )


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
    xpath: str | None = None,
) -> str:
    base_dir = Path(os.path.expanduser(output_dir)) if output_dir else None
    if dry_run:
        trace_path = (base_dir / "trace.trace") if base_dir else Path("<temporary-directory>") / "trace.trace"
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
    trace_path = tmp_dir / "trace.trace"
    xml_path = tmp_dir / "export.xml"

    try:
        await record_trace(template, target, time_limit_seconds, trace_path)
        export_error: str | None = None
        try:
            if xpath:
                await export_xml(trace_path, xml_path, xpath=xpath)
            else:
                await export_xml(trace_path, xml_path, toc=True)
        except Exception as exc:
            export_error = str(exc)
        xml_content = xml_path.read_text(encoding="utf-8") if xml_path.exists() else ""
        result = formatter(parser(xml_content))
        if export_error:
            result = f"{result}\n\n## Export Warning\n- xctrace export failed: {export_error}"
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
    *,
    xpath: str | None = None,
) -> str:
    expanded_trace_path = Path(os.path.expanduser(trace_path))
    if not expanded_trace_path.exists():
        return f"Trace file not found: {trace_path}"

    tmp_dir = Path(tempfile.mkdtemp(prefix="instruments-mcp-"))
    xml_path = tmp_dir / "export.xml"

    try:
        export_error: str | None = None
        try:
            if xpath:
                await export_xml(expanded_trace_path, xml_path, xpath=xpath)
            else:
                await export_xml(expanded_trace_path, xml_path, toc=True)
        except Exception as exc:
            export_error = str(exc)
        xml_content = xml_path.read_text(encoding="utf-8") if xml_path.exists() else ""
        result = formatter(parser(xml_content))
        quality = assess_xml_quality(xml_content, evidence_checker(xml_content), parser_name)
        quality_text = format_quality(quality)
        if quality_text:
            result = f"{result}\n{quality_text}"
        if export_error:
            result = f"{result}\n\n## Export Warning\n- xctrace export failed: {export_error}"
        return result
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
    *,
    xpath: str | None = None,
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

    async def _export(trace: Path, target: Path) -> str | None:
        try:
            if xpath:
                await export_xml(trace, target, xpath=xpath)
            else:
                await export_xml(trace, target, toc=True)
        except Exception as exc:
            return str(exc)
        return None

    try:
        baseline_export_error = await _export(baseline_path, baseline_xml_path)
        candidate_export_error = await _export(candidate_path, candidate_xml_path)

        baseline_xml = baseline_xml_path.read_text(encoding="utf-8") if baseline_xml_path.exists() else ""
        candidate_xml = candidate_xml_path.read_text(encoding="utf-8") if candidate_xml_path.exists() else ""
        result = comparator(parser(baseline_xml), parser(candidate_xml))

        baseline_quality = assess_xml_quality(baseline_xml, evidence_checker(baseline_xml), f"baseline {parser_name}")
        candidate_quality = assess_xml_quality(candidate_xml, evidence_checker(candidate_xml), f"candidate {parser_name}")
        warnings = baseline_quality.warnings + candidate_quality.warnings
        if warnings:
            result = f"{result}\n{format_quality(AnalysisQuality(confidence='low', warnings=warnings))}"

        export_errors = [error for error in (baseline_export_error, candidate_export_error) if error]
        if export_errors:
            lines = ["", "## Export Warning"]
            lines.extend(f"- xctrace export failed: {error}" for error in export_errors)
            result = f"{result}\n" + "\n".join(lines)
        return result
    except Exception as error:
        return f"Error comparing traces: {error}"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
