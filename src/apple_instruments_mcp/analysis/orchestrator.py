from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TypeVar

from apple_instruments_mcp.analysis.models import AnalysisQuality
from apple_instruments_mcp.analysis.presets import (
    Family,
    preset_families,
    preset_instruments,
)
from apple_instruments_mcp.analysis.quality import assess_xml_quality, format_quality
from apple_instruments_mcp.analysis.symbolicate import (
    format_symbolication_summary,
    symbolize_samples,
)
from apple_instruments_mcp.analysis.targets import RecordingTarget, format_target_error
from apple_instruments_mcp.analysis.time_profile import (
    build_time_profile_analysis,
    format_time_profiler,
    has_time_profiler_evidence,
)
from apple_instruments_mcp.analysis.xctrace import (
    build_record_command,
    export_xml,
    format_command,
    format_preflight_findings,
    preflight_device_target,
    preflight_ios_target,
    record_trace,
)
from apple_instruments_mcp.analysis.xml_helpers import parse_time_profile_samples

T = TypeVar("T")


_UNSUPPORTED_TEMPLATES: dict[str, str] = {
    "allocations": "Allocations",
    "leaks": "Leaks",
}
_RUN_ISSUES_STORE = "RunIssues.storedata"


def _usable_partial_trace(trace_path: Path) -> Path | None:
    """Return the trace only when xctrace wrote a non-boilerplate payload."""
    try:
        if trace_path.is_file():
            return trace_path if trace_path.stat().st_size > 0 else None
        if not trace_path.is_dir():
            return None
        for entry in trace_path.rglob("*"):
            if not entry.is_file():
                continue
            relative_parts = entry.relative_to(trace_path).parts
            if _RUN_ISSUES_STORE in relative_parts:
                continue
            if entry.stat().st_size > 0:
                return trace_path
    except OSError:
        return None
    return None


def _artifact_lines(
    trace_path: Path,
    xml_paths: tuple[tuple[str, Path], ...] = (),
) -> list[str]:
    def artifact_line(label: str, path: Path) -> str:
        suffix = "" if path.exists() else " (not created)"
        return f"- {label}: `{path}`{suffix}"

    lines = [
        "",
        "## Artifacts",
        f"- Run directory: `{trace_path.parent}`",
        artifact_line("Trace", trace_path),
    ]
    lines.extend(artifact_line(label, path) for label, path in xml_paths)
    return lines


def _error_bullet(error: str, *, label: str | None = None) -> str:
    error_detail = error.strip() or "No error details were provided."
    detail = f"{label}: {error_detail}" if label else error_detail
    indented_detail = detail.replace("\n", "\n  ")
    return f"- {indented_detail}"


def _format_export_failure(parser_name: str, error: str) -> str:
    analysis_name = parser_name.replace("_", " ").title()
    return "\n".join(
        [
            f"# {analysis_name} Analysis Inconclusive",
            "",
            "`xctrace` failed to export the data required by this parser.",
            "No performance conclusions were generated from this trace.",
            "",
            "## Export Error",
            _error_bullet(error),
        ]
    )


def _format_comparison_export_failure(
    parser_name: str, failures: tuple[tuple[str, str], ...]
) -> str:
    analysis_name = parser_name.replace("_", " ").title()
    return "\n".join(
        [
            f"# {analysis_name} Trace Comparison Inconclusive",
            "",
            "`xctrace` failed to export one or more traces required for comparison.",
            "No regression or improvement conclusions were generated.",
            "",
            "## Export Errors",
            *(_error_bullet(error, label=label) for label, error in failures),
        ]
    )


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
    async_pipeline: Callable[[str], Awaitable[str]] | None = None,
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

    preflight_timings: dict[str, float] | None = None
    if target.device_id:
        report = (
            await preflight_ios_target(target.device_id, target.bundle_id)
            if target.bundle_id
            else await preflight_device_target(target.device_id)
        )
        preflight_timings = report.timings
        if report.blockers:
            return format_preflight_findings(template, target.label, report.blockers)

    if base_dir:
        base_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="instruments-mcp-", dir=base_dir))
    trace_path = tmp_dir / "trace.trace"
    xml_path = tmp_dir / "export.xml"
    preserve_tmp_dir = False

    try:
        await record_trace(template, target, time_limit_seconds, trace_path)
        try:
            if xpath:
                await export_xml(trace_path, xml_path, xpath=xpath)
            else:
                await export_xml(trace_path, xml_path, toc=True)
        except Exception as exc:
            result = _format_export_failure(parser_name, str(exc))
            if keep_trace:
                preserve_tmp_dir = True
                result = "\n".join(
                    [result, *_artifact_lines(trace_path, (("XML export", xml_path),))]
                )
            return result
        xml_content = xml_path.read_text(encoding="utf-8") if xml_path.exists() else ""
        if async_pipeline is not None:
            result = await async_pipeline(xml_content)
        else:
            result = formatter(parser(xml_content))
        if async_pipeline is None:
            quality = assess_xml_quality(xml_content, evidence_checker(xml_content), parser_name)
            quality_text = format_quality(quality)
            if quality_text:
                result = f"{result}\n{quality_text}"
        if keep_trace:
            preserve_tmp_dir = True
            result = "\n".join(
                [result, *_artifact_lines(trace_path, (("XML export", xml_path),))]
            )
        return result
    except Exception as error:
        partial_trace = _usable_partial_trace(trace_path)
        preserve_tmp_dir = keep_trace or partial_trace is not None
        result = format_target_error(
            target,
            template,
            str(error),
            partial_trace=partial_trace,
            preflight_timings=preflight_timings,
        )
        if keep_trace:
            result = "\n".join(
                [result, *_artifact_lines(trace_path, (("XML export", xml_path),))]
            )
        return result
    finally:
        if not preserve_tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


async def _run_family(
    family: Family, trace_path: Path, xml_path: Path, target_label: str
) -> str | None:
    """Export and analyze one family from a finished trace bundle.

    Returns the formatted family section, or `None` when the family produced
    no evidence (its instrument was in the recording but emitted nothing
    parseable — typically the case when the workload didn't exercise it). On
    export failure the caller decides what to surface.
    """
    try:
        await export_xml(trace_path, xml_path, xpath=family.xpath)
    except Exception as exc:
        return (
            f"## {family.section_title}\n"
            "**Status:** Inconclusive\n"
            f"{_error_bullet(f'xctrace export failed: {exc}')}"
        )
    xml_content = xml_path.read_text(encoding="utf-8") if xml_path.exists() else ""
    if not family.evidence_checker(xml_content):
        return None
    analysis = family.parser(xml_content)
    body = family.formatter(analysis, target_label)
    quality = assess_xml_quality(
        xml_content, family.evidence_checker(xml_content), family.parser_name
    )
    quality_text = format_quality(quality)
    section = f"## {family.section_title}\n\n{body}"
    if quality_text:
        section = f"{section}\n{quality_text}"
    return section


async def run_preset_analysis(
    preset: str,
    target: RecordingTarget,
    time_limit_seconds: int,
    *,
    dry_run: bool = False,
    keep_trace: bool = False,
    output_dir: str | None = None,
) -> str:
    """Record once with all instruments needed by `preset`, then run every
    family in the preset against the resulting trace bundle. Each family that
    produced evidence becomes its own section in the report; missing families
    are dropped so the LLM doesn't have to interpret "no data" sections.
    """
    instruments = preset_instruments(preset)
    families = preset_families(preset)
    preset_label = f"{preset} ({', '.join(instruments)})"

    base_dir = Path(os.path.expanduser(output_dir)) if output_dir else None
    if dry_run:
        trace_path = (base_dir / "trace.trace") if base_dir else Path("<temporary-directory>") / "trace.trace"
        command = format_command(
            build_record_command(
                None, target, time_limit_seconds, trace_path, instruments=instruments
            )
        )
        return "\n".join(
            [
                "# xctrace Dry Run",
                "",
                f"**Preset:** {preset_label}",
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
                f"Refusing to record preset '{preset}': target failed pre-flight checks.",
                "",
                *(f"- {error}" for error in validation_errors),
            ]
        )

    preflight_timings: dict[str, float] | None = None
    if target.device_id:
        report = (
            await preflight_ios_target(target.device_id, target.bundle_id)
            if target.bundle_id
            else await preflight_device_target(target.device_id)
        )
        preflight_timings = report.timings
        if report.blockers:
            return format_preflight_findings(preset_label, target.label, report.blockers)

    if base_dir:
        base_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="instruments-mcp-", dir=base_dir))
    trace_path = tmp_dir / "trace.trace"
    preserve_tmp_dir = False
    xml_paths = tuple(
        (f"{family.section_title} XML export", tmp_dir / f"export-{family.key}.xml")
        for family in families
    )

    try:
        await record_trace(
            None, target, time_limit_seconds, trace_path, instruments=instruments
        )

        sections: list[str] = [f"# {preset.capitalize()} Profile — {target.label}", ""]
        sections.append(f"**Instruments recorded:** {', '.join(instruments)}")
        missing: list[str] = []
        for family, (_, xml_path) in zip(families, xml_paths, strict=True):
            section = await _run_family(family, trace_path, xml_path, target.label)
            if section is None:
                missing.append(family.section_title)
                continue
            sections.append("")
            sections.append(section)
        if missing:
            sections.append("")
            sections.append("## Notes")
            sections.extend(
                f"- No `{title}` data in the trace — workload may not have exercised it."
                for title in missing
            )
        if keep_trace:
            preserve_tmp_dir = True
            sections.extend(_artifact_lines(trace_path, xml_paths))
        return "\n".join(sections)
    except Exception as error:
        partial_trace = _usable_partial_trace(trace_path)
        preserve_tmp_dir = keep_trace or partial_trace is not None
        result = format_target_error(
            target,
            preset_label,
            str(error),
            partial_trace=partial_trace,
            preflight_timings=preflight_timings,
        )
        if keep_trace:
            result = "\n".join([result, *_artifact_lines(trace_path, xml_paths)])
        return result
    finally:
        if not preserve_tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


async def analyze_existing(
    trace_path: str,
    parser: Callable[[str], T],
    formatter: Callable[[T], str],
    parser_name: str,
    evidence_checker: Callable[[str], bool],
    *,
    xpath: str | None = None,
    async_pipeline: Callable[[str], Awaitable[str]] | None = None,
) -> str:
    expanded_trace_path = Path(os.path.expanduser(trace_path))
    if not expanded_trace_path.exists():
        return f"Trace file not found: {trace_path}"

    tmp_dir = Path(tempfile.mkdtemp(prefix="instruments-mcp-"))
    xml_path = tmp_dir / "export.xml"

    try:
        try:
            if xpath:
                await export_xml(expanded_trace_path, xml_path, xpath=xpath)
            else:
                await export_xml(expanded_trace_path, xml_path, toc=True)
        except Exception as exc:
            return _format_export_failure(parser_name, str(exc))
        xml_content = xml_path.read_text(encoding="utf-8") if xml_path.exists() else ""
        if async_pipeline is not None:
            result = await async_pipeline(xml_content)
        else:
            result = formatter(parser(xml_content))
            quality = assess_xml_quality(xml_content, evidence_checker(xml_content), parser_name)
            quality_text = format_quality(quality)
            if quality_text:
                result = f"{result}\n{quality_text}"
        return result
    except Exception as error:
        return f"Error analyzing trace: {error}"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def build_time_profile_symbolicated_pipeline(
    label: str,
    dsym_path: str,
    *,
    total_good_ms: float = 100,
    total_critical_ms: float = 500,
    method_warning_ms: float = 50,
    method_critical_ms: float = 200,
    start_ms: int | None = None,
    end_ms: int | None = None,
    hang_threshold_ms: int = 250,
    user_binaries: tuple[str, ...] = (),
) -> Callable[[str], Awaitable[str]]:
    """Return an async pipeline that resolves a Time Profiler XML into a
    formatted report with dSYM-resolved frame names.

    Suitable as the `async_pipeline` argument to `run_analysis` /
    `analyze_existing`. Inlines symbolication between sample parsing and
    aggregation so the hot-method list shows resolved symbols instead of raw
    addresses, then appends a status block reporting resolved / unresolved
    counts.
    """

    async def pipeline(xml_content: str) -> str:
        samples, total_ms_unscoped = parse_time_profile_samples(xml_content)
        symbolicated, summary = await symbolize_samples(samples, dsym_path)
        analysis = build_time_profile_analysis(
            symbolicated,
            total_ms_unscoped,
            total_good_ms=total_good_ms,
            total_critical_ms=total_critical_ms,
            method_warning_ms=method_warning_ms,
            method_critical_ms=method_critical_ms,
            start_ms=start_ms,
            end_ms=end_ms,
            hang_threshold_ms=hang_threshold_ms,
            user_binaries=user_binaries,
        )
        body = format_time_profiler(analysis, label)
        quality = assess_xml_quality(
            xml_content, has_time_profiler_evidence(xml_content), "time profiler"
        )
        quality_text = format_quality(quality)
        sym_text = format_symbolication_summary(summary)
        sections = [body]
        if quality_text:
            sections.append(quality_text)
        if sym_text:
            sections.append(sym_text)
        return "\n\n".join(s for s in sections if s)

    return pipeline


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

        export_failures = tuple(
            (label, error)
            for label, error in (
                ("Baseline", baseline_export_error),
                ("Candidate", candidate_export_error),
            )
            if error is not None
        )
        if export_failures:
            return _format_comparison_export_failure(parser_name, export_failures)

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
