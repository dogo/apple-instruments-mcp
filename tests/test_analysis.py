import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from apple_instruments_mcp.analysis import (
    RecordingTarget,
    assess_xml_quality,
    build_record_command,
    compare_allocation_analyses,
    compare_launch_analyses,
    compare_time_profile_analyses,
    format_launch,
    format_quality,
    format_target_error,
    has_time_profiler_evidence,
    list_as_json,
    parse_allocations,
    parse_app_launch,
    parse_leaks,
    parse_network,
    parse_time_profiler,
    run_analysis,
)


class AnalysisTests(unittest.TestCase):
    def test_recording_target_launches_bundle_on_device(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-123")

        self.assertEqual(
            target.xctrace_args(),
            ["--device", "SIM-123", "--launch", "--", "com.example.app"],
        )
        self.assertEqual(target.label, "com.example.app")

    def test_recording_target_launches_path_with_args(self) -> None:
        target = RecordingTarget.build(launch_path="/Applications/MyApp.app", launch_args="--debug 'two words'")

        self.assertEqual(
            target.xctrace_args(),
            ["--launch", "--", "/Applications/MyApp.app", "--debug", "two words"],
        )

    def test_recording_target_attaches_to_process_name(self) -> None:
        target = RecordingTarget.build(process_name="MyMacApp")

        self.assertEqual(target.xctrace_args(), ["--attach", "MyMacApp"])

    def test_recording_target_attaches_to_pid(self) -> None:
        target = RecordingTarget.build(pid=1234)

        self.assertEqual(target.xctrace_args(), ["--attach", "1234"])
        self.assertEqual(target.label, "pid:1234")

    def test_recording_target_records_all_processes(self) -> None:
        target = RecordingTarget.build(all_processes=True)

        self.assertEqual(target.xctrace_args(), ["--all-processes"])
        self.assertEqual(target.label, "all processes")

    def test_build_record_command(self) -> None:
        target = RecordingTarget.build(process_name="MyMacApp")

        self.assertEqual(
            build_record_command("Time Profiler", target, 10, Path("/tmp/trace.trace")),
            [
                "xcrun",
                "xctrace",
                "record",
                "--template",
                "Time Profiler",
                "--time-limit",
                "10s",
                "--output",
                "/tmp/trace.trace",
                "--attach",
                "MyMacApp",
            ],
        )

    def test_run_analysis_dry_run(self) -> None:
        target = RecordingTarget.build(launch_path="/Applications/MyApp.app")

        output = asyncio.run(
            run_analysis(
                "Time Profiler",
                target,
                10,
                lambda xml: xml,
                lambda result: result,
                "time profiler",
                has_time_profiler_evidence,
                dry_run=True,
            )
        )

        self.assertIn("# xctrace Dry Run", output)
        self.assertIn("xcrun xctrace record", output)
        self.assertIn("trace.trace", output)
        self.assertIn("/Applications/MyApp.app", output)

    def test_analysis_quality_reports_empty_xml(self) -> None:
        quality = assess_xml_quality("", False, "time profiler")
        output = format_quality(quality)

        self.assertEqual(quality.confidence, "low")
        self.assertIn("Analysis Quality", output)
        self.assertIn("produced no XML", output)

    def test_list_as_json_groups_sections(self) -> None:
        output = """
        Devices:
        My Mac
        iPhone 15 (17.5) (ABCD-1234)

        Templates:
        Time Profiler
        Allocations
        """

        parsed = json.loads(list_as_json(output))

        self.assertEqual(parsed["devices"][0]["name"], "My Mac")
        self.assertEqual(parsed["devices"][1]["id"], "ABCD-1234")
        self.assertEqual(parsed["templates"][0]["name"], "Time Profiler")

    def test_recording_target_requires_exactly_one_target(self) -> None:
        with self.assertRaises(ValueError):
            RecordingTarget.build()

        with self.assertRaises(ValueError):
            RecordingTarget.build(bundle_id="com.example.app", launch_path="/Applications/MyApp.app")

    def test_parse_app_launch_from_node_call_tree(self) -> None:
        xml = """
        <trace>
          <launch-time>1.2</launch-time>
          <node name="-[DatabaseManager setup]" self-weight="540ms" total-weight="540ms" />
          <node name="+[AnalyticsSDK configure:]" self-weight="210ms" total-weight="210ms" />
        </trace>
        """

        analysis = parse_app_launch(xml, "com.example.app")
        output = format_launch(analysis, "com.example.app")

        self.assertEqual(analysis.total_launch_ms, 1200)
        self.assertEqual(analysis.status, "critical")
        self.assertEqual(analysis.offenders[0].symbol, "-[DatabaseManager setup]")
        self.assertIn("Move database initialization", output)

    def test_parse_app_launch_accepts_custom_thresholds(self) -> None:
        xml = """
        <trace>
          <launch-time>0.8</launch-time>
          <node name="-[Warmup run]" self-weight="120ms" total-weight="120ms" />
        </trace>
        """

        analysis = parse_app_launch(
            xml,
            "com.example.app",
            launch_good_ms=900,
            launch_critical_ms=1500,
            offender_warning_ms=900,
            offender_critical_ms=1000,
        )

        self.assertEqual(analysis.status, "good")
        self.assertEqual(analysis.offenders[0].severity, "ok")

    def test_parse_allocations_rows(self) -> None:
        xml = """
        <row><type>UIImage</type><live-bytes>2097152</live-bytes><live-count>4</live-count><total-bytes>4194304</total-bytes><total-count>8</total-count></row>
        <peak-memory>64 mb</peak-memory>
        """

        analysis = parse_allocations(xml)

        self.assertEqual(analysis.peak_memory_mb, 64)
        self.assertEqual(analysis.live_memory_mb, 2)
        self.assertEqual(analysis.top_allocations[0].type, "UIImage")

    def test_parse_allocations_accepts_custom_thresholds(self) -> None:
        xml = """
        <row><type>Buffer</type><live-bytes>2097152</live-bytes><live-count>1</live-count><total-bytes>2097152</total-bytes><total-count>1</total-count></row>
        <peak-memory>64 mb</peak-memory>
        """

        analysis = parse_allocations(xml, memory_warning_mb=32, memory_critical_mb=48)

        self.assertEqual(analysis.status, "critical")

    def test_parse_leaks_direct_entries(self) -> None:
        xml = '<leak type="Closure" count="2" size="4096" root-cycle="true" />'

        analysis = parse_leaks(xml)

        self.assertEqual(analysis.total_leaks, 2)
        self.assertEqual(analysis.total_leaked_bytes, 4096)
        self.assertTrue(analysis.leaks[0].root_cycle)

    def test_parse_time_profiler_from_node_call_tree(self) -> None:
        xml = '<node name="JSONDecoder.decode" self-weight="75ms" total-weight="120ms" />'

        analysis = parse_time_profiler(xml)

        self.assertEqual(analysis.total_duration_ms, 120)
        self.assertEqual(analysis.hot_methods[0].severity, "warning")
        self.assertIn("JSON", analysis.hot_methods[0].symbol)

    def test_parse_time_profiler_accepts_custom_thresholds(self) -> None:
        xml = '<node name="Work.run" self-weight="75ms" total-weight="120ms" />'

        analysis = parse_time_profiler(
            xml,
            total_good_ms=150,
            total_critical_ms=300,
            method_warning_ms=100,
            method_critical_ms=200,
        )

        self.assertEqual(analysis.status, "good")
        self.assertEqual(analysis.hot_methods[0].severity, "ok")

    def test_parse_network_requests(self) -> None:
        xml = '<request url="https://example.com/api" method="GET" duration="0.8" bytes="2048" status="200" />'

        analysis = parse_network(xml)

        self.assertEqual(analysis.total_requests, 1)
        self.assertEqual(analysis.slow_requests[0].duration_ms, 800)
        self.assertEqual(analysis.status, "warning")

    def test_parse_network_accepts_custom_thresholds(self) -> None:
        xml = '<request url="https://example.com/api" method="GET" duration="0.8" bytes="6291456" status="200" />'

        analysis = parse_network(
            xml,
            request_warning_ms=1000,
            request_critical_ms=2000,
            transfer_warning_mb=1,
        )

        self.assertEqual(analysis.slow_requests[0].severity, "ok")
        self.assertEqual(analysis.status, "good")
        self.assertTrue(any(recommendation.startswith("Total transfer > 1MB") for recommendation in analysis.recommendations))

    def test_compare_launch_analyses_reports_delta(self) -> None:
        baseline = parse_app_launch(
            '<trace><launch-time>0.5</launch-time><node name="A.start" self-weight="100ms" total-weight="100ms" /></trace>',
            "com.example.app",
        )
        candidate = parse_app_launch(
            '<trace><launch-time>0.8</launch-time><node name="A.start" self-weight="200ms" total-weight="200ms" /></trace>',
            "com.example.app",
        )

        output = compare_launch_analyses(baseline, candidate, "com.example.app")

        self.assertIn("Launch Trace Comparison", output)
        self.assertIn("+300ms (regression)", output)

    def test_compare_allocation_analyses_reports_delta(self) -> None:
        baseline = parse_allocations(
            "<row><type>Buffer</type><live-bytes>1048576</live-bytes><live-count>1</live-count><total-bytes>1048576</total-bytes><total-count>1</total-count></row><peak-memory>10 mb</peak-memory>"
        )
        candidate = parse_allocations(
            "<row><type>Buffer</type><live-bytes>3145728</live-bytes><live-count>3</live-count><total-bytes>3145728</total-bytes><total-count>3</total-count></row><peak-memory>14 mb</peak-memory>"
        )

        output = compare_allocation_analyses(baseline, candidate, "com.example.app")

        self.assertIn("Memory Trace Comparison", output)
        self.assertIn("+4MB (regression)", output)
        self.assertIn("+2MB (regression)", output)

    def test_compare_time_profile_analyses_reports_improvement(self) -> None:
        baseline = parse_time_profiler('<node name="Work.run" self-weight="120ms" total-weight="150ms" />')
        candidate = parse_time_profiler('<node name="Work.run" self-weight="80ms" total-weight="100ms" />')

        output = compare_time_profile_analyses(baseline, candidate, "com.example.app")

        self.assertIn("CPU Trace Comparison", output)
        self.assertIn("-50ms (improvement)", output)


class RecordingTargetValidationTests(unittest.TestCase):
    def test_validate_passes_for_running_pid(self) -> None:
        target = RecordingTarget.build(pid=os.getpid())

        self.assertEqual(target.validate(), [])

    def test_validate_rejects_non_positive_pid(self) -> None:
        target = RecordingTarget.build(pid=0)

        errors = target.validate()

        self.assertEqual(len(errors), 1)
        self.assertIn("positive integer", errors[0])

    def test_validate_rejects_dead_pid(self) -> None:
        # Allocate then reap a child so the pid is no longer running.
        pid = os.fork() if hasattr(os, "fork") else None
        if pid == 0:
            os._exit(0)
        if pid is None:
            self.skipTest("fork unavailable on this platform")
        os.waitpid(pid, 0)

        target = RecordingTarget.build(pid=pid)
        errors = target.validate()

        self.assertEqual(len(errors), 1)
        self.assertIn(f"pid {pid}", errors[0])

    def test_validate_rejects_missing_launch_path(self) -> None:
        target = RecordingTarget.build(launch_path="/definitely/does/not/exist.app")

        errors = target.validate()

        self.assertEqual(len(errors), 1)
        self.assertIn("launch_path does not exist", errors[0])

    def test_validate_passes_for_existing_launch_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = RecordingTarget.build(launch_path=tmp)

            self.assertEqual(target.validate(), [])

    def test_validate_expands_tilde_in_launch_path(self) -> None:
        target = RecordingTarget.build(launch_path="~")

        self.assertEqual(target.validate(), [])

    def test_validate_rejects_bundle_id_with_bad_chars(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example app!")

        errors = target.validate()

        self.assertEqual(len(errors), 1)
        self.assertIn("bundle_id", errors[0])

    def test_validate_accepts_reverse_dns_bundle_id(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example.my-app_v2")

        self.assertEqual(target.validate(), [])


class FormatTargetErrorTests(unittest.TestCase):
    def test_bundle_not_installed_message(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-123")

        output = format_target_error(target, "App Launch", "Could not find application com.example.app")

        self.assertIn("not installed", output)
        self.assertIn("com.example.app", output)
        self.assertIn("simctl listapps SIM-123", output)

    def test_dead_pid_message_includes_ps_hint(self) -> None:
        target = RecordingTarget.build(pid=4242)

        output = format_target_error(target, "Time Profiler", "kill: No such process")

        self.assertIn("Process is not running", output)
        self.assertIn("ps -p 4242", output)

    def test_dead_process_name_message_includes_pgrep_hint(self) -> None:
        target = RecordingTarget.build(process_name="MyMacApp")

        output = format_target_error(target, "Time Profiler", "No such process")

        self.assertIn("pgrep -f MyMacApp", output)

    def test_device_not_found_message_suggests_boot(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-XYZ")

        output = format_target_error(target, "App Launch", "Device could not be found: SIM-XYZ")

        self.assertIn("could not resolve the device", output)
        self.assertIn("simctl boot SIM-XYZ", output)

    def test_device_not_found_without_device_id_suggests_list(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example.app")

        output = format_target_error(target, "App Launch", "Device not found")

        self.assertIn("list_devices", output)

    def test_invalid_launch_path_message(self) -> None:
        target = RecordingTarget.build(launch_path="/Applications/Missing.app")

        output = format_target_error(target, "Time Profiler", "No such file or directory")

        self.assertIn("rejected the launch_path", output)
        self.assertIn("/Applications/Missing.app", output)

    def test_xcode_tools_missing_message(self) -> None:
        target = RecordingTarget.build(process_name="MyMacApp")

        output = format_target_error(target, "Time Profiler", "xcrun: error: invalid active developer path")

        self.assertIn("xcode-select --install", output)

    def test_generic_fallback_is_target_aware_for_all_processes(self) -> None:
        target = RecordingTarget.build(all_processes=True)

        output = format_target_error(target, "Time Profiler", "totally unexpected failure")

        self.assertIn("--all-processes", output)
        self.assertIn("sudo", output)

    def test_generic_fallback_is_target_aware_for_launch_path(self) -> None:
        target = RecordingTarget.build(launch_path="/Applications/Calculator.app")

        output = format_target_error(target, "Time Profiler", "totally unexpected failure")

        self.assertIn("signing/entitlements", output)

    def test_error_includes_target_label_and_template(self) -> None:
        target = RecordingTarget.build(pid=1234)

        output = format_target_error(target, "Allocations", "boom")

        self.assertIn("Allocations", output)
        self.assertIn("pid:1234", output)


if __name__ == "__main__":
    unittest.main()
