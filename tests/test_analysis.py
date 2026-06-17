import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest import mock

from apple_instruments_mcp.analysis import (
    RecordingTarget,
    assess_xml_quality,
    build_record_command,
    compare_allocation_analyses,
    compare_launch_analyses,
    compare_time_profile_analyses,
    format_quality,
    format_target_error,
    format_time_profiler,
    has_allocations_evidence,
    has_time_profiler_evidence,
    list_as_json,
    parse_allocations,
    parse_app_launch,
    parse_leaks,
    parse_network,
    parse_time_profiler,
    run_analysis,
)
from apple_instruments_mcp.analysis import xctrace as xctrace_module
from apple_instruments_mcp.analysis.xctrace import (
    PreflightFinding,
    _trace_bundle_finalized,
    _watchdog_loop,
    find_stale_xctrace_pids,
    format_preflight_findings,
    kill_stale_xctrace_processes,
    preflight_ios_target,
    probe_xctrace_health,
)


def _time_profile_fixture() -> str:
    # Three 100ms samples mirroring xctrace's real --xpath time-profile output:
    #   row 1: LeafFunc -> MidFunc -> RootFunc          (leaf = LeafFunc)
    #   row 2: same backtrace by reference              (leaf = LeafFunc)
    #   row 3: OtherLeaf -> RootFunc                    (leaf = OtherLeaf)
    return """<?xml version="1.0"?>
<trace-query-result>
<node xpath="//time-profile">
  <schema name="time-profile"/>
  <row>
    <weight id="W" fmt="150.00 ms">150000000</weight>
    <tagged-backtrace id="TB1">
      <backtrace id="B1">
        <frame id="LEAF" name="LeafFunc" addr="0x100"/>
        <frame id="MID" name="MidFunc" addr="0x200"/>
        <frame id="ROOT" name="RootFunc" addr="0x300"/>
      </backtrace>
    </tagged-backtrace>
  </row>
  <row>
    <weight ref="W"/>
    <tagged-backtrace id="TB2">
      <backtrace id="B2">
        <frame ref="LEAF"/>
        <frame ref="MID"/>
        <frame ref="ROOT"/>
      </backtrace>
    </tagged-backtrace>
  </row>
  <row>
    <weight ref="W"/>
    <tagged-backtrace id="TB3">
      <backtrace id="B3">
        <frame id="OTHER" name="OtherLeaf" addr="0x400"/>
        <frame ref="ROOT"/>
      </backtrace>
    </tagged-backtrace>
  </row>
</node>
</trace-query-result>"""


def _launch_fixture() -> str:
    # Four 200ms time-profile samples covering the cases parse_app_launch handles:
    #   - Swift runtime symbol (pre-main classification)
    #   - mach_o:: dyld symbol (pre-main classification, included)
    #   - AppDelegate Cocoa method (post-main classification)
    #   - mach_msg2_trap leaf (idle wait, must be dropped entirely)
    return """<?xml version="1.0"?>
<trace-query-result>
<node xpath="//time-profile">
  <schema name="time-profile"/>
  <row>
    <weight id="W" fmt="200.00 ms">200000000</weight>
    <thread-state id="RUN" fmt="Running">Running</thread-state>
    <tagged-backtrace id="TB1">
      <backtrace id="B1">
        <frame name="swift_conformsToProtocol" addr="0x100"/>
        <frame name="start" addr="0x300"/>
      </backtrace>
    </tagged-backtrace>
  </row>
  <row>
    <weight ref="W"/>
    <thread-state ref="RUN"/>
    <tagged-backtrace id="TB2">
      <backtrace id="B2">
        <frame name="mach_o::UnsafeHeader::forEachLoadCommand" addr="0x200"/>
        <frame name="start" addr="0x300"/>
      </backtrace>
    </tagged-backtrace>
  </row>
  <row>
    <weight ref="W"/>
    <thread-state ref="RUN"/>
    <tagged-backtrace id="TB3">
      <backtrace id="B3">
        <frame name="-[AppDelegate didFinishLaunchingWithOptions:]" addr="0x400"/>
        <frame name="UIApplicationMain" addr="0x500"/>
      </backtrace>
    </tagged-backtrace>
  </row>
  <row>
    <weight ref="W"/>
    <thread-state ref="RUN"/>
    <tagged-backtrace id="TB4">
      <backtrace id="B4">
        <frame name="mach_msg2_trap" addr="0x600"/>
        <frame name="start_wqthread" addr="0x700"/>
      </backtrace>
    </tagged-backtrace>
  </row>
</node>
</trace-query-result>"""


def _time_profile_single_sample(symbol: str, weight_ns: int) -> str:
    return f"""<?xml version="1.0"?>
<trace-query-result>
<node xpath="//time-profile">
  <schema name="time-profile"/>
  <row>
    <weight fmt="{weight_ns / 1_000_000:.2f} ms">{weight_ns}</weight>
    <tagged-backtrace>
      <backtrace>
        <frame name="{symbol}" addr="0x1"/>
      </backtrace>
    </tagged-backtrace>
  </row>
</node>
</trace-query-result>"""


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
                "--time-limit",
                "10s",
                "--output",
                "/tmp/trace.trace",
                "--no-prompt",
                "--template",
                "Time Profiler",
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

    def test_parse_app_launch_classifies_phases_from_real_xml(self) -> None:
        xml = _launch_fixture()

        analysis = parse_app_launch(xml, "com.example.app")

        # 4 samples of 200ms each, but the mach_msg2_trap one is dropped as idle.
        self.assertEqual(analysis.total_launch_ms, 600)
        # 600ms total -> between launch_good_ms (400) and launch_critical_ms (1000).
        self.assertEqual(analysis.status, "warning")

        offenders = {offender.symbol: offender for offender in analysis.offenders}
        # Swift runtime symbol -> pre-main phase.
        self.assertEqual(offenders["swift_conformsToProtocol"].phase, "pre-main")
        # Cocoa method on the app -> post-main phase.
        self.assertEqual(offenders["-[AppDelegate didFinishLaunchingWithOptions:]"].phase, "post-main")
        # mach_msg2_trap leaf samples should be dropped entirely as idle wait.
        self.assertNotIn("mach_msg2_trap", offenders)

        phase_names = {phase.name for phase in analysis.phases}
        self.assertIn("pre-main (dyld + static init)", phase_names)
        self.assertIn("post-main (AppDelegate + UI)", phase_names)

    def test_parse_app_launch_accepts_custom_thresholds(self) -> None:
        xml = _launch_fixture()

        analysis = parse_app_launch(
            xml,
            "com.example.app",
            launch_good_ms=1000,
            launch_critical_ms=2000,
            offender_warning_ms=900,
            offender_critical_ms=1000,
        )

        self.assertEqual(analysis.status, "good")
        # 200ms self per offender is below the 900ms warning threshold -> ok.
        self.assertTrue(all(offender.severity == "ok" for offender in analysis.offenders))

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

    def test_parse_allocations_statistics_detail_from_real_xctrace_shape(self) -> None:
        xml = """<?xml version="1.0"?>
        <trace-query-result>
          <node xpath='//trace-toc[1]/run[1]/tracks[1]/track[1]/details[1]/detail[1]'>
            <row category="All Heap &amp; Anonymous VM" persistent-bytes="43207888"
                 count-persistent="189754" total-bytes="981356224" count-total="8867577"/>
            <row category="All Heap Allocations" persistent-bytes="32476368"
                 count-persistent="189648" total-bytes="917933760" count-total="8866677"/>
            <row category="All VM Regions" persistent-bytes="73875456"
                 count-persistent="134" total-bytes="160661504" count-total="1015"/>
            <row category="SWDestinyTrades.CardDTO" persistent-bytes="829440"
                 count-persistent="1853" total-bytes="2641920" count-total="2000"/>
            <row category="VM: ImageIO_AppleJPEG_Data" persistent-bytes="4194304"
                 count-persistent="8" total-bytes="13631488" count-total="12"/>
          </node>
        </trace-query-result>"""

        analysis = parse_allocations(xml)

        self.assertTrue(has_allocations_evidence(xml))
        self.assertEqual(analysis.live_memory_mb, 31.0)
        self.assertEqual(analysis.peak_memory_mb, 70.5)
        categories = {category.type: category for category in analysis.top_allocations}
        self.assertEqual(categories["SWDestinyTrades.CardDTO"].live_count, 1853)
        self.assertEqual(categories["VM: ImageIO_AppleJPEG_Data"].live_bytes, 4194304)
        self.assertTrue(any("ImageIO" in recommendation for recommendation in analysis.recommendations))

    def test_parse_leaks_direct_entries(self) -> None:
        xml = '<leak type="Closure" count="2" size="4096" root-cycle="true" />'

        analysis = parse_leaks(xml)

        self.assertEqual(analysis.total_leaks, 2)
        self.assertEqual(analysis.total_leaked_bytes, 4096)
        self.assertTrue(analysis.leaks[0].root_cycle)

    def test_parse_leaks_accepts_detail_row_attributes(self) -> None:
        xml = """<?xml version="1.0"?>
        <trace-query-result>
          <node xpath='//trace-toc[1]/run[1]/tracks[1]/track[1]/details[1]/detail[1]'>
            <row category="Closure" count="2" size="4096" root-cycle="true"/>
            <row leaked-object="ObservationRegistrar.Extent" count="1" size="32"/>
            <row leaked-object="ObservationRegistrar.Extent" count="1" size="32"/>
            <row responsible-library="UIKit" count-persistent="1" persistent-bytes="2048"/>
          </node>
        </trace-query-result>"""

        analysis = parse_leaks(xml)

        self.assertEqual(analysis.total_leaks, 5)
        self.assertEqual(analysis.total_leaked_bytes, 6208)
        self.assertTrue(analysis.leaks[0].root_cycle)
        registrar = next(leak for leak in analysis.leaks if leak.type == "ObservationRegistrar.Extent")
        self.assertEqual(registrar.count, 2)
        self.assertEqual(registrar.total_bytes, 64)

    def test_parse_time_profiler_from_real_xctrace_xml(self) -> None:
        xml = _time_profile_fixture()

        analysis = parse_time_profiler(xml)

        # 3 samples of 150ms each.
        self.assertEqual(analysis.total_duration_ms, 450)
        self.assertEqual(analysis.status, "critical")

        symbols = {method.symbol: method for method in analysis.hot_methods}
        # LeafFunc is the leaf in 2 samples -> 300ms self.
        self.assertIn("LeafFunc", symbols)
        self.assertEqual(symbols["LeafFunc"].self_time_ms, 300)
        self.assertEqual(symbols["LeafFunc"].total_time_ms, 300)
        self.assertEqual(symbols["LeafFunc"].severity, "critical")
        # OtherLeaf is the leaf in 1 sample -> 150ms self.
        self.assertIn("OtherLeaf", symbols)
        self.assertEqual(symbols["OtherLeaf"].self_time_ms, 150)
        self.assertEqual(symbols["OtherLeaf"].severity, "warning")
        # MidFunc / RootFunc only appear as non-leaf frames -> zero self time, filtered.
        self.assertNotIn("MidFunc", symbols)
        self.assertNotIn("RootFunc", symbols)

    def test_parse_time_profiler_accepts_custom_thresholds(self) -> None:
        xml = _time_profile_fixture()

        analysis = parse_time_profiler(
            xml,
            total_good_ms=500,
            total_critical_ms=1000,
            method_warning_ms=400,
            method_critical_ms=800,
        )

        self.assertEqual(analysis.status, "good")
        symbols = {method.symbol: method for method in analysis.hot_methods}
        # LeafFunc: 300ms self is below the new 400ms warning threshold -> ok.
        self.assertEqual(symbols["LeafFunc"].severity, "ok")

    def test_parse_time_profiler_resolves_xml_refs(self) -> None:
        # Same leaf frame reused by reference across two samples - both samples
        # should attribute self-time to the dereferenced symbol.
        xml = """<?xml version="1.0"?>
<trace-query-result>
<node xpath="//time-profile">
  <schema name="time-profile"/>
  <row>
    <weight id="W" fmt="50.00 ms">50000000</weight>
    <tagged-backtrace id="TB1">
      <backtrace id="B1">
        <frame id="SharedLeaf" name="SharedLeaf" addr="0x1"/>
      </backtrace>
    </tagged-backtrace>
  </row>
  <row>
    <weight ref="W"/>
    <tagged-backtrace id="TB2">
      <backtrace id="B2">
        <frame ref="SharedLeaf"/>
      </backtrace>
    </tagged-backtrace>
  </row>
</node>
</trace-query-result>"""

        analysis = parse_time_profiler(xml)

        self.assertEqual(analysis.total_duration_ms, 100)
        symbols = {method.symbol for method in analysis.hot_methods}
        self.assertIn("SharedLeaf", symbols)

    def test_parse_time_profiler_skips_deduplicated_symbol(self) -> None:
        xml = """<?xml version="1.0"?>
<trace-query-result>
<node xpath="//time-profile">
  <schema name="time-profile"/>
  <row>
    <weight fmt="100.00 ms">100000000</weight>
    <tagged-backtrace>
      <backtrace>
        <frame name="&lt;deduplicated_symbol&gt;" addr="0x1"/>
        <frame name="RealLeaf" addr="0x2"/>
        <frame name="RealRoot" addr="0x3"/>
      </backtrace>
    </tagged-backtrace>
  </row>
</node>
</trace-query-result>"""

        analysis = parse_time_profiler(xml)

        symbols = {method.symbol for method in analysis.hot_methods}
        # The deduplicated_symbol leaf is skipped; RealLeaf becomes the leaf and gets self.
        self.assertIn("RealLeaf", symbols)
        leaf_method = next(method for method in analysis.hot_methods if method.symbol == "RealLeaf")
        self.assertEqual(leaf_method.self_time_ms, 100)

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

    def test_parse_network_xctrace_task_intervals(self) -> None:
        xml = """<?xml version="1.0"?>
<trace-query-result>
<node xpath="//trace-toc[1]/run[1]/data[1]/table[24]">
  <schema name="com-apple-cfnetwork-task-intervals">
    <col><mnemonic>start</mnemonic></col>
    <col><mnemonic>duration</mnemonic></col>
    <col><mnemonic>process</mnemonic></col>
    <col><mnemonic>host</mnemonic></col>
    <col><mnemonic>server-ip</mnemonic></col>
    <col><mnemonic>session</mnemonic></col>
    <col><mnemonic>session-is-ephemeral</mnemonic></col>
    <col><mnemonic>layout-qualifier</mnemonic></col>
    <col><mnemonic>task-uuid</mnemonic></col>
    <col><mnemonic>public-task-identifier</mnemonic></col>
    <col><mnemonic>task-description</mnemonic></col>
    <col><mnemonic>resume-backtrace</mnemonic></col>
    <col><mnemonic>http-method</mnemonic></col>
    <col><mnemonic>url</mnemonic></col>
    <col><mnemonic>http-path</mnemonic></col>
    <col><mnemonic>query-string</mnemonic></col>
    <col><mnemonic>request-attribution</mnemonic></col>
    <col><mnemonic>successful</mnemonic></col>
  </schema>
  <row>
    <event-time fmt="00:00.000">0</event-time>
    <duration fmt="750.00 ms">750000000</duration>
    <process fmt="App">123</process>
    <domain-name fmt="example.com">example.com</domain-name>
    <string/>
    <string/>
    <boolean>0</boolean>
    <uint32>1</uint32>
    <uuid>task</uuid>
    <uint32>2</uint32>
    <string/>
    <text-backtrace/>
    <word-string fmt="POST">POST</word-string>
    <string fmt="https://example.com/api">https://example.com/api</string>
    <string/>
    <string/>
    <string/>
    <boolean>1</boolean>
  </row>
</node>
</trace-query-result>"""

        analysis = parse_network(xml)

        self.assertEqual(analysis.total_requests, 1)
        self.assertEqual(analysis.slow_requests[0].method, "POST")
        self.assertEqual(analysis.slow_requests[0].url, "https://example.com/api")
        self.assertEqual(analysis.slow_requests[0].duration_ms, 750)

    def test_parse_network_connection_rows_when_http_rows_are_absent(self) -> None:
        xml = """<?xml version="1.0"?>
<trace-query-result>
<node xpath="//trace-toc[1]/run[1]/data[1]/table[29]">
  <schema name="network-connection-detected">
    <col><mnemonic>time</mnemonic></col>
    <col><mnemonic>pid</mnemonic></col>
    <col><mnemonic>local-address</mnemonic></col>
    <col><mnemonic>remote-address</mnemonic></col>
    <col><mnemonic>interface-index</mnemonic></col>
    <col><mnemonic>recv-buffer-size</mnemonic></col>
    <col><mnemonic>recv-buffer-used</mnemonic></col>
    <col><mnemonic>serial-number</mnemonic></col>
    <col><mnemonic>kind</mnemonic></col>
  </schema>
  <row>
    <event-time id="T" fmt="00:00.000">0</event-time>
    <sentinel/>
    <sockaddr fmt="192.168.15.4:64652">1</sockaddr>
    <sockaddr id="R" fmt="162.159.153.238:443">2</sockaddr>
    <uint32>21</uint32>
    <size-in-bytes id="B" fmt="1.93 MiB">2027080</size-in-bytes>
    <size-in-bytes>0</size-in-bytes>
    <uint32>149050</uint32>
    <network-protocol id="P" fmt="tcp4">tcp4</network-protocol>
  </row>
  <row>
    <event-time ref="T"/>
    <sentinel/>
    <sockaddr fmt="192.168.15.4:64653">3</sockaddr>
    <sockaddr ref="R"/>
    <uint32>21</uint32>
    <size-in-bytes ref="B"/>
    <size-in-bytes>0</size-in-bytes>
    <uint32>149051</uint32>
    <network-protocol ref="P"/>
  </row>
</node>
</trace-query-result>"""

        analysis = parse_network(xml)

        self.assertEqual(analysis.total_requests, 1)
        self.assertEqual(analysis.total_transferred_mb, 3.87)
        self.assertEqual(analysis.slow_requests[0].method, "TCP4")
        self.assertEqual(analysis.slow_requests[0].url, "162.159.153.238:443")
        self.assertIn("socket-level", analysis.recommendations[0])

    def test_compare_launch_analyses_reports_delta(self) -> None:
        baseline = parse_app_launch(
            _time_profile_single_sample("LaunchSetup", weight_ns=500_000_000),
            "com.example.app",
        )
        candidate = parse_app_launch(
            _time_profile_single_sample("LaunchSetup", weight_ns=800_000_000),
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
        baseline = parse_time_profiler(_time_profile_single_sample("Work.run", weight_ns=120_000_000))
        candidate = parse_time_profiler(_time_profile_single_sample("Work.run", weight_ns=80_000_000))

        output = compare_time_profile_analyses(baseline, candidate, "com.example.app")

        self.assertIn("CPU Trace Comparison", output)
        self.assertIn("-40ms (improvement)", output)


def _enriched_time_profile_fixture() -> str:
    """Fixture mirroring xctrace's real export shape when start-time, thread,
    and binary attributes are present. Six 50ms samples laid out so the
    scope/hangs/user-frame tests have signal:

      t=  100ms  Main Thread      Work.run @ MyApp -> Root @ MyApp
      t=  500ms  Main Thread      Work.run @ MyApp -> Root @ MyApp
      t= 4000ms  Main Thread      Work.run @ MyApp -> Root @ MyApp   (3.5s gap → stall)
      t= 4050ms  Main Thread      Work.run @ MyApp -> Root @ MyApp
      t= 4100ms  com.acme.queue   bg_step  @ libsystem -> Root @ MyApp
      t= 4150ms  com.acme.queue   bg_step  @ libsystem -> Root @ MyApp
    """
    return """<?xml version="1.0"?>
<trace-query-result>
<node xpath="//time-profile">
  <schema name="time-profile"/>
  <row>
    <start-time id="T1">100000000</start-time>
    <weight id="W" fmt="50.00 ms">50000000</weight>
    <thread-state id="RUN" fmt="Running">Running</thread-state>
    <thread id="MAIN" name="Main Thread"/>
    <tagged-backtrace id="TB1">
      <backtrace id="B1">
        <frame id="WORK" name="Work.run" binary="MyApp" addr="0x100"/>
        <frame id="ROOT" name="Root" binary="MyApp" addr="0x300"/>
      </backtrace>
    </tagged-backtrace>
  </row>
  <row>
    <start-time id="T2">500000000</start-time>
    <weight ref="W"/>
    <thread-state ref="RUN"/>
    <thread ref="MAIN"/>
    <tagged-backtrace ref="TB1"/>
  </row>
  <row>
    <start-time id="T3">4000000000</start-time>
    <weight ref="W"/>
    <thread-state ref="RUN"/>
    <thread ref="MAIN"/>
    <tagged-backtrace ref="TB1"/>
  </row>
  <row>
    <start-time id="T4">4050000000</start-time>
    <weight ref="W"/>
    <thread-state ref="RUN"/>
    <thread ref="MAIN"/>
    <tagged-backtrace ref="TB1"/>
  </row>
  <row>
    <start-time id="T5">4100000000</start-time>
    <weight ref="W"/>
    <thread-state ref="RUN"/>
    <thread id="BG" name="com.acme.queue"/>
    <tagged-backtrace id="TB2">
      <backtrace id="B2">
        <frame id="BGSTEP" name="bg_step" binary="libsystem" addr="0x500"/>
        <frame ref="ROOT"/>
      </backtrace>
    </tagged-backtrace>
  </row>
  <row>
    <start-time id="T6">4150000000</start-time>
    <weight ref="W"/>
    <thread-state ref="RUN"/>
    <thread ref="BG"/>
    <tagged-backtrace ref="TB2"/>
  </row>
</node>
</trace-query-result>"""


class TimeProfileScopeAndHangsTests(unittest.TestCase):
    def test_scope_clips_samples_to_window(self) -> None:
        analysis = parse_time_profiler(
            _enriched_time_profile_fixture(),
            start_ms=4000,
            end_ms=4200,
        )

        self.assertIsNotNone(analysis.scope)
        assert analysis.scope is not None
        self.assertEqual(analysis.scope.start_ms, 4000)
        self.assertEqual(analysis.scope.end_ms, 4200)
        # 4 of the 6 samples are inside the [4000ms, 4200ms] window.
        self.assertEqual(analysis.scope.samples_in_scope, 4)
        # Total duration reflects only the scoped samples (4 × 50ms).
        self.assertEqual(analysis.total_duration_ms, 200)

    def test_scope_open_ended_extends_to_end(self) -> None:
        analysis = parse_time_profiler(
            _enriched_time_profile_fixture(),
            start_ms=4000,
            end_ms=None,
        )

        assert analysis.scope is not None
        self.assertEqual(analysis.scope.end_ms, 0)  # 0 = open-ended marker
        self.assertEqual(analysis.scope.samples_in_scope, 4)

    def test_main_thread_stats_detects_large_gap_as_candidate_stall(self) -> None:
        # Threshold 1000ms — only the 500ms→4000ms gap (~3500ms) qualifies as
        # a candidate stall; the 100ms→500ms (400ms) and 4000ms→4050ms (50ms)
        # gaps stay below it.
        analysis = parse_time_profiler(
            _enriched_time_profile_fixture(),
            hang_threshold_ms=1000,
        )

        assert analysis.main_thread is not None
        mt = analysis.main_thread
        self.assertEqual(mt.samples, 4)  # 4 main-thread samples
        self.assertGreaterEqual(mt.max_gap_ms, 3000)
        self.assertEqual(mt.candidate_stalls, 1)
        self.assertEqual(mt.gap_threshold_ms, 1000)

    def test_main_thread_stats_threshold_filters_smaller_gaps(self) -> None:
        analysis = parse_time_profiler(
            _enriched_time_profile_fixture(),
            hang_threshold_ms=5000,
        )

        assert analysis.main_thread is not None
        self.assertEqual(analysis.main_thread.candidate_stalls, 0)

    def test_user_methods_filter_by_binary(self) -> None:
        analysis = parse_time_profiler(
            _enriched_time_profile_fixture(),
            user_binaries=("MyApp",),
        )

        user_symbols = {m.symbol for m in analysis.user_methods}
        self.assertIn("Work.run", user_symbols)
        # bg_step's binary is libsystem — should not appear in user methods.
        self.assertNotIn("bg_step", user_symbols)
        # `is_user` is still flagged on the merged list too.
        my_app_methods = [m for m in analysis.hot_methods if m.binary == "MyApp"]
        self.assertTrue(all(m.is_user for m in my_app_methods))

    def test_format_surfaces_scope_main_thread_and_user_sections(self) -> None:
        analysis = parse_time_profiler(
            _enriched_time_profile_fixture(),
            start_ms=4000,
            end_ms=4200,
            user_binaries=("MyApp",),
        )

        output = format_time_profiler(analysis, "com.example.app")

        self.assertIn("**Scope:** 4000ms – 4200ms", output)
        self.assertIn("Main Thread", output)
        self.assertIn("Top User Methods", output)
        self.assertIn("Hot Methods", output)  # original section still present

    def test_legacy_fixture_without_new_columns_still_parses(self) -> None:
        # The pre-existing minimal fixture has no start-time/thread/binary,
        # but parse_time_profiler should still produce a usable report (no
        # scope, no main_thread, no user methods).
        analysis = parse_time_profiler(_time_profile_fixture())

        self.assertIsNone(analysis.scope)
        self.assertIsNone(analysis.main_thread)
        self.assertEqual(analysis.user_methods, [])
        self.assertGreater(analysis.total_duration_ms, 0)


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


    def test_timeout_message_for_simulator_includes_coresim_hints(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-123")

        output = format_target_error(
            target, "App Launch", "Command timed out: xcrun xctrace record ..."
        )

        self.assertIn("did not finish", output)
        self.assertIn("wedged simulator", output)
        self.assertIn("simctl shutdown SIM-123", output)
        self.assertIn("CoreSimulatorService", output)

    def test_timeout_message_for_non_simulator_target_suggests_time_limit(self) -> None:
        target = RecordingTarget.build(process_name="MyMacApp")

        output = format_target_error(target, "Time Profiler", "Command timed out: xcrun ...")

        self.assertIn("did not finish", output)
        self.assertIn("time_limit_seconds", output)

    def test_timeout_message_mentions_partial_trace_path(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-123")
        with tempfile.TemporaryDirectory() as tmp:
            trace_dir = Path(tmp) / "trace.trace"
            trace_dir.mkdir()
            (trace_dir / "fake.bin").write_bytes(b"abc")

            output = format_target_error(
                target,
                "App Launch",
                "Command timed out: ...",
                partial_trace=trace_dir,
            )

            self.assertIn(str(trace_dir), output)
            self.assertIn("Partial trace bundle preserved", output)


def _is_xctrace_probe(args: tuple[str, ...]) -> bool:
    return "xctrace" in args and "list" in args


def _is_simctl_list(args: tuple[str, ...]) -> bool:
    return "simctl" in args and "list" in args


class PreflightIosTargetTests(unittest.TestCase):
    def _patch_run(self, side_effect):
        return mock.patch.object(xctrace_module, "run_command", side_effect=side_effect)

    def test_returns_empty_when_device_not_in_simctl_list(self) -> None:
        async def fake(*args, **kwargs):  # noqa: ARG001
            if _is_xctrace_probe(args):
                return ""
            return json.dumps({"devices": {"runtime": [{"udid": "OTHER", "state": "Booted"}]}})

        with self._patch_run(fake):
            report = asyncio.run(preflight_ios_target("SIM-123", "com.example.app"))

        self.assertEqual(report.findings, [])
        self.assertIn("xctrace_list_devices", report.timings)
        self.assertIn("simctl_list_devices", report.timings)

    def test_blocks_when_simulator_not_booted(self) -> None:
        async def fake(*args, **kwargs):  # noqa: ARG001
            if _is_xctrace_probe(args):
                return ""
            return json.dumps({"devices": {"r": [{"udid": "SIM-123", "state": "Shutdown"}]}})

        with self._patch_run(fake):
            report = asyncio.run(preflight_ios_target("SIM-123", "com.example.app"))

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "blocker")
        self.assertIn("not Booted", report.findings[0].message)
        self.assertTrue(any("simctl boot SIM-123" in h for h in report.findings[0].hints))

    def test_passes_when_simulator_booted_and_app_installed(self) -> None:
        calls: list[tuple[str, ...]] = []

        async def fake(*args, **kwargs):  # noqa: ARG001
            calls.append(args)
            if _is_xctrace_probe(args):
                return ""
            if _is_simctl_list(args):
                return json.dumps({"devices": {"r": [{"udid": "SIM-123", "state": "Booted"}]}})
            return "/Users/.../App.app\n"

        with self._patch_run(fake):
            report = asyncio.run(preflight_ios_target("SIM-123", "com.example.app"))

        self.assertEqual(report.findings, [])
        self.assertEqual(len(calls), 3)
        self.assertTrue(_is_xctrace_probe(calls[0]))
        self.assertIn("get_app_container", calls[2])
        self.assertEqual(
            set(report.timings),
            {"xctrace_list_devices", "simctl_list_devices", "simctl_get_app_container"},
        )

    def test_blocks_when_app_not_installed(self) -> None:
        async def fake(*args, **kwargs):  # noqa: ARG001
            if _is_xctrace_probe(args):
                return ""
            if _is_simctl_list(args):
                return json.dumps({"devices": {"r": [{"udid": "SIM-123", "state": "Booted"}]}})
            raise RuntimeError("No such app com.example.app on device")

        with self._patch_run(fake):
            report = asyncio.run(preflight_ios_target("SIM-123", "com.example.app"))

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "blocker")
        self.assertIn("is not installed", report.findings[0].message)
        self.assertTrue(any("simctl listapps SIM-123" in h for h in report.findings[0].hints))

    def test_blocks_when_coresim_wedged_on_get_app_container(self) -> None:
        async def fake(*args, **kwargs):  # noqa: ARG001
            if _is_xctrace_probe(args):
                return ""
            if _is_simctl_list(args):
                return json.dumps({"devices": {"r": [{"udid": "SIM-123", "state": "Booted"}]}})
            raise RuntimeError("Command timed out: xcrun simctl get_app_container ...")

        with self._patch_run(fake):
            report = asyncio.run(preflight_ios_target("SIM-123", "com.example.app"))

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "blocker")
        self.assertIn("CoreSimulator did not respond", report.findings[0].message)
        self.assertTrue(any("killall -9 com.apple.CoreSimulator" in h for h in report.findings[0].hints))

    def test_blocks_when_simctl_list_itself_times_out(self) -> None:
        async def fake(*args, **kwargs):  # noqa: ARG001
            if _is_xctrace_probe(args):
                return ""
            raise RuntimeError("Command timed out: xcrun simctl list devices -j")

        with self._patch_run(fake):
            report = asyncio.run(preflight_ios_target("SIM-123", "com.example.app"))

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "blocker")
        self.assertIn("did not respond to `simctl list devices`", report.findings[0].message)

    def test_udid_lookup_is_case_insensitive(self) -> None:
        async def fake(*args, **kwargs):  # noqa: ARG001
            if _is_xctrace_probe(args):
                return ""
            if _is_simctl_list(args):
                return json.dumps({"devices": {"r": [{"udid": "AFF97D0A-AAAA", "state": "Shutdown"}]}})
            return ""

        with self._patch_run(fake):
            report = asyncio.run(preflight_ios_target("aff97d0a-aaaa", "com.example.app"))

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "blocker")

    def test_blocks_immediately_when_xctrace_probe_times_out(self) -> None:
        calls: list[tuple[str, ...]] = []

        async def fake(*args, **kwargs):  # noqa: ARG001
            calls.append(args)
            if _is_xctrace_probe(args):
                raise RuntimeError("Command timed out: xcrun xctrace list devices")
            raise AssertionError("simctl should not be called after xctrace probe blocker")

        with self._patch_run(fake):
            report = asyncio.run(preflight_ios_target("SIM-123", "com.example.app"))

        self.assertEqual(len(calls), 1)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "blocker")
        self.assertIn("xctrace list devices", report.findings[0].message)
        self.assertTrue(any("pkill -9 xctrace" in h for h in report.findings[0].hints))

    def test_format_preflight_findings_includes_hints(self) -> None:
        findings = [
            PreflightFinding(
                "blocker",
                "Simulator SIM-X is in state 'Shutdown', not Booted.",
                ("Boot first: `xcrun simctl boot SIM-X`",),
            )
        ]

        output = format_preflight_findings("App Launch", "com.example.app", findings)

        self.assertIn("App Launch", output)
        self.assertIn("com.example.app", output)
        self.assertIn("Simulator SIM-X", output)
        self.assertIn("Boot first", output)


class ProbeXctraceHealthTests(unittest.TestCase):
    def test_returns_none_when_xctrace_responds(self) -> None:
        async def fake(*args, **kwargs):  # noqa: ARG001
            return "== Devices ==\n"

        with mock.patch.object(xctrace_module, "run_command", side_effect=fake):
            finding = asyncio.run(probe_xctrace_health())

        self.assertIsNone(finding)

    def test_returns_blocker_when_xctrace_times_out(self) -> None:
        async def fake(*args, **kwargs):  # noqa: ARG001
            raise RuntimeError("Command timed out: xcrun xctrace list devices")

        with mock.patch.object(xctrace_module, "run_command", side_effect=fake):
            finding = asyncio.run(probe_xctrace_health())

        assert finding is not None
        self.assertEqual(finding.severity, "blocker")
        self.assertIn("xctrace list devices", finding.message)
        self.assertTrue(any("pkill -9 xctrace" in h for h in finding.hints))
        self.assertTrue(any("Instruments.app" in h for h in finding.hints))

    def test_returns_warning_on_non_timeout_failure(self) -> None:
        async def fake(*args, **kwargs):  # noqa: ARG001
            raise RuntimeError("xcrun: error: invalid active developer path")

        with mock.patch.object(xctrace_module, "run_command", side_effect=fake):
            finding = asyncio.run(probe_xctrace_health())

        assert finding is not None
        self.assertEqual(finding.severity, "warning")
        self.assertIn("invalid active developer path", finding.message)


class StaleXctraceProcessCleanupTests(unittest.TestCase):
    def test_find_stale_pids_returns_empty_when_pgrep_finds_none(self) -> None:
        async def fake_quiet(*args, **kwargs):  # noqa: ARG001
            return 1, ""  # pgrep exit 1 = no matches

        with mock.patch.object(xctrace_module, "_quiet_run", side_effect=fake_quiet):
            pids = asyncio.run(find_stale_xctrace_pids())

        self.assertEqual(pids, [])

    def test_find_stale_pids_parses_pgrep_output(self) -> None:
        async def fake_quiet(*args, **kwargs):  # noqa: ARG001
            return 0, "1234\n5678\n"

        with mock.patch.object(xctrace_module, "_quiet_run", side_effect=fake_quiet):
            pids = asyncio.run(find_stale_xctrace_pids())

        self.assertEqual(pids, [1234, 5678])

    def test_find_stale_pids_ignores_unexpected_exit_codes(self) -> None:
        async def fake_quiet(*args, **kwargs):  # noqa: ARG001
            return -1, ""  # timeout sentinel

        with mock.patch.object(xctrace_module, "_quiet_run", side_effect=fake_quiet):
            pids = asyncio.run(find_stale_xctrace_pids())

        self.assertEqual(pids, [])

    def test_kill_stale_returns_zero_when_none_found(self) -> None:
        calls: list[tuple[str, ...]] = []

        async def fake_quiet(*args, **kwargs):  # noqa: ARG001
            calls.append(args)
            return 1, ""  # pgrep finds nothing

        with mock.patch.object(xctrace_module, "_quiet_run", side_effect=fake_quiet):
            killed = asyncio.run(kill_stale_xctrace_processes())

        self.assertEqual(killed, 0)
        self.assertEqual(len(calls), 1)  # pgrep only, no kill issued
        self.assertEqual(calls[0][0], "pgrep")

    def test_kill_stale_invokes_kill_dash_9_for_found_pids(self) -> None:
        calls: list[tuple[str, ...]] = []

        async def fake_quiet(*args, **kwargs):  # noqa: ARG001
            calls.append(args)
            if args[0] == "pgrep":
                return 0, "111\n222\n"
            return 0, ""

        with mock.patch.object(xctrace_module, "_quiet_run", side_effect=fake_quiet):
            killed = asyncio.run(kill_stale_xctrace_processes())

        self.assertEqual(killed, 2)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], ("kill", "-9", "111", "222"))


def _seed_finalized_trace(trace_path: Path) -> None:
    """Build a fake `.trace` bundle that looks finalized to `_trace_bundle_finalized`."""
    run_dir = trace_path / "Trace1.run"
    run_dir.mkdir(parents=True)
    (run_dir / "RunIssues.storedata").write_bytes(b"")
    (run_dir / "core.perfdata").write_bytes(b"x" * 128)


def _seed_wedged_trace(trace_path: Path) -> None:
    """Build a `.trace` bundle in the shape xctrace leaves behind on a wedge:
    only Trace1.run/RunIssues.storedata, no payload."""
    run_dir = trace_path / "Trace1.run"
    run_dir.mkdir(parents=True)
    (run_dir / "RunIssues.storedata").write_bytes(b"")


class TraceBundleFinalizedTests(unittest.TestCase):
    def test_missing_path_is_not_finalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(_trace_bundle_finalized(Path(tmp) / "missing.trace"))

    def test_bundle_with_only_run_issues_is_not_finalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "wedged.trace"
            _seed_wedged_trace(trace)
            self.assertFalse(_trace_bundle_finalized(trace))

    def test_bundle_with_payload_is_finalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "ok.trace"
            _seed_finalized_trace(trace)
            self.assertTrue(_trace_bundle_finalized(trace))

    def test_bundle_without_any_run_dir_is_not_finalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "empty.trace"
            trace.mkdir()
            self.assertFalse(_trace_bundle_finalized(trace))


class RecordTraceCleanupTests(unittest.TestCase):
    def test_record_trace_sweeps_before_and_after_on_failure(self) -> None:
        sweep_calls: list[str] = []
        record_called = False

        async def fake_kill():
            sweep_calls.append("sweep")
            return 0

        async def fake_record(*args, **kwargs):  # noqa: ARG001
            nonlocal record_called
            record_called = True
            raise RuntimeError("xctrace started recording but did not finish within 10s + 15s grace.")

        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-123")

        with (
            mock.patch.object(xctrace_module, "kill_stale_xctrace_processes", side_effect=fake_kill),
            mock.patch.object(xctrace_module, "_run_record_with_watchdog", side_effect=fake_record),
            tempfile.TemporaryDirectory() as tmp,
            self.assertRaises(RuntimeError),
        ):
            asyncio.run(xctrace_module.record_trace("App Launch", target, 10, Path(tmp) / "t.trace"))

        self.assertTrue(record_called)
        self.assertEqual(sweep_calls, ["sweep", "sweep"])

    def test_record_trace_swallows_nonzero_exit_when_bundle_is_finalized(self) -> None:
        sweep_calls: list[str] = []

        async def fake_kill():
            sweep_calls.append("sweep")
            return 0

        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-123")

        with (
            mock.patch.object(xctrace_module, "kill_stale_xctrace_processes", side_effect=fake_kill),
            tempfile.TemporaryDirectory() as tmp,
        ):
            trace_path = Path(tmp) / "t.trace"
            _seed_finalized_trace(trace_path)

            async def fake_record(*args, **kwargs):  # noqa: ARG001
                # xctrace exited non-zero (e.g. the launched target was killed
                # by --time-limit and returned its own exit status), but the
                # bundle on disk is fine.
                raise RuntimeError("xctrace exited with status 54")

            with mock.patch.object(
                xctrace_module, "_run_record_with_watchdog", side_effect=fake_record
            ):
                asyncio.run(xctrace_module.record_trace("App Launch", target, 10, trace_path))

        self.assertEqual(sweep_calls, ["sweep"])  # no post-failure sweep — treated as success

    def test_record_trace_propagates_wedge_even_if_bundle_exists(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-123")

        async def fake_kill():
            return 0

        async def fake_record(*args, **kwargs):  # noqa: ARG001
            raise RuntimeError(
                "xctrace started recording but did not finish within 5s + 60s grace."
            )

        with (
            mock.patch.object(xctrace_module, "kill_stale_xctrace_processes", side_effect=fake_kill),
            mock.patch.object(xctrace_module, "_run_record_with_watchdog", side_effect=fake_record),
            tempfile.TemporaryDirectory() as tmp,
        ):
            trace_path = Path(tmp) / "t.trace"
            # Even with a "finalized-looking" bundle, a wedge error must still
            # propagate — the bundle from a wedged sim isn't trustworthy.
            _seed_finalized_trace(trace_path)
            with self.assertRaises(RuntimeError):
                asyncio.run(xctrace_module.record_trace("App Launch", target, 5, trace_path))

    def test_record_trace_sweeps_only_before_on_success(self) -> None:
        sweep_calls: list[str] = []

        async def fake_kill():
            sweep_calls.append("sweep")
            return 0

        async def fake_record(*args, **kwargs):  # noqa: ARG001
            return None

        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-123")

        with (
            mock.patch.object(xctrace_module, "kill_stale_xctrace_processes", side_effect=fake_kill),
            mock.patch.object(xctrace_module, "_run_record_with_watchdog", side_effect=fake_record),
            tempfile.TemporaryDirectory() as tmp,
        ):
            asyncio.run(xctrace_module.record_trace("App Launch", target, 10, Path(tmp) / "t.trace"))

        self.assertEqual(sweep_calls, ["sweep"])


class _FakeStream:
    def __init__(self, script: list[tuple[float, bytes]]) -> None:
        # script: list of (delay_seconds, line_bytes). An empty bytes ends the stream.
        self._script = list(script)

    async def readline(self) -> bytes:
        if not self._script:
            await asyncio.sleep(60)  # block; tests should never get here
            return b""
        delay, line = self._script.pop(0)
        if delay > 0:
            await asyncio.sleep(delay)
        return line


class _FakeProcess:
    def __init__(self, script: list[tuple[float, bytes]], returncode: int = 0) -> None:
        self.stdout = _FakeStream(script)
        self.returncode: int | None = None
        self._wait_event = asyncio.Event()
        self._final_returncode = returncode
        self.kill_called = False

    def kill(self) -> None:
        self.kill_called = True
        self.returncode = -9
        self._wait_event.set()

    async def wait(self) -> int:
        if self.returncode is None:
            # The reader is what drives the lifecycle; once EOF is reached, mark exit.
            # In tests we set returncode either via kill() or by letting the watchdog finish.
            await self._wait_event.wait()
        return self.returncode if self.returncode is not None else self._final_returncode

    def finish_naturally(self) -> None:
        self.returncode = self._final_returncode
        self._wait_event.set()


def _as_process(fake: _FakeProcess) -> asyncio.subprocess.Process:
    return cast(asyncio.subprocess.Process, fake)


class WatchdogLoopTests(unittest.TestCase):
    def test_happy_path_completes_when_process_exits_cleanly(self) -> None:
        process = _FakeProcess(
            [
                (0.0, b"Starting recording with Time Profiler.\n"),
                (0.05, b"Time limit: 1.0 s\n"),
                (0.1, b"Recording finished.\n"),
                (0.0, b""),
            ]
        )

        async def driver() -> None:
            task = asyncio.create_task(
                _watchdog_loop(
                    _as_process(process),
                    time_limit_seconds=1,
                    startup_timeout=2.0,
                    teardown_grace=2.0,
                    poll_interval=0.05,
                )
            )
            await asyncio.sleep(0.4)
            if not task.done():
                process.finish_naturally()
            await task

        asyncio.run(driver())
        self.assertFalse(process.kill_called)

    def test_kills_when_starting_recording_never_appears(self) -> None:
        process = _FakeProcess(
            [
                (0.0, b"some unrelated noise\n"),
                # never prints "Starting recording" and never EOFs
            ]
        )

        async def driver() -> None:
            with self.assertRaises(RuntimeError) as ctx:
                await _watchdog_loop(
                    _as_process(process),
                    time_limit_seconds=1,
                    startup_timeout=0.3,
                    teardown_grace=10.0,
                    poll_interval=0.05,
                )
            self.assertIn("did not begin recording", str(ctx.exception))

        asyncio.run(driver())
        self.assertTrue(process.kill_called)

    def test_kills_when_recording_started_but_never_finishes(self) -> None:
        process = _FakeProcess(
            [
                (0.0, b"Starting recording with Time Profiler.\n"),
                (0.05, b"Time limit: 1.0 s\n"),
                # never prints "Recording finished" and never EOFs
            ]
        )

        async def driver() -> None:
            with self.assertRaises(RuntimeError) as ctx:
                await _watchdog_loop(
                    _as_process(process),
                    time_limit_seconds=1,
                    startup_timeout=10.0,
                    teardown_grace=0.3,
                    poll_interval=0.05,
                )
            self.assertIn("started recording but did not finish", str(ctx.exception))
            self.assertIn("Time limit: 1.0 s", str(ctx.exception))

        asyncio.run(driver())
        self.assertTrue(process.kill_called)

    def test_propagates_nonzero_exit_with_captured_output(self) -> None:
        process = _FakeProcess(
            [
                (0.0, b"Starting recording.\n"),
                (0.05, b"xctrace: error: template not found\n"),
                (0.0, b""),
            ],
            returncode=1,
        )

        async def driver() -> None:
            task = asyncio.create_task(
                _watchdog_loop(
                    _as_process(process),
                    time_limit_seconds=1,
                    startup_timeout=2.0,
                    teardown_grace=2.0,
                    poll_interval=0.05,
                )
            )
            await asyncio.sleep(0.3)
            process.finish_naturally()
            with self.assertRaises(RuntimeError) as ctx:
                await task
            self.assertIn("template not found", str(ctx.exception))

        asyncio.run(driver())


class FormatTargetErrorRecordingWedgeTests(unittest.TestCase):
    def test_started_but_unfinished_calls_out_runtime_wedge(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-123")

        output = format_target_error(
            target,
            "App Launch",
            "xctrace started recording but did not finish within 5s + 15s grace. Last output: Time limit: 5.0 s",
        )

        self.assertIn("announced `Starting recording`", output)
        self.assertIn("per-instrument tap", output)
        self.assertIn("DTServiceHub/dtsecurity", output)
        self.assertIn("runtime wedge", output)
        self.assertIn("simctl shutdown SIM-123", output)

    def test_never_started_message_suggests_pkill_xctrace(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-123")

        output = format_target_error(
            target,
            "App Launch",
            "xctrace did not begin recording within 15s (never reported `Starting recording`).",
        )

        self.assertIn("never reported `Starting recording`", output)
        self.assertIn("pkill -9 xctrace", output)
        self.assertIn("simctl shutdown SIM-123", output)

    def test_preflight_timings_are_rendered_when_provided(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-123")

        output = format_target_error(
            target,
            "App Launch",
            "xctrace started recording but did not finish within 5s + 15s grace.",
            preflight_timings={
                "xctrace_list_devices": 1.412,
                "simctl_list_devices": 0.081,
                "simctl_get_app_container": 0.103,
            },
        )

        self.assertIn("Pre-flight probes", output)
        self.assertIn("xctrace_list_devices", output)
        self.assertIn("1412 ms", output)
        self.assertIn("simctl_get_app_container", output)
        self.assertIn("103 ms", output)


class CountXctraceListingItemsTests(unittest.TestCase):
    def test_counts_data_lines_only(self) -> None:
        from apple_instruments_mcp.analysis.xctrace import count_xctrace_listing_items

        output = """== Devices ==
Diogo's iPhone (17.5) (DEAD-BEEF)
iPhone 17 (CEC2F29A)

== Devices Offline ==
Old iPad
"""
        self.assertEqual(count_xctrace_listing_items(output), 3)

    def test_skips_colon_section_headers(self) -> None:
        from apple_instruments_mcp.analysis.xctrace import count_xctrace_listing_items

        output = "Standard Templates:\nApp Launch\nTime Profiler\n\nCustom Templates:\n"
        self.assertEqual(count_xctrace_listing_items(output), 2)

    def test_empty_output_is_zero(self) -> None:
        from apple_instruments_mcp.analysis.xctrace import count_xctrace_listing_items

        self.assertEqual(count_xctrace_listing_items(""), 0)


class DoctorToolTests(unittest.TestCase):
    """Drive `server.doctor` with patched xctrace surface to verify reporting."""

    def _run_doctor(
        self,
        *,
        run_command_side_effect,
        probe_finding,
        list_devices_output: str = "== Devices ==\nA\nB\n",
        list_templates_output: str = "== Templates ==\nTime Profiler\n",
        list_instruments_output: str = "== Instruments ==\nCPU Profiler\nAllocations\n",
        list_devices_error: Exception | None = None,
        list_templates_error: Exception | None = None,
        list_instruments_error: Exception | None = None,
    ) -> str:
        from apple_instruments_mcp import server

        async def fake_devices():
            if list_devices_error is not None:
                raise list_devices_error
            return list_devices_output

        async def fake_templates():
            if list_templates_error is not None:
                raise list_templates_error
            return list_templates_output

        async def fake_instruments():
            if list_instruments_error is not None:
                raise list_instruments_error
            return list_instruments_output

        async def fake_probe():
            return probe_finding

        with (
            mock.patch.object(server, "run_command", side_effect=run_command_side_effect),
            mock.patch.object(server, "probe_xctrace_health", side_effect=fake_probe),
            mock.patch.object(server, "xctrace_list_devices", side_effect=fake_devices),
            mock.patch.object(server, "xctrace_list_templates", side_effect=fake_templates),
            mock.patch.object(server, "xctrace_list_instruments", side_effect=fake_instruments),
        ):
            return asyncio.run(server.doctor_report())

    def test_healthy_report_includes_version_path_and_counts(self) -> None:
        async def fake_run(*args, **kwargs):  # noqa: ARG001
            if "--find" in args:
                return "/Applications/Xcode.app/Contents/Developer/usr/bin/xctrace\n"
            return "xctrace version 14.0\nIncludes …\n"

        output = self._run_doctor(run_command_side_effect=fake_run, probe_finding=None)

        self.assertIn("✅ ok", output)
        self.assertIn("xctrace_version", output)
        self.assertIn("xctrace version 14.0", output)
        self.assertIn("/Applications/Xcode.app", output)
        self.assertIn("- **devices**: 2", output)
        self.assertIn("- **templates**: 1", output)
        self.assertIn("- **instruments**: 2", output)
        self.assertNotIn("## Problems", output)

    def test_blocker_probe_surfaces_as_problem_and_skips_listings(self) -> None:
        async def fake_run(*args, **kwargs):  # noqa: ARG001
            if "--find" in args:
                return "/usr/bin/xctrace\n"
            return "xctrace version 14.0\n"

        listings_called = {"devices": 0, "templates": 0, "instruments": 0}

        async def counting_devices():
            listings_called["devices"] += 1
            return "== Devices ==\nA\n"

        async def counting_templates():
            listings_called["templates"] += 1
            return "== Templates ==\nT\n"

        async def counting_instruments():
            listings_called["instruments"] += 1
            return "== Instruments ==\nI\n"

        from apple_instruments_mcp import server
        from apple_instruments_mcp.analysis.xctrace import PreflightFinding

        async def fake_probe():
            return PreflightFinding(
                "blocker",
                "`xctrace list devices` did not respond within 5s.",
                ("Try: `pkill -9 xctrace` then retry.",),
            )

        with (
            mock.patch.object(server, "run_command", side_effect=fake_run),
            mock.patch.object(server, "probe_xctrace_health", side_effect=fake_probe),
            mock.patch.object(server, "xctrace_list_devices", side_effect=counting_devices),
            mock.patch.object(server, "xctrace_list_templates", side_effect=counting_templates),
            mock.patch.object(server, "xctrace_list_instruments", side_effect=counting_instruments),
        ):
            output = asyncio.run(server.doctor_report())

        self.assertIn("🔴 problems", output)
        self.assertIn("[blocker]", output)
        self.assertIn("did not respond", output)
        self.assertIn("pkill -9 xctrace", output)
        # A blocker probe is a hard stop — listings must not be queried.
        self.assertEqual(listings_called, {"devices": 0, "templates": 0, "instruments": 0})

    def test_partial_failure_still_reports_what_worked(self) -> None:
        async def fake_run(*args, **kwargs):  # noqa: ARG001
            if "--find" in args:
                return "/usr/bin/xctrace\n"
            return "xctrace version 14.0\n"

        output = self._run_doctor(
            run_command_side_effect=fake_run,
            probe_finding=None,
            list_instruments_error=RuntimeError("xctrace list instruments crashed"),
        )

        self.assertIn("🔴 problems", output)  # the instruments failure
        self.assertIn("- **devices**: 2", output)  # devices still counted
        self.assertIn("- **templates**: 1", output)  # templates still counted
        self.assertIn("`xctrace list instruments` failed", output)


class PresetsRegistryTests(unittest.TestCase):
    def test_preset_names_are_stable(self) -> None:
        from apple_instruments_mcp.analysis.presets import preset_names

        self.assertEqual(preset_names(), ["cpu", "memory", "network", "full"])

    def test_preset_instruments_for_cpu(self) -> None:
        from apple_instruments_mcp.analysis.presets import preset_instruments

        self.assertEqual(preset_instruments("cpu"), ["Time Profiler"])

    def test_preset_instruments_for_memory_lists_both(self) -> None:
        from apple_instruments_mcp.analysis.presets import preset_instruments

        self.assertEqual(preset_instruments("memory"), ["Allocations", "Leaks"])

    def test_preset_instruments_for_full_dedupes(self) -> None:
        from apple_instruments_mcp.analysis.presets import preset_instruments

        # `full` lists cpu, allocations, leaks, network; no instrument is shared
        # between them, but the de-dup path is exercised here.
        result = preset_instruments("full")
        self.assertEqual(len(result), len(set(result)))
        self.assertIn("Time Profiler", result)
        self.assertIn("Allocations", result)
        self.assertIn("Leaks", result)
        self.assertIn("Network Connections", result)

    def test_unknown_preset_raises(self) -> None:
        from apple_instruments_mcp.analysis.presets import preset_families

        with self.assertRaises(ValueError) as ctx:
            preset_families("ultraviolet")
        self.assertIn("unknown preset", str(ctx.exception))
        self.assertIn("cpu", str(ctx.exception))


class BuilderInstrumentsTests(unittest.TestCase):
    def test_builder_emits_repeated_instrument_flags(self) -> None:
        target = RecordingTarget.build(bundle_id="com.example.app", device_id="SIM-1")
        argv = build_record_command(
            None,
            target,
            5,
            Path("/tmp/x.trace"),
            instruments=("Time Profiler", "Allocations"),
        )

        self.assertNotIn("--template", argv)
        # Order preserved, each value follows its --instrument
        idxs = [i for i, a in enumerate(argv) if a == "--instrument"]
        self.assertEqual(len(idxs), 2)
        self.assertEqual(argv[idxs[0] + 1], "Time Profiler")
        self.assertEqual(argv[idxs[1] + 1], "Allocations")
        # The launch target is still last (--launch -- bundle.id)
        self.assertEqual(argv[-3:], ["--launch", "--", "com.example.app"])

    def test_builder_rejects_both_template_and_instruments(self) -> None:
        target = RecordingTarget.build(process_name="App")
        with self.assertRaises(ValueError):
            build_record_command(
                "Time Profiler",
                target,
                5,
                Path("/tmp/x.trace"),
                instruments=("Allocations",),
            )

    def test_builder_rejects_neither_template_nor_instruments(self) -> None:
        target = RecordingTarget.build(process_name="App")
        with self.assertRaises(ValueError):
            build_record_command(None, target, 5, Path("/tmp/x.trace"))


class RunPresetAnalysisTests(unittest.TestCase):
    """Mock record + export to verify run_preset_analysis composes a
    multi-section report from the trace bundle's families."""

    def _run_with_mocks(
        self,
        *,
        preset: str,
        export_xml_payloads: dict[str, str],
        record_side_effect=None,
        keep_trace: bool = False,
    ):
        from apple_instruments_mcp.analysis import orchestrator as orch_module

        recorded: dict[str, object] = {"instruments": None, "template": None}

        async def fake_record(template, target, time_limit_seconds, output_path, *, instruments=()):  # noqa: ARG001
            recorded["template"] = template
            recorded["instruments"] = list(instruments)
            # Simulate that xctrace wrote a trace bundle.
            output_path.mkdir(parents=True, exist_ok=True)
            run_dir = output_path / "Trace1.run"
            run_dir.mkdir()
            (run_dir / "core.perfdata").write_bytes(b"x")
            if record_side_effect is not None:
                await record_side_effect()

        async def fake_export(trace_path, output_xml_path, *, xpath=None, toc=False):  # noqa: ARG001
            assert xpath is not None
            payload = export_xml_payloads.get(xpath, "")
            output_xml_path.write_text(payload, encoding="utf-8")

        target = RecordingTarget.build(process_name="MyApp")
        with (
            mock.patch.object(orch_module, "record_trace", side_effect=fake_record),
            mock.patch.object(orch_module, "export_xml", side_effect=fake_export),
        ):
            output = asyncio.run(
                orch_module.run_preset_analysis(
                    preset, target, 5, keep_trace=keep_trace
                )
            )
        return output, recorded

    def test_dry_run_lists_instruments_without_recording(self) -> None:
        from apple_instruments_mcp.analysis.orchestrator import run_preset_analysis

        target = RecordingTarget.build(process_name="MyApp")
        output = asyncio.run(
            run_preset_analysis("memory", target, 5, dry_run=True)
        )
        self.assertIn("xctrace Dry Run", output)
        self.assertIn("memory", output)
        self.assertIn("--instrument", output)
        self.assertIn("Allocations", output)
        self.assertIn("Leaks", output)

    def test_records_with_preset_instruments_and_renders_present_families(self) -> None:
        from apple_instruments_mcp.analysis.presets import FAMILY_ALLOCATIONS, FAMILY_LEAKS

        # Allocations has evidence; Leaks has none (empty XML).
        export_payloads = {
            FAMILY_ALLOCATIONS.xpath: _allocations_evidence_xml(),
            FAMILY_LEAKS.xpath: "",
        }
        output, recorded = self._run_with_mocks(
            preset="memory", export_xml_payloads=export_payloads
        )

        self.assertEqual(recorded["template"], None)
        self.assertEqual(recorded["instruments"], ["Allocations", "Leaks"])
        self.assertIn("## Allocations", output)
        self.assertNotIn("## Leaks\n\n#", output)  # no Leaks body section
        # The missing family is summarized in the Notes section.
        self.assertIn("Leaks", output)
        self.assertIn("Notes", output)
        self.assertIn("workload may not have exercised it", output)

    def test_export_failure_in_one_family_does_not_nuke_the_rest(self) -> None:
        from apple_instruments_mcp.analysis import orchestrator as orch_module
        from apple_instruments_mcp.analysis.presets import FAMILY_LEAKS

        target = RecordingTarget.build(process_name="MyApp")

        async def fake_record(template, target, time_limit_seconds, output_path, *, instruments=()):  # noqa: ARG001
            output_path.mkdir(parents=True, exist_ok=True)
            run_dir = output_path / "Trace1.run"
            run_dir.mkdir()
            (run_dir / "core.perfdata").write_bytes(b"x")

        async def fake_export(trace_path, output_xml_path, *, xpath=None, toc=False):  # noqa: ARG001
            if xpath == FAMILY_LEAKS.xpath:
                raise RuntimeError("export blew up for Leaks")
            output_xml_path.write_text(_allocations_evidence_xml(), encoding="utf-8")

        with (
            mock.patch.object(orch_module, "record_trace", side_effect=fake_record),
            mock.patch.object(orch_module, "export_xml", side_effect=fake_export),
        ):
            output = asyncio.run(
                orch_module.run_preset_analysis("memory", target, 5)
            )

        self.assertIn("## Allocations", output)
        self.assertIn("## Leaks", output)
        self.assertIn("xctrace export failed: export blew up for Leaks", output)


def _allocations_evidence_xml() -> str:
    # `has_allocations_evidence` keys on either a <live-bytes>/<total-bytes>/<peak*>
    # element or a row carrying `persistent-bytes|total-bytes|category` as attributes.
    return """<?xml version="1.0"?>
<trace-query-result>
  <node>
    <schema name="allocation-statistics"/>
    <row>
      <category>String</category>
      <total-bytes fmt="1.2 KB">1200</total-bytes>
      <live-bytes fmt="500 B">500</live-bytes>
      <count-allocated>10</count-allocated>
      <count-live>3</count-live>
    </row>
  </node>
</trace-query-result>"""


class SymbolicateIsUnsymbolicatedTests(unittest.TestCase):
    def test_hex_address_detected(self) -> None:
        from apple_instruments_mcp.analysis.symbolicate import is_unsymbolicated

        self.assertTrue(is_unsymbolicated("0x100001a2b4"))
        self.assertTrue(is_unsymbolicated("0xDEADBEEF"))

    def test_real_symbol_is_not_flagged(self) -> None:
        from apple_instruments_mcp.analysis.symbolicate import is_unsymbolicated

        self.assertFalse(is_unsymbolicated("MyApp.run()"))
        self.assertFalse(is_unsymbolicated("-[NSString length]"))
        self.assertFalse(is_unsymbolicated(""))
        self.assertFalse(is_unsymbolicated("0xnotanaddress"))


class SymbolicateAtosParsingTests(unittest.TestCase):
    def test_parse_atos_line_strips_in_image_suffix(self) -> None:
        from apple_instruments_mcp.analysis.symbolicate import _parse_atos_line

        line = "MyApp.run() (in MyApp) (MyApp.swift:42)"
        self.assertEqual(_parse_atos_line(line), "MyApp.run()")

    def test_parse_atos_line_keeps_raw_address_when_unresolved(self) -> None:
        from apple_instruments_mcp.analysis.symbolicate import _parse_atos_line

        self.assertEqual(_parse_atos_line("0x100001a2b4"), "0x100001a2b4")


class SymbolicateAtosResolveTests(unittest.TestCase):
    def test_returns_addr_to_name_map_when_lines_align(self) -> None:
        from apple_instruments_mcp.analysis.symbolicate import atos_resolve

        async def fake_run(*args, timeout):  # noqa: ARG001
            return 0, "Func.one() (in MyApp) (a.swift:1)\nFunc.two() (in MyApp) (b.swift:2)\n"

        with mock.patch(
            "apple_instruments_mcp.analysis.symbolicate._run_capturing", side_effect=fake_run
        ):
            result = asyncio.run(
                atos_resolve(Path("/d"), "arm64", "0x100000000", ["0x10001", "0x10002"])
            )
        self.assertEqual(result, {"0x10001": "Func.one()", "0x10002": "Func.two()"})

    def test_drops_batch_when_line_count_mismatches(self) -> None:
        from apple_instruments_mcp.analysis.symbolicate import atos_resolve

        # Two input addresses but atos returned only one line — could be a
        # crash mid-batch. Returning a partial map would risk mis-attribution.
        async def fake_run(*args, timeout):  # noqa: ARG001
            return 0, "OnlyOneLine\n"

        with mock.patch(
            "apple_instruments_mcp.analysis.symbolicate._run_capturing", side_effect=fake_run
        ):
            result = asyncio.run(
                atos_resolve(Path("/d"), "", "", ["0x1", "0x2"])
            )
        self.assertEqual(result, {})

    def test_drops_batch_when_atos_exits_nonzero(self) -> None:
        from apple_instruments_mcp.analysis.symbolicate import atos_resolve

        async def fake_run(*args, timeout):  # noqa: ARG001
            return 1, "atos: error: invalid binary\n"

        with mock.patch(
            "apple_instruments_mcp.analysis.symbolicate._run_capturing", side_effect=fake_run
        ):
            result = asyncio.run(
                atos_resolve(Path("/d"), "", "", ["0x1"])
            )
        self.assertEqual(result, {})


class SymbolizeSamplesEndToEndTests(unittest.TestCase):
    def _samples(self) -> list:
        from apple_instruments_mcp.analysis.models import SampleFrame, TimeProfileSample

        # Two samples: one with a raw-address leaf in MyApp, another with the
        # same raw leaf, and a third where the leaf is already symbolicated
        # (should be left untouched).
        f1 = SampleFrame(
            symbol="0x100001a2b4",
            binary="MyApp",
            addr="0x100001a2b4",
            binary_uuid="UUID-1",
            binary_load_addr="0x100000000",
            arch="arm64",
        )
        f_named = SampleFrame(symbol="namedFunc", binary="MyApp")
        return [
            TimeProfileSample(weight_ns=1_000_000, frames=(f1, f_named)),
            TimeProfileSample(weight_ns=1_000_000, frames=(f1,)),
        ]

    def test_resolves_raw_addresses_into_symbol_names(self) -> None:
        import apple_instruments_mcp.analysis.symbolicate as sym_module
        from apple_instruments_mcp.analysis.symbolicate import symbolize_samples

        async def fake_run(args0, *rest, timeout):  # noqa: ARG001
            if args0 == "xcrun":
                # dwarfdump probe — confirm the UUID
                return 0, "UUID: UUID-1 (arm64) /path/to/MyApp\n"
            # atos: one line per input address
            return 0, "Real.symbol() (in MyApp) (foo.swift:7)\n"

        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(sym_module, "_run_capturing", side_effect=fake_run),
        ):
            dsym = Path(tmp) / "MyApp.dSYM"
            inner = dsym / "Contents" / "Resources" / "DWARF"
            inner.mkdir(parents=True)
            (inner / "MyApp").write_bytes(b"")

            new_samples, summary = asyncio.run(
                symbolize_samples(self._samples(), str(dsym))
            )

        self.assertEqual(summary.resolved, 2)  # the same raw leaf in 2 samples
        self.assertEqual(summary.unresolved, 0)
        self.assertEqual(summary.images_with_dsym, 1)
        # The named frame is unchanged; the raw addr is replaced.
        leaf_symbols = {s.frames[0].symbol for s in new_samples}
        self.assertEqual(leaf_symbols, {"Real.symbol()"})

    def test_missing_dsym_path_returns_note_and_no_changes(self) -> None:
        from apple_instruments_mcp.analysis.symbolicate import symbolize_samples

        new_samples, summary = asyncio.run(
            symbolize_samples(self._samples(), "/nonexistent/path.dSYM")
        )

        self.assertEqual(summary.resolved, 0)
        self.assertEqual(summary.unresolved, 0)
        self.assertIn("does not exist", summary.note)
        # Samples should be untouched
        self.assertEqual(
            [s.frames for s in new_samples], [s.frames for s in self._samples()]
        )

    def test_uuid_mismatch_leaves_frames_raw(self) -> None:
        import apple_instruments_mcp.analysis.symbolicate as sym_module
        from apple_instruments_mcp.analysis.symbolicate import symbolize_samples

        async def fake_run(*args, timeout):  # noqa: ARG001
            # dwarfdump returns a DIFFERENT UUID than what the sample carries
            return 0, "UUID: OTHER-UUID (arm64) /path\n"

        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(sym_module, "_run_capturing", side_effect=fake_run),
        ):
            dsym = Path(tmp) / "MyApp.dSYM"
            inner = dsym / "Contents" / "Resources" / "DWARF"
            inner.mkdir(parents=True)
            (inner / "MyApp").write_bytes(b"")

            new_samples, summary = asyncio.run(
                symbolize_samples(self._samples(), str(dsym))
            )

        self.assertEqual(summary.resolved, 0)
        self.assertEqual(summary.images_without_dsym, 1)
        # Raw leaf remains raw — honest fallback.
        self.assertEqual(new_samples[0].frames[0].symbol, "0x100001a2b4")


class FormatSymbolicationSummaryTests(unittest.TestCase):
    def test_skipped_when_not_attempted(self) -> None:
        from apple_instruments_mcp.analysis.symbolicate import (
            SymbolicationSummary,
            format_symbolication_summary,
        )

        sym = SymbolicationSummary(
            attempted=False, resolved=0, unresolved=0,
            images_with_dsym=0, images_without_dsym=0,
        )
        self.assertEqual(format_symbolication_summary(sym), "")
        self.assertEqual(format_symbolication_summary(None), "")

    def test_renders_counts_and_note(self) -> None:
        from apple_instruments_mcp.analysis.symbolicate import (
            SymbolicationSummary,
            format_symbolication_summary,
        )

        sym = SymbolicationSummary(
            attempted=True, resolved=12, unresolved=3,
            images_with_dsym=1, images_without_dsym=2,
            note="resolved leaf frames from MyApp",
        )
        out = format_symbolication_summary(sym)
        self.assertIn("Symbolication", out)
        self.assertIn("**12**", out)
        self.assertIn("**3**", out)
        self.assertIn("Images without a matching dSYM: 2", out)
        self.assertIn("resolved leaf frames from MyApp", out)


if __name__ == "__main__":
    unittest.main()
