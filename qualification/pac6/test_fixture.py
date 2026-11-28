import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fixture import (
    CASE_LENGTHS,
    SEGMENT_SIZE,
    generate_fixture,
    rename_layout,
    required_free_bytes,
)
from run_matrix import (
    EXPECTED_FIREWALL_RULE,
    TOKEN_ENV_NAMES,
    clean_consumer_environment,
    fail_without_execution,
    hash_member_set,
    inspect_output_files,
    verify_isolation_evidence,
)
from wfp_audit import has_matching_wfp_block


class FixtureTests(unittest.TestCase):
    def test_clean_environment_rejects_credentials_from_parent_process(self):
        for name in sorted(TOKEN_ENV_NAMES):
            with self.subTest(name=name):
                with patch.dict("os.environ", {name: "credential-sentinel"}, clear=True):
                    with self.assertRaisesRegex(ValueError, "credential variable"):
                        clean_consumer_environment()

    def test_case_sizes_include_production_split_boundary(self):
        self.assertEqual(CASE_LENGTHS["production-boundary"], (0xFFFF0000, 1))
        self.assertEqual(SEGMENT_SIZE, 0xFFFF0000)
        self.assertEqual(len(CASE_LENGTHS["ten-members"]), 10)

    def test_generated_members_reconstruct_the_recorded_stream(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = generate_fixture(root / "input", "small-multipart", "xc")
            joined = hashlib.sha256()
            length = 0
            for member in result["ordered_members"]:
                data = (root / "input" / member["name"]).read_bytes()
                self.assertEqual(len(data), member["length"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), member["sha256"])
                joined.update(data)
                length += len(data)
            self.assertEqual(length, result["input_length"])
            self.assertEqual(joined.hexdigest(), result["input_sha256"])

    def test_fixture_hashes_repeat_for_the_same_case(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = generate_fixture(root / "first", "small-multipart", "xc")
            second = generate_fixture(root / "second", "small-multipart", "xc")
            self.assertEqual(first["input_sha256"], second["input_sha256"])
            self.assertEqual(
                [member["sha256"] for member in first["ordered_members"]],
                [member["sha256"] for member in second["ordered_members"]],
            )

    def test_production_boundary_storage_check_stops_before_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            total_length = sum(CASE_LENGTHS["production-boundary"])
            with self.assertRaises(OSError):
                generate_fixture(
                    root / "production-boundary",
                    "production-boundary",
                    "xc",
                    available_free_bytes=required_free_bytes(total_length) - 1,
                )
            self.assertFalse((root / "production-boundary").exists())

    def test_layout_rename_preserves_member_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "input"
            result = generate_fixture(directory, "ten-members", "xc")
            before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.iterdir()}
            rename_layout(directory, "xc", "ns")
            after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.iterdir()}
            self.assertEqual(
                {name.replace(".xc", ".ns"): digest for name, digest in before.items()},
                after,
            )
            snapshot = hash_member_set(directory, result["ordered_members"], "ns")
            self.assertEqual(snapshot["input_length"], result["input_length"])
            self.assertEqual(snapshot["input_sha256"], result["input_sha256"])
            self.assertEqual(
                [member["sha256"] for member in snapshot["ordered_members"]],
                [member["sha256"] for member in result["ordered_members"]],
            )

    def test_member_snapshot_hashes_persisted_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "input"
            result = generate_fixture(directory, "small-multipart", "xc")
            first_member = directory / result["ordered_members"][0]["name"]
            data = bytearray(first_member.read_bytes())
            data[0] ^= 0xFF
            first_member.write_bytes(data)

            snapshot = hash_member_set(directory, result["ordered_members"], "xc")
            self.assertEqual(snapshot["input_length"], result["input_length"])
            self.assertNotEqual(snapshot["input_sha256"], result["input_sha256"])
            self.assertNotEqual(
                snapshot["ordered_members"][0]["sha256"],
                result["ordered_members"][0]["sha256"],
            )

    def test_pre_generation_failure_separates_expected_from_observed_bytes(self):
        result = fail_without_execution(
            "small-multipart",
            "LegacyNs",
            "fixture generation failed",
            python_exe=Path("python.exe"),
            source_root=Path("source"),
            work_dir=Path("work"),
        )
        self.assertIsNone(result["input_length"])
        self.assertEqual(
            result["expected_input_length"],
            sum(CASE_LENGTHS["small-multipart"]),
        )
        self.assertEqual(result["output_name"], "pac6-small-multipart.nsp")
        self.assertFalse(result["consumer_invocation"]["invoked"])
        self.assertFalse(result["output_matches_input"])
        self.assertEqual(
            [member["expected_length"] for member in result["ordered_members"]],
            list(CASE_LENGTHS["small-multipart"]),
        )

    def test_output_inventory_records_an_unexpected_basename(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir()
            (output / "unexpected.nsp").write_bytes(b"synthetic output")
            self.assertEqual(
                inspect_output_files(output),
                [
                    {
                        "name": "unexpected.nsp",
                        "type": "file",
                        "length": len(b"synthetic output"),
                        "sha256": hashlib.sha256(b"synthetic output").hexdigest(),
                    }
                ],
            )

    def test_block_preflight_requires_a_matching_wfp_event_before_verification(self):
        script = Path(__file__).with_name("block-python-egress.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("$auditSubcategory = '{0CCE9226-69AE-11D9-BED3-505054503030}'", script)
        self.assertIn("Get-WinEvent -FilterHashtable", script)
        self.assertIn("wfp_audit.py", script)
        self.assertIn("filter_origin = $fields['FilterOrigin']", script)
        self.assertIn("--firewall-rule-name $ruleName", script)
        verification_query_start = script.index("$eventRows = @()")
        verification_query_end = script.index("} while", verification_query_start)
        verification_query = script[verification_query_start:verification_query_end]
        self.assertIn("EndTime = $verificationEnded", verification_query)
        self.assertIn("-MaxEvents 256", verification_query)
        verification_gate = script.index(
            "if ($null -eq $verification -or -not $verification.matched)"
        )
        failure_throw = script.index(
            "throw 'No matching Windows Filtering Platform block event confirmed the Python probe.'"
        )
        verified_marker = script.index("PAC6_ISOLATION_VERIFIED=1")
        self.assertLess(verification_gate, failure_throw)
        self.assertLess(failure_throw, verified_marker)

    def test_successful_probe_emits_wfp_diagnostics_before_failing_closed(self):
        script = Path(__file__).with_name("block-python-egress.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("/success:enable", script)
        self.assertIn("Id = 5156", script)
        self.assertIn("EndTime = $diagnosticEnded", script)
        self.assertIn("-MaxEvents 256", script)
        self.assertIn("diagnostic_collection_error_type", script)
        diagnostic = script.index("PAC6_PREFLIGHT_DIAGNOSTIC=")
        successful_probe_branch = script.index("if ($probeExit -eq 0) {")
        failed_isolation = script.index(
            "throw 'The Python network probe succeeded after the firewall rule was installed.'"
        )
        self.assertLess(diagnostic, failed_isolation)
        diagnostic_block = script[
            successful_probe_branch:failed_isolation
        ]
        self.assertIn("catch {", diagnostic_block)
        self.assertIn("-ErrorAction Stop", diagnostic_block)
        self.assertIn("NoMatchingEventsFound,", diagnostic_block)
        self.assertIn(
            "if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound,*') {\n"
            "                    throw\n"
            "                }",
            diagnostic_block,
        )
        self.assertIn("diagnostic_collection_error_type", diagnostic_block)
        self.assertIn("diagnostic_collection_command", diagnostic_block)
        self.assertIn("diagnostic_collection_error_id", diagnostic_block)
        self.assertIn("$diagnosticCommand -notin $allowedDiagnosticCommands", diagnostic_block)
        self.assertIn("$diagnosticErrorId = 'Other'", diagnostic_block)
        self.assertNotIn("Exception.Message", diagnostic_block)
        self.assertNotIn("throw ", diagnostic_block)
        self.assertEqual(
            diagnostic_block.count("{") - diagnostic_block.count("}"),
            1,
        )
        verifier = script.index("$eventRows = @()", failed_isolation)
        verified_marker = script.index("PAC6_ISOLATION_VERIFIED=1")
        self.assertLess(failed_isolation, verifier)
        self.assertLess(failed_isolation, verified_marker)
        self.assertIn(
            "        }\n"
            "        throw 'The Python network probe succeeded after the firewall rule was installed.'\n"
            "    }\n\n"
            "    $eventRows = @()",
            script,
        )
        self.assertIn("restoreSuccessAudit", script)

    def test_matrix_runner_reuses_verified_evidence_instead_of_reprobing(self):
        source = Path(__file__).with_name("run_matrix.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("socket.create_connection", source)
        self.assertIn('parser.add_argument("--isolation-evidence"', source)
        verification_call = source.index(
            "isolation_evidence = verify_isolation_evidence("
        )
        extraction_call = source.index(
            "safe_extract_source(\n            args.bundle", verification_call
        )
        self.assertLess(verification_call, extraction_call)
        workflow = Path(__file__).parents[2] / ".github" / "workflows" / "pac6-legacy-consumer.yml"
        self.assertIn("--isolation-evidence", workflow.read_text(encoding="utf-8"))

    def test_matrix_runner_rejects_unmatched_or_wrong_program_evidence(self):
        event = {
            "event_id": 5157,
            "process_id": "4242",
            "application": r"\device\harddiskvolume4\hostedtoolcache\Python\3.12.10\x64\python.exe",
            "destination_address": "1.1.1.1",
            "destination_port": "443",
            "protocol": "6",
            "filter_origin": EXPECTED_FIREWALL_RULE,
        }
        python_path = r"C:\hostedtoolcache\Python\3.12.10\x64\python.exe"
        evidence = {
            "rule_name": EXPECTED_FIREWALL_RULE,
            "program": python_path,
            "program_nt_path": r"\device\harddiskvolume4\hostedtoolcache\Python\3.12.10\x64\python.exe",
            "direction": "Outbound",
            "action": "Block",
            "enabled": True,
            "audit_subcategory": "{0CCE9226-69AE-11D9-BED3-505054503030}",
            "probe_process_id": 4242,
            "probe_address": "1.1.1.1",
            "probe_port": 443,
            "network_probe_exit_status": 1,
            "network_probe_result": "blocked-by-matching-wfp-event",
            "wfp_block_event": event,
        }
        with tempfile.TemporaryDirectory() as temporary:
            evidence_path = Path(temporary) / "isolation.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            accepted = verify_isolation_evidence(
                evidence_path,
                python_path=python_path,
                firewall_rule_name=EXPECTED_FIREWALL_RULE,
            )
            self.assertEqual(accepted["wfp_block_event"], event)

            evidence["wfp_block_event"] = event | {"filter_origin": "Other-Rule"}
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "matching WFP block event"):
                verify_isolation_evidence(
                    evidence_path,
                    python_path=python_path,
                    firewall_rule_name=EXPECTED_FIREWALL_RULE,
                )

            evidence["wfp_block_event"] = event
            evidence["program_nt_path"] = (
                r"\device\harddiskvolume4\hostedtoolcache\Python\3.12.10\x64\other\python.exe"
            )
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "matching WFP block event"):
                verify_isolation_evidence(
                    evidence_path,
                    python_path=python_path,
                    firewall_rule_name=EXPECTED_FIREWALL_RULE,
                )

            evidence["program_nt_path"] = (
                r"\device\harddiskvolume4\hostedtoolcache\Python\3.12.10\x64\python.exe"
            )
            evidence["wfp_block_event"] = event
            evidence["program"] = r"C:\other\python.exe"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "interpreter differs"):
                verify_isolation_evidence(
                    evidence_path,
                    python_path=python_path,
                    firewall_rule_name=EXPECTED_FIREWALL_RULE,
                )

    def test_wfp_block_event_must_match_probe_process_and_endpoint(self):
        event = {
            "event_id": "5157",
            "process_id": "4242",
            "application": r"\device\harddiskvolume4\hostedtoolcache\Python\3.12.10\x64\python.exe",
            "destination_address": "1.1.1.1",
            "destination_port": "443",
            "protocol": "6",
            "filter_origin": "NSCB-PAC6-Python-Egress-Block",
        }
        expected = {
            "process_id": 4242,
            "python_nt_path": r"\device\harddiskvolume4\hostedtoolcache\Python\3.12.10\x64\python.exe",
            "destination_address": "1.1.1.1",
            "destination_port": 443,
            "firewall_rule_name": "NSCB-PAC6-Python-Egress-Block",
        }
        self.assertTrue(has_matching_wfp_block([event], **expected))
        self.assertTrue(
            has_matching_wfp_block(
                [event | {"process_id": "0x1092"}], **expected
            )
        )
        for field, value in (
            ("event_id", "5156"),
            ("process_id", "4243"),
            ("application", r"\device\harddiskvolume4\actions\runner\other.exe"),
            (
                "application",
                r"\device\harddiskvolume4\actions\runner\different\python.exe",
            ),
            (
                "application",
                r"\device\harddiskvolume5\hostedtoolcache\Python\3.12.10\x64\python.exe",
            ),
            ("destination_address", "1.1.1.2"),
            ("destination_port", "444"),
            ("protocol", "17"),
            ("filter_origin", "Other-Block-Rule"),
        ):
            with self.subTest(field=field):
                self.assertFalse(
                    has_matching_wfp_block([event | {field: value}], **expected)
                )

    def test_missing_or_malformed_wfp_events_do_not_verify(self):
        expected = {
            "process_id": 4242,
            "python_nt_path": r"\device\harddiskvolume4\hostedtoolcache\Python\3.12.10\x64\python.exe",
            "destination_address": "1.1.1.1",
            "destination_port": 443,
            "firewall_rule_name": "NSCB-PAC6-Python-Egress-Block",
        }
        self.assertFalse(has_matching_wfp_block([], **expected))
        self.assertFalse(has_matching_wfp_block([{}], **expected))

    def test_wfp_verifier_cli_requires_the_installed_firewall_rule(self):
        event = {
            "event_id": 5157,
            "process_id": "4242",
            "application": r"\device\harddiskvolume4\hostedtoolcache\Python\3.12.10\x64\python.exe",
            "destination_address": "1.1.1.1",
            "destination_port": "443",
            "protocol": "6",
            "filter_origin": "NSCB-PAC6-Python-Egress-Block",
        }
        with tempfile.TemporaryDirectory() as temporary:
            events_path = Path(temporary) / "wfp-events.json"
            command = [
                sys.executable,
                "-E",
                "-s",
                str(Path(__file__).with_name("wfp_audit.py")),
                "--events",
                str(events_path),
                "--process-id",
                "4242",
                "--python-nt-path",
                r"\device\harddiskvolume4\hostedtoolcache\Python\3.12.10\x64\python.exe",
                "--destination-address",
                "1.1.1.1",
                "--destination-port",
                "443",
                "--firewall-rule-name",
                "NSCB-PAC6-Python-Egress-Block",
            ]
            events_path.write_text(json.dumps([event]), encoding="utf-8")
            matching = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(matching.returncode, 0, matching.stderr)

            events_path.write_text(
                json.dumps([event | {"filter_origin": "Unrelated-Rule"}]),
                encoding="utf-8",
            )
            unrelated = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(unrelated.returncode, 1, unrelated.stderr)


if __name__ == "__main__":
    unittest.main()
