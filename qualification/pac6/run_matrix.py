"""Run PAC-6 on a Windows x64 runner and write a compact digest report."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path, PurePosixPath
from typing import Any

from fixture import (
    CASE_LENGTHS,
    RESERVE_BYTES,
    generate_fixture,
    rename_layout,
    required_free_bytes,
    write_json,
)
from wfp_audit import has_matching_wfp_block, normalized_nt_path

BUFFER_BYTES = 8 * 1024 * 1024
LOG_TAIL_BYTES = 8 * 1024
CONSUMER_COMMIT = "92690c0137f520b6ee4d6c20b6f5abe8a3ce5738"
EXPECTED_FIREWALL_RULE = "NSCB-PAC6-Python-Egress-Block"
EXPECTED_AUDIT_SUBCATEGORY = "{0CCE9226-69AE-11D9-BED3-505054503030}"
KEY_DATA_NAMES = {"keys_template.txt", "title.keys", "prod.keys", "dev.keys", "keys.txt"}
TOKEN_ENV_NAMES = {
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "GIT_ASKPASS",
    "SSH_AUTH_SOCK",
}


def digest_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def log_tail(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    with path.open("rb") as source:
        source.seek(max(0, size - LOG_TAIL_BYTES))
        data = source.read(LOG_TAIL_BYTES)
    return {
        "text": data.decode("utf-8", errors="replace"),
        "truncated": size > LOG_TAIL_BYTES,
        "bytes_included": len(data),
    }


def inspect_output_files(directory: Path) -> list[dict[str, Any]]:
    """Record every regular output file without loading it into memory."""
    if not directory.is_dir():
        return []
    files = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            files.append(
                {"name": path.relative_to(directory).as_posix(), "type": "symlink"}
            )
        elif path.is_file():
            files.append(
                {
                    "name": path.relative_to(directory).as_posix(),
                    "type": "file",
                    "length": path.stat().st_size,
                    "sha256": digest_file(path),
                }
            )
    return files


def hash_member_set(
    input_dir: Path,
    expected_members: list[dict[str, Any]],
    member_extension: str,
) -> dict[str, Any]:
    """Hash the exact persisted members in consumer order with bounded memory."""
    stream_hash = hashlib.sha256()
    stream_length = 0
    actual_members = []
    expected_names = set()

    for expected in expected_members:
        name = expected["name"].replace(".xc", f".{member_extension}", 1)
        expected_names.add(name)
        path = input_dir / name
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError(f"fixture member is missing or not a regular file: {name}")

        member_hash = hashlib.sha256()
        member_length = 0
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                member_hash.update(chunk)
                stream_hash.update(chunk)
                member_length += len(chunk)
                stream_length += len(chunk)
        actual_members.append(
            {
                "name": name,
                "length": member_length,
                "sha256": member_hash.hexdigest(),
            }
        )

    actual_names = {
        path.name for path in input_dir.glob(f"*.{member_extension}[0-9]*")
    }
    if actual_names != expected_names:
        raise ValueError("fixture directory contains missing or unexpected split members")
    return {
        "input_length": stream_length,
        "input_sha256": stream_hash.hexdigest(),
        "ordered_members": actual_members,
    }


def safe_extract_source(archive_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive_path, "r:") as archive:
        for member in archive:
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"unsafe path in pinned source archive: {member.name}")
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise ValueError(f"unexpected source entry type: {member.name}")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise OSError(f"unable to read source archive member: {member.name}")
            with target.open("xb") as output:
                shutil.copyfileobj(stream, output, length=1024 * 1024)


def verify_bundle(bundle: Path) -> dict[str, Any]:
    manifest_path = bundle / "bundle-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_files = manifest["bundle_files"]
    actual_files = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file() and path != manifest_path
    }
    if actual_files != set(expected_files):
        raise ValueError("qualification bundle file list differs from its manifest")
    for relative, expected_hash in expected_files.items():
        path = bundle.joinpath(*PurePosixPath(relative).parts)
        if digest_file(path) != expected_hash:
            raise ValueError(f"qualification bundle hash mismatch: {relative}")

    source = manifest["consumer_source"]
    source_archive = bundle / "consumer-source.tar"
    if digest_file(source_archive) != source["archive_sha256"]:
        raise ValueError("pinned consumer source archive hash mismatch")
    dependencies = manifest["dependencies"]
    lock = bundle / "requirements-win-cp312.lock"
    if digest_file(lock) != dependencies["lock_sha256"]:
        raise ValueError("dependency lock hash mismatch")
    if source["commit"] != CONSUMER_COMMIT:
        raise ValueError("consumer commit differs from the approved pin")

    for distribution in dependencies["distributions"]:
        wheel = bundle / "wheelhouse" / distribution["filename"]
        if not wheel.is_file() or digest_file(wheel) != distribution["sha256"]:
            raise ValueError(f"wheel hash mismatch: {distribution['filename']}")
    return manifest


def clean_consumer_environment() -> dict[str, str]:
    if TOKEN_ENV_NAMES.intersection(os.environ):
        raise ValueError("parent environment contains a credential variable")
    keys = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "PATHEXT", "COMSPEC")
    env = {key: os.environ[key] for key in keys if key in os.environ}
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONUTF8"] = "1"
    return env


def verify_isolation_evidence(
    evidence_path: Path,
    *,
    python_path: Path | str,
    firewall_rule_name: str,
) -> dict[str, Any]:
    """Require the preflight's rule-specific WFP event before the matrix runs."""
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("the Windows isolation evidence is unreadable") from exc
    if not isinstance(evidence, dict):
        raise RuntimeError("the Windows isolation evidence is malformed")

    expected_program = os.path.normcase(os.path.normpath(str(python_path)))
    actual_program = os.path.normcase(os.path.normpath(str(evidence.get("program", ""))))
    if actual_program != expected_program:
        raise RuntimeError("the isolation evidence interpreter differs from the consumer")
    if firewall_rule_name != EXPECTED_FIREWALL_RULE or evidence.get("rule_name") != EXPECTED_FIREWALL_RULE:
        raise RuntimeError("the isolation evidence does not identify the PAC-6 firewall rule")
    if (
        evidence.get("direction") != "Outbound"
        or evidence.get("action") != "Block"
        or evidence.get("enabled") is not True
        or evidence.get("audit_subcategory") != EXPECTED_AUDIT_SUBCATEGORY
        or evidence.get("network_probe_result") != "blocked-by-matching-wfp-event"
    ):
        raise RuntimeError("the Windows isolation evidence does not show an active outbound block")

    event = evidence.get("wfp_block_event")
    python_nt_path = normalized_nt_path(evidence.get("program_nt_path"))
    if python_nt_path is None:
        raise RuntimeError("the isolation evidence lacks the resolved NT device path")
    try:
        process_id = int(evidence["probe_process_id"])
        destination_port = int(evidence["probe_port"])
        probe_exit_status = int(evidence["network_probe_exit_status"])
        destination_address = str(evidence["probe_address"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("the Windows isolation evidence lacks probe details") from exc
    if process_id <= 0 or not 1 <= destination_port <= 65535 or probe_exit_status == 0:
        raise RuntimeError("the Windows isolation probe did not fail as expected")
    if not isinstance(event, dict) or not has_matching_wfp_block(
        [event],
        process_id=process_id,
        python_nt_path=python_nt_path,
        destination_address=destination_address,
        destination_port=destination_port,
        firewall_rule_name=EXPECTED_FIREWALL_RULE,
    ):
        raise RuntimeError("the isolation evidence lacks a matching WFP block event")
    return evidence


def run_logged(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log_path: Path,
    timeout_seconds: int,
) -> tuple[int, float]:
    started = time.monotonic()
    with log_path.open("wb") as log:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=timeout_seconds,
            check=False,
        )
    return completed.returncode, time.monotonic() - started


def planned_command(
    python_exe: Path,
    script: Path,
    output_dir: Path,
    text_file: Path,
) -> list[str]:
    # In pinned v0.99, --joinfile is a mode flag with nargs='+'. When -tfile
    # is set, the join branch reads its first member path from that list file.
    # Keep the empty mode argument separate from the actual member selection.
    return [
        str(python_exe),
        "-E",
        "-s",
        str(script),
        "-b",
        str(BUFFER_BYTES),
        "-o",
        str(output_dir),
        "-tfile",
        str(text_file),
        "--joinfile",
        "",
    ]


def run_case(
    *,
    case_name: str,
    layout: str,
    fixture_data: dict[str, Any],
    member_extension: str,
    python_exe: Path,
    source_root: Path,
    work_dir: Path,
    env: dict[str, str],
) -> dict[str, Any]:
    input_dir = work_dir / "fixtures" / case_name
    output_dir = work_dir / "output" / f"{case_name}-{layout}"
    filelist = work_dir / "filelists" / f"{case_name}-{layout}.txt"
    logs_dir = work_dir / "logs"
    command = planned_command(
        python_exe,
        source_root / "py" / "ztools" / "squirrel.py",
        output_dir,
        filelist,
    )
    expected_suffix = ".xci" if member_extension == "xc" else ".nsp"
    output_path = output_dir / f"pac6-{case_name}{expected_suffix}"
    log_path = logs_dir / f"{case_name}-{layout}.log"

    input_error = None
    try:
        input_snapshot = hash_member_set(
            input_dir,
            fixture_data["ordered_members"],
            member_extension,
        )
    except Exception as exc:
        input_snapshot = {
            "input_length": None,
            "input_sha256": None,
            "ordered_members": [
                {
                    "name": member["name"].replace(".xc", f".{member_extension}", 1),
                    "length": None,
                    "sha256": None,
                }
                for member in fixture_data["ordered_members"]
            ],
        }
        input_error = f"{type(exc).__name__}: {exc}"
    generated_members = [
        {
            **member,
            "name": member["name"].replace(".xc", f".{member_extension}", 1),
        }
        for member in fixture_data["ordered_members"]
    ]
    input_matches_generated_fixture = (
        input_snapshot["input_length"] == fixture_data["input_length"]
        and input_snapshot["input_sha256"] == fixture_data["input_sha256"]
        and input_snapshot["ordered_members"] == generated_members
    )
    result: dict[str, Any] = {
        "case": case_name,
        "layout": layout,
        "input_length": input_snapshot["input_length"],
        "input_sha256": input_snapshot["input_sha256"],
        "input_matches_generated_fixture": input_matches_generated_fixture,
        "ordered_members": input_snapshot["ordered_members"],
        "consumer_invocation": {
            "argv": command,
            "windows_command_line": subprocess.list2cmdline(command),
            "working_directory": str(source_root / "py" / "ztools"),
            "environment_names": sorted(env),
            "invoked": False,
        },
        "exit_status": None,
        "output_length": None,
        "output_name": output_path.name,
        "output_sha256": None,
        "produced_files": [],
        "output_matches_input": False,
        "result": "FAIL",
    }

    if input_error is not None:
        result["failure_reason"] = f"input verification failed: {input_error}"
        return result
    if not input_matches_generated_fixture:
        result["failure_reason"] = "persisted fixture bytes differ from the generated stream"
        return result

    first_member = input_dir / input_snapshot["ordered_members"][0]["name"]
    try:
        filelist.parent.mkdir(parents=True, exist_ok=True)
        filelist.write_text(str(first_member) + "\n", encoding="utf-8")
        result["consumer_invocation"]["text_file_length"] = filelist.stat().st_size
        result["consumer_invocation"]["text_file_sha256"] = digest_file(filelist)
        output_dir.mkdir(parents=True, exist_ok=False)
        logs_dir.mkdir(parents=True, exist_ok=True)
        result["consumer_invocation"]["invoked"] = True
        exit_status, elapsed = run_logged(
            command,
            cwd=source_root / "py" / "ztools",
            env=env,
            log_path=log_path,
            timeout_seconds=3600,
        )
        result["exit_status"] = exit_status
        result["elapsed_seconds"] = round(elapsed, 3)
        result["log_sha256"] = digest_file(log_path)
        result["produced_files"] = inspect_output_files(output_dir)
        expected_output = next(
            (
                produced
                for produced in result["produced_files"]
                if produced["name"] == output_path.name and produced["type"] == "file"
            ),
            None,
        )
        if expected_output is not None:
            result["output_length"] = expected_output["length"]
            result["output_sha256"] = expected_output["sha256"]
        matches = (
            exit_status == 0
            and result["output_length"] == input_snapshot["input_length"]
            and result["output_sha256"] == input_snapshot["input_sha256"]
        )
        result["output_matches_input"] = matches
        if matches:
            result["result"] = "PASS"
        else:
            result["failure_reason"] = "consumer status, output length, or SHA-256 did not match"
            result["log_tail"] = log_tail(log_path)
    except Exception as exc:  # Include timeout and file errors in the evidence report.
        result["failure_reason"] = f"{type(exc).__name__}: {exc}"
        if log_path.is_file():
            result["log_sha256"] = digest_file(log_path)
            result["log_tail"] = log_tail(log_path)
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)
        filelist.unlink(missing_ok=True)
    return result


def fail_without_execution(
    case_name: str,
    layout: str,
    reason: str,
    *,
    python_exe: Path,
    source_root: Path,
    work_dir: Path,
    storage_preflight: dict[str, Any] | None = None,
) -> dict[str, Any]:
    extension = "xc" if layout == "LegacyXc" else "ns"
    output_dir = work_dir / "output" / f"{case_name}-{layout}"
    filelist = work_dir / "filelists" / f"{case_name}-{layout}.txt"
    member_paths = [f"pac6-{case_name}.{extension}{index}" for index in range(len(CASE_LENGTHS[case_name]))]
    command = planned_command(
        python_exe,
        source_root / "py" / "ztools" / "squirrel.py",
        output_dir,
        filelist,
    )
    expected_output = f"pac6-{case_name}{'.xci' if extension == 'xc' else '.nsp'}"
    expected_input_length = sum(CASE_LENGTHS[case_name])
    return {
        "case": case_name,
        "layout": layout,
        "input_length": None,
        "expected_input_length": expected_input_length,
        "input_sha256": None,
        "input_matches_generated_fixture": False,
        "ordered_members": [
            {
                "name": name,
                "length": None,
                "expected_length": length,
                "sha256": None,
            }
            for name, length in zip(member_paths, CASE_LENGTHS[case_name])
        ],
        "consumer_invocation": {
            "argv": command,
            "windows_command_line": subprocess.list2cmdline(command),
            "working_directory": str(source_root / "py" / "ztools"),
            "invoked": False,
        },
        "exit_status": None,
        "output_length": None,
        "output_name": expected_output,
        "output_sha256": None,
        "produced_files": [],
        "output_matches_input": False,
        "result": "FAIL",
        "failure_reason": reason,
        "storage_preflight": storage_preflight,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--isolation-evidence", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    args = parser.parse_args()

    report: dict[str, Any] = {
        "schema_version": 1,
        "task": "NSCB Issue 14 Slice C PAC-6",
        "tested_revision": os.environ.get("PAC6_HEAD_SHA"),
        "workflow": {
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "run_url": (
                f"{os.environ.get('GITHUB_SERVER_URL')}/{os.environ.get('GITHUB_REPOSITORY')}"
                f"/actions/runs/{os.environ.get('GITHUB_RUN_ID')}"
            ),
        },
        "runner": {
            "label": os.environ.get("PAC6_RUNNER_LABEL", "windows-2025"),
            "os": platform.platform(),
            "architecture": platform.machine(),
            "python": sys.version,
        },
        "consumer_source": {},
        "dependencies": {},
        "isolation": {},
        "cases": [],
    }
    fixture_root = args.work_dir / "fixtures"
    args.work_dir.mkdir(parents=True, exist_ok=True)

    try:
        if sys.platform != "win32" or platform.machine().lower() not in {"amd64", "x86_64"}:
            raise RuntimeError("PAC-6 requires a Windows x64 runner")
        if sys.version_info[:3] != (3, 12, 10):
            raise RuntimeError("PAC-6 requires CPython 3.12.10")
        if os.environ.get("GITHUB_ACTIONS") != "true":
            raise RuntimeError("the pinned consumer may run only in the hosted Actions job")
        if os.environ.get("PAC6_ISOLATION_VERIFIED") != "1":
            raise RuntimeError("the Windows network boundary was not verified")
        if TOKEN_ENV_NAMES.intersection(os.environ):
            raise RuntimeError("credential variables are present in the consumer runner process")
        firewall_rule_name = os.environ.get("PAC6_EGRESS_RULE", "")
        expected_program = os.environ.get("PAC6_EGRESS_PROGRAM", "")
        if os.path.normcase(os.path.normpath(expected_program)) != os.path.normcase(
            os.path.normpath(str(args.python.resolve()))
        ):
            raise RuntimeError("the verified firewall program differs from the consumer")

        manifest = verify_bundle(args.bundle.resolve())
        expected_revision = os.environ.get("PAC6_HEAD_SHA")
        if not expected_revision or manifest["tested_revision"] != expected_revision:
            raise RuntimeError("qualification bundle revision differs from the pull request head")
        report["tested_revision"] = manifest["tested_revision"]
        report["consumer_source"] = manifest["consumer_source"]
        report["dependencies"] = manifest["dependencies"]
        isolation_evidence = verify_isolation_evidence(
            args.isolation_evidence,
            python_path=args.python.resolve(),
            firewall_rule_name=firewall_rule_name,
        )
        report["isolation"] = {
            "repository_checkout": False,
            "repository_token_permissions": "none",
            "credential_environment_variables": "absent",
            "consumer_subprocess_environment": "allowlisted system paths only",
            "python_firewall_rule": firewall_rule_name,
            "python_firewall_program": expected_program,
            "python_firewall_program_nt_path": isolation_evidence["program_nt_path"],
            "network_probe": isolation_evidence["network_probe_result"],
            "probe_exit_status": isolation_evidence["network_probe_exit_status"],
            "wfp_block_event": isolation_evidence["wfp_block_event"],
        }

        env = clean_consumer_environment()

        safe_extract_source(
            args.bundle / "consumer-source.tar",
            args.work_dir / "consumer-source",
        )
        source_root = args.work_dir / "consumer-source"
        forbidden_files = [
            path.relative_to(source_root).as_posix()
            for path in source_root.rglob("*")
            if path.is_file()
            and (
                path.name.lower() in KEY_DATA_NAMES
                or path.suffix.lower() in {".keys", ".key"}
            )
        ]
        if forbidden_files:
            raise RuntimeError("key data appeared in the consumer source bundle")
        report["consumer_source"]["excluded_key_data_files"] = manifest["consumer_source"][
            "excluded_key_data_files"
        ]

        script = source_root / "py" / "ztools" / "squirrel.py"
        help_log = args.work_dir / "logs" / "consumer-help.log"
        help_log.parent.mkdir(parents=True, exist_ok=True)
        help_command = [str(args.python.resolve()), "-E", "-s", str(script), "--help"]
        help_status, help_elapsed = run_logged(
            help_command,
            cwd=script.parent,
            env=env,
            log_path=help_log,
            timeout_seconds=120,
        )
        help_text = help_log.read_text(encoding="utf-8", errors="replace")
        report["isolation"]["consumer_import_preflight"] = {
            "argv": help_command,
            "windows_command_line": subprocess.list2cmdline(help_command),
            "exit_status": help_status,
            "elapsed_seconds": round(help_elapsed, 3),
            "joinfile_option_present": "--joinfile" in help_text,
            "log_sha256": digest_file(help_log),
        }
        if help_status != 0 or "--joinfile" not in help_text:
            report["isolation"]["consumer_import_preflight"]["log_tail"] = log_tail(
                help_log
            )
            raise RuntimeError("pinned consumer import preflight failed")

        fixture_root.mkdir(parents=True, exist_ok=True)
        for case_name in CASE_LENGTHS:
            input_dir = fixture_root / case_name
            total_length = sum(CASE_LENGTHS[case_name])
            storage_preflight = None
            available_free_bytes = None
            if case_name == "production-boundary":
                free_bytes = shutil.disk_usage(fixture_root).free
                required_bytes = required_free_bytes(total_length)
                storage_preflight = {
                    "free_bytes": free_bytes,
                    "required_bytes": required_bytes,
                    "input_and_output_bytes_required": total_length * 2,
                    "reserve_bytes": RESERVE_BYTES,
                    "passed": free_bytes >= required_bytes,
                }
                available_free_bytes = free_bytes
                if not storage_preflight["passed"]:
                    reason = (
                        "insufficient free space before fixture generation: "
                        f"{free_bytes} < {required_bytes}"
                    )
                    for layout in ("LegacyXc", "LegacyNs"):
                        result = fail_without_execution(
                            case_name,
                            layout,
                            reason,
                            python_exe=args.python.resolve(),
                            source_root=source_root,
                            work_dir=args.work_dir,
                            storage_preflight=storage_preflight,
                        )
                        report["cases"].append(result)
                        write_json(args.report, report)
                    continue
            try:
                fixture_data = generate_fixture(
                    input_dir,
                    case_name,
                    "xc",
                    available_free_bytes=available_free_bytes,
                )
            except Exception as exc:
                reason = f"fixture generation failed: {type(exc).__name__}: {exc}"
                for layout in ("LegacyXc", "LegacyNs"):
                    result = fail_without_execution(
                        case_name,
                        layout,
                        reason,
                        python_exe=args.python.resolve(),
                        source_root=source_root,
                        work_dir=args.work_dir,
                        storage_preflight=storage_preflight,
                    )
                    report["cases"].append(result)
                    write_json(args.report, report)
                continue
            if storage_preflight is None:
                storage_preflight = fixture_data["storage_preflight"]
            fixture_data["storage_preflight"]["input_and_output_bytes_required"] = (
                fixture_data["input_length"] * 2
            )
            for layout, member_extension in (("LegacyXc", "xc"), ("LegacyNs", "ns")):
                if member_extension == "ns":
                    rename_layout(input_dir, "xc", "ns")
                result = run_case(
                    case_name=case_name,
                    layout=layout,
                    fixture_data=fixture_data,
                    member_extension=member_extension,
                    python_exe=args.python.resolve(),
                    source_root=source_root,
                    work_dir=args.work_dir,
                    env=env,
                )
                result["storage_preflight"] = fixture_data["storage_preflight"]
                report["cases"].append(result)
                write_json(args.report, report)
            shutil.rmtree(input_dir, ignore_errors=True)

    except Exception as exc:
        report["fatal_error"] = f"{type(exc).__name__}: {exc}"
    report["result"] = (
        "PASS"
        if len(report["cases"]) == 8
        and all(case["result"] == "PASS" for case in report["cases"])
        and "fatal_error" not in report
        else "FAIL"
    )
    write_json(args.report, report)
    print(json.dumps({"result": report["result"], "cases": len(report["cases"]), "report": str(args.report)}))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
