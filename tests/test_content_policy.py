"""Behavioral tests for repository content policy without disposable Git repositories."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_TEMP_DIRECTORY_BASE = Path(os.path.realpath(tempfile.gettempdir()))
CHECKER = REPOSITORY_ROOT / "scripts" / "check_content_policy.py"
REGISTRY_PATH = "tests/fixtures/registry.json"

sys.path.insert(0, str(CHECKER.parent))
sys.path.insert(0, str(REPOSITORY_ROOT / "tests"))

import check_content_policy as content_policy  # noqa: E402
from check_content_policy import (  # noqa: E402
    CheckerFailure,
    ContentPolicyChecker,
    _display_path,
    _run_git_command,
)
from content_policy_test_support import (  # noqa: E402
    InMemoryGitFixture,
    ProhibitedGitMetadata,
    ProhibitedGitOperation,
    RoutineGitGuard,
    UnsupportedGitCommand,
    write_fake_git_script,
)


def registry_document(fixtures: list[dict[str, object]] | None = None) -> bytes:
    """Return the canonical empty or populated version-one fixture registry."""
    return (
        json.dumps({"schema_version": 1, "fixtures": fixtures or []}, indent=2) + "\n"
    ).encode()


def synthetic_entry(path: str, data: bytes) -> dict[str, object]:
    """Describe deterministic synthetic bytes for registry validation tests."""
    return {
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "source": "Generated deterministically for policy tests",
        "provenance": {
            "kind": "synthetic",
            "generator": "tests/test_content_policy.py",
            "reproduction": "Run the policy test that creates this in-memory fixture",
        },
        "license_basis": "Original synthetic bytes created for this test",
    }


@dataclass(frozen=True)
class CheckResult:
    """Small command-like result used by in-process policy assertions."""

    returncode: int
    stdout: bytes
    stderr: bytes


class ContentPolicyTestCase(unittest.TestCase):
    """Provide one isolated worktree and fail closed against real Git mutation."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        self.root = Path(self.temporary_directory.name)
        self.guard = RoutineGitGuard([self.root])
        self.guard.start()
        self.fixture = InMemoryGitFixture(self.root)
        self.fixture.stage(
            "README.md", b"A synthetic repository used by content-policy tests.\n"
        )
        self.fixture.stage(REGISTRY_PATH, registry_document())

    def tearDown(self) -> None:
        try:
            self.guard.assert_no_git_metadata(self.root)
        finally:
            self.guard.stop()
            self.temporary_directory.cleanup()

    def path(self, relative_path: str) -> Path:
        return self.root / relative_path

    def write(self, relative_path: str, data: bytes) -> Path:
        """Write worktree bytes without implicitly changing the index."""
        path = self.path(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if relative_path in self.fixture.staged_paths:
            self.fixture.edit(relative_path, data)
        else:
            self.fixture.register_untracked_path(relative_path)
        return path

    def stage(self, relative_path: str, data: bytes | None = None, **kwargs: object) -> str:
        return self.fixture.stage(relative_path, data, **kwargs)

    def check(
        self,
        *,
        root: Path | None = None,
        runner: object | None = None,
    ) -> CheckResult:
        """Run the checker in process through the supplied read-only runner."""
        selected_root = self.root if root is None else root
        selected_runner = self.fixture.run_command if runner is None else runner
        try:
            checker = ContentPolicyChecker(selected_root, runner=selected_runner)  # type: ignore[arg-type]
            findings = checker.run()
        except CheckerFailure as failure:
            suffix = f" path={_display_path(failure.path)}" if failure.path else ""
            return CheckResult(2, b"", f"ERROR {failure.code}{suffix}\n".encode())
        if not findings:
            return CheckResult(
                0,
                b"Content policy passed for the Git index and working tree.\n",
                b"",
            )
        lines = sorted(
            f"{finding.snapshot}_{finding.rule} path={_display_path(finding.path)}"
            for finding in findings
        )
        if checker.omitted_findings:
            lines.append(f"FINDINGS_TRUNCATED omitted={checker.omitted_findings}")
        return CheckResult(1, ("\n".join(lines) + "\n").encode(), b"")

    @staticmethod
    def report(result: CheckResult | subprocess.CompletedProcess[bytes]) -> str:
        return (result.stdout + result.stderr).decode("utf-8", errors="replace")


class GitGuardTests(unittest.TestCase):
    """Prove the routine-test guard rejects mutation rather than silently passing."""

    def test_guard_rejects_direct_and_nested_subprocess_git_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guard = RoutineGitGuard([root])
            guard.start()
            try:
                for command in (
                    ["git", "init", "--quiet"],
                    ["/bin/sh", "-c", "git commit -m forbidden"],
                ):
                    with self.subTest(command=command):
                        with self.assertRaises(ProhibitedGitOperation):
                            subprocess.run(command, cwd=root, check=False)
                with self.assertRaises(ProhibitedGitOperation):
                    os.system("git update-index --refresh")
            finally:
                guard.stop()

    def test_guard_rejects_git_metadata_creation_before_it_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guard = RoutineGitGuard([root])
            guard.start()
            try:
                with self.assertRaises(ProhibitedGitMetadata):
                    (root / ".git").mkdir()
                with self.assertRaises(ProhibitedGitMetadata):
                    os.mkdir(root / "nested" / ".git")
            finally:
                guard.stop()
            self.assertFalse((root / ".git").exists())

    def test_guard_fails_closed_for_unknown_git_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = RoutineGitGuard([Path(directory)])
            guard.start()
            try:
                with self.assertRaises(ProhibitedGitOperation):
                    subprocess.run(["git", "status"], check=False)
                with self.assertRaises(ProhibitedGitOperation):
                    guard.assert_command_allowed("git --version", shell=True)
            finally:
                guard.stop()

    def test_guard_rejects_low_level_process_launcher_git_mutation(self) -> None:
        missing = "/definitely-not-an-executable"
        launchers = [
            ("execv", lambda: os.execv(missing, ["git", "init"])),
            ("execve", lambda: os.execve(missing, ["git", "init"], os.environ)),
            ("execl", lambda: os.execl(missing, "git", "init")),
            ("execlp", lambda: os.execlp(missing, "git", "init")),
            ("execvp", lambda: os.execvp(missing, ["git", "init"])),
            ("execvpe", lambda: os.execvpe(missing, ["git", "init"], os.environ)),
            ("spawnv", lambda: os.spawnv(os.P_WAIT, missing, ["git", "init"])),
            ("spawnve", lambda: os.spawnve(os.P_WAIT, missing, ["git", "init"], os.environ)),
            ("spawnl", lambda: os.spawnl(os.P_WAIT, missing, "git", "init")),
            ("spawnle", lambda: os.spawnle(os.P_WAIT, missing, "git", "init", os.environ)),
            ("spawnlp", lambda: os.spawnlp(os.P_WAIT, missing, "git", "init")),
            ("spawnlpe", lambda: os.spawnlpe(os.P_WAIT, missing, "git", "init", os.environ)),
            ("spawnvp", lambda: os.spawnvp(os.P_WAIT, missing, ["git", "init"])),
            ("spawnvpe", lambda: os.spawnvpe(os.P_WAIT, missing, ["git", "init"], os.environ)),
            (
                "posix_spawn",
                lambda: os.posix_spawn(missing, ["git", "init"], os.environ),
            ),
            (
                "posix_spawnp",
                lambda: os.posix_spawnp(missing, ["git", "init"], os.environ),
            ),
        ]
        with tempfile.TemporaryDirectory() as directory:
            guard = RoutineGitGuard([Path(directory)])
            guard.start()
            try:
                for name, launch in launchers:
                    if not hasattr(os, name):
                        continue
                    with self.subTest(launcher=name), self.assertRaises(
                        ProhibitedGitOperation
                    ):
                        launch()
                for name, launch in (
                    ("execv", lambda: os.execv("/missing/git", ["not-git", "init"])),
                    (
                        "spawnv",
                        lambda: os.spawnv(os.P_WAIT, "/missing/git", ["not-git", "init"]),
                    ),
                    (
                        "posix_spawn",
                        lambda: os.posix_spawn(
                            "/missing/git", ["not-git", "init"], os.environ
                        ),
                    ),
                ):
                    if not hasattr(os, name):
                        continue
                    with self.subTest(launcher=name, detection="path"), self.assertRaises(
                        ProhibitedGitOperation
                    ):
                        launch()
            finally:
                guard.stop()

    def test_guard_rejects_popen_executable_override_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "git-like"
            executable.write_text("#!/bin/sh\nmkdir -p .git\n", encoding="utf-8")
            executable.chmod(0o755)
            guard = RoutineGitGuard([root])
            guard.start()
            try:
                with self.assertRaises(ProhibitedGitOperation):
                    subprocess.run(
                        ["init"],
                        executable=str(executable),
                        cwd=root,
                        check=False,
                    )
                with self.assertRaises(ProhibitedGitOperation):
                    subprocess.Popen(
                        ["init"],
                        -1,
                        "/definitely-not-an-executable",
                        cwd=root,
                    )
                self.assertFalse((root / ".git").exists())
            finally:
                guard.stop()


class ContentPolicyTests(ContentPolicyTestCase):
    """Exercise checker behavior through the in-memory index and real worktree."""

    def test_empty_registry_and_benign_documentation_pass(self) -> None:
        self.write(
            "docs/policy-notes.md",
            b"Nintendo keys and ticket files are prohibited. Use synthetic fixtures.\n"
            b"A regex description may mention master_key_00 and hexadecimal placeholders.\n",
        )
        result = self.check()
        self.assertEqual(result.returncode, 0, self.report(result))

    def test_initial_unstaged_registry_is_scanned_as_worktree_content(self) -> None:
        self.fixture.unstage(REGISTRY_PATH)
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 0, report)
        self.assertNotIn("INDEX_REGISTRY_MISSING", report)
        self.assertNotIn("WORKTREE_REGISTRY_MISSING", report)

    def test_registered_synthetic_binary_passes_with_matching_hash(self) -> None:
        relative_path = "tests/fixtures/sample.bin"
        data = b"PFS0\x00synthetic-only"
        self.stage(relative_path, data)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, data)]))
        self.stage(REGISTRY_PATH)
        result = self.check()
        self.assertEqual(result.returncode, 0, self.report(result))

    def test_unregistered_untracked_binary_is_rejected_only_in_worktree(self) -> None:
        self.write("notes/opaque.bin", b"\x00synthetic payload")
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_BINARY_UNREGISTERED", report)
        self.assertNotIn("INDEX_BINARY_UNREGISTERED", report)

    def test_invalid_utf8_is_binary_even_without_a_known_extension(self) -> None:
        self.write("notes/opaque.data", b"\xff\xfe")
        result = self.check()
        self.assertEqual(result.returncode, 1, self.report(result))
        self.assertIn("WORKTREE_BINARY_UNREGISTERED", self.report(result))

    def test_worktree_fixture_tampering_uses_worktree_registry(self) -> None:
        original = b"\x00original synthetic bytes"
        relative_path = "tests/fixtures/sample.bin"
        self.stage(relative_path, original)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, original)]))
        self.stage(REGISTRY_PATH)
        self.write(relative_path, b"\x00tampered working copy")
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_FIXTURE_HASH_MISMATCH", report)
        self.assertNotIn("INDEX_FIXTURE_HASH_MISMATCH", report)

    def test_staged_fixture_tampering_uses_index_registry(self) -> None:
        original = b"\x00original synthetic bytes"
        relative_path = "tests/fixtures/sample.bin"
        self.stage(relative_path, original)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, original)]))
        self.stage(REGISTRY_PATH)
        self.stage(relative_path, b"\x00staged tampering")
        self.write(relative_path, original)
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_FIXTURE_HASH_MISMATCH", report)
        self.assertNotIn("WORKTREE_FIXTURE_HASH_MISMATCH", report)

    def test_staged_secret_survives_benign_worktree_replacement(self) -> None:
        token = b"ghp_" + b"Q" * 40
        marker = b"STAGED_SECRET_MARKER"
        relative_path = "notes/credential-sample.txt"
        self.stage(relative_path, token + b" " + marker)
        self.write(relative_path, b"benign working-tree replacement\n")
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_GITHUB_CREDENTIAL", report)
        self.assertNotIn("WORKTREE_GITHUB_CREDENTIAL", report)
        self.assertNotIn(token.decode(), report)
        self.assertNotIn(marker.decode(), report)
        self.assertNotIn(str(self.root), report)

    def test_staged_binary_survives_benign_worktree_replacement(self) -> None:
        relative_path = "notes/staged-only.txt"
        self.stage(relative_path, b"\x00staged binary payload")
        self.write(relative_path, b"benign text replacement\n")
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_BINARY_UNREGISTERED", report)
        self.assertNotIn("WORKTREE_BINARY_UNREGISTERED", report)
        self.assertNotIn("staged binary payload", report)

    def test_staged_binary_cannot_rely_on_untracked_registry(self) -> None:
        data = b"\x00staged binary payload"
        relative_path = "notes/staged-only.bin"
        self.stage(relative_path, data)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, data)]))
        self.fixture.unstage(REGISTRY_PATH)
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_REGISTRY_MISSING", report)
        self.assertIn("INDEX_BINARY_UNREGISTERED", report)
        self.assertNotIn("WORKTREE_BINARY_UNREGISTERED", report)

    def test_index_and_worktree_registries_are_validated_independently(self) -> None:
        original = b"\x00original bytes"
        updated = b"\x00updated bytes"
        relative_path = "tests/fixtures/sample.bin"
        self.stage(relative_path, updated)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, updated)]))
        self.stage(REGISTRY_PATH)
        self.fixture.edit(relative_path, original)
        self.fixture.edit(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, original)]))
        result = self.check()
        self.assertEqual(result.returncode, 0, self.report(result))

    def test_registry_rejects_wrong_schema_hash_and_missing_provenance(self) -> None:
        relative_path = "tests/fixtures/sample.bin"
        data = b"\x00synthetic"
        bad_entry = synthetic_entry(relative_path, data)
        bad_hash = dict(bad_entry, sha256="0" * 64)
        bad_provenance = dict(bad_entry, provenance={"kind": "private"})
        self.stage(relative_path, data)
        documents = (
            (b'{"schema_version": 2, "fixtures": []}\n', "WORKTREE_REGISTRY_INVALID"),
            (registry_document([bad_hash]), "WORKTREE_FIXTURE_HASH_MISMATCH"),
            (registry_document([bad_provenance]), "WORKTREE_REGISTRY_INVALID"),
        )
        for document, expected in documents:
            with self.subTest(document=document[:40]):
                self.write(REGISTRY_PATH, document)
                self.stage(REGISTRY_PATH)
                result = self.check()
                self.assertEqual(result.returncode, 1, self.report(result))
                self.assertIn(expected, self.report(result))

    def test_registry_rejects_duplicate_and_escaping_paths(self) -> None:
        data = b"\x00synthetic"
        duplicate = synthetic_entry("tests/fixtures/sample.bin", data)
        escaping = synthetic_entry("../outside.bin", data)
        for fixtures in ([duplicate, duplicate], [escaping]):
            with self.subTest(fixtures=fixtures):
                self.write(REGISTRY_PATH, registry_document(fixtures))
                self.stage(REGISTRY_PATH)
                result = self.check()
                self.assertEqual(result.returncode, 1, self.report(result))
                self.assertIn("WORKTREE_REGISTRY_INVALID", self.report(result))

    def test_registry_reports_missing_fixture_without_echoing_registry(self) -> None:
        relative_path = "tests/fixtures/missing.bin"
        self.write(
            REGISTRY_PATH,
            registry_document([synthetic_entry(relative_path, b"\x00missing")]),
        )
        self.stage(REGISTRY_PATH)
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_FIXTURE_MISSING", report)
        self.assertIn("INDEX_FIXTURE_MISSING", report)
        self.assertNotIn("schema_version", report)

    def test_registry_rejects_untracked_fixture_path(self) -> None:
        relative_path = "tests/fixtures/untracked.bin"
        data = b"\x00untracked"
        self.write(relative_path, data)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, data)]))
        self.fixture.unstage(REGISTRY_PATH)
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_FIXTURE_UNTRACKED", report)

    def test_prohibited_filename_is_rejected_without_matching_prose(self) -> None:
        self.write("tests/fixtures/prod.keys", b"not key material\n")
        self.write(
            "docs/prohibited-name-example.txt",
            b"The name prod.keys is prohibited, but this prose is documentation.\n",
        )
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_PROHIBITED_FILENAME", report)
        self.assertIn('"tests/fixtures/prod.keys"', report)
        self.assertNotIn('"docs/prohibited-name-example.txt"', report)

    def test_private_key_headers_are_detected_without_echoing_bytes(self) -> None:
        marker = b"PRIVATE_MATERIAL_MARKER"
        begin = b"-----BEGIN "
        suffix = b"PRIVATE" + b" KEY-----"
        headers = tuple(
            begin + prefix + suffix
            for prefix in (b"", b"RSA ", b"EC ", b"DSA ", b"OPENSSH ", b"ENCRYPTED ")
        )
        for index, header in enumerate(headers):
            self.write(f"notes/sample-{index}.txt", header + b"\n" + marker)
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertEqual(report.count("WORKTREE_PRIVATE_KEY_HEADER"), len(headers))
        self.assertNotIn(marker.decode(), report)
        for header in headers:
            self.assertNotIn(header.decode(), report)

    def test_aws_access_key_is_detected_without_echoing_value(self) -> None:
        marker = b"AWS_VALUE_MARKER"
        value = b"AKIA" + b"0" * 16
        self.write("notes/config.txt", b"aws_access_key_id = " + value + b" # " + marker)
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_AWS_CREDENTIAL", report)
        self.assertNotIn(value.decode(), report)
        self.assertNotIn(marker.decode(), report)

    def test_aws_secret_in_path_is_redacted_from_diagnostics(self) -> None:
        secret = b"ghp_" + b"R" * 40
        relative_path = f"notes/{secret.decode()}/prod.keys"
        self.write(relative_path, b"benign documented bytes\n")
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("[redacted]", report)
        self.assertNotIn(secret.decode(), report)
        self.assertNotIn(str(self.root), report)

    def test_aws_secret_assignment_with_windows_newline_is_detected(self) -> None:
        secret = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
        path = "notes/windows-aws-secret.txt"
        for value, expected_code in ((secret, 1), (b"-" * 40, 0)):
            self.write(path, b"aws_secret_access_key = " + value + b"\r\n")
            result = self.check()
            self.assertEqual(result.returncode, expected_code, self.report(result))
            if expected_code:
                self.assertIn("WORKTREE_AWS_CREDENTIAL", self.report(result))
                self.assertNotIn(secret.decode(), self.report(result))

    def test_aws_json_secret_forms_are_detected_without_echoing_values(self) -> None:
        secret = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
        documents = (
            b'{"aws_secret_access_key":"' + secret + b'"}\n',
            b'{"SecretAccessKey": "' + secret + b'"}\n',
        )
        for index, document in enumerate(documents):
            self.write(f"notes/aws-{index}.json", document)
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertEqual(report.count("WORKTREE_AWS_CREDENTIAL"), 2)
        self.assertNotIn(secret.decode(), report)

    def test_aws_json_secret_longer_than_forty_characters_is_not_matched(self) -> None:
        secret = b"0" * 41
        self.write("notes/aws-long.json", b'{"aws_secret_access_key":"' + secret + b'"}')
        result = self.check()
        self.assertEqual(result.returncode, 0, self.report(result))

    def test_benign_aws_documentation_and_placeholders_pass(self) -> None:
        self.write(
            "docs/aws.md",
            b"Set aws_secret_access_key to an environment variable.\n"
            b"Example: use an access-key environment variable, not a literal value.\n",
        )
        result = self.check()
        self.assertEqual(result.returncode, 0, self.report(result))

    def test_concrete_nintendo_key_assignment_is_detected(self) -> None:
        key_shape = b"0123456789abcdef" * 2
        self.write("notes/keys.txt", b"master_key_00 = " + key_shape + b"\n")
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_NINTENDO_KEY_ASSIGNMENT", report)
        self.assertNotIn(key_shape.decode(), report)

    def test_nintendo_placeholders_and_long_values_are_ignored(self) -> None:
        replacements = (
            b"master_key_00 = " + b"0" * 32 + b"\n",
            b"master_key_00 = " + b"0123456789abcdef" * 9 + b"\n",
        )
        for value in replacements:
            self.write("notes/keys.txt", value)
            result = self.check()
            self.assertEqual(result.returncode, 0, self.report(result))

    def test_nintendo_assignment_with_windows_newlines_is_detected(self) -> None:
        value = b"fedcba9876543210" * 2
        self.write("notes/keys-crlf.txt", b"titlekek = " + value + b"\r\n")
        result = self.check()
        self.assertEqual(result.returncode, 1, self.report(result))
        self.assertIn("WORKTREE_NINTENDO_KEY_ASSIGNMENT", self.report(result))

    def test_ignored_untracked_path_is_not_scanned(self) -> None:
        secret = b"ghp_" + b"S" * 40
        self.fixture.ignore("notes/ignored.txt", secret)
        result = self.check()
        self.assertEqual(result.returncode, 0, self.report(result))

    def test_symlink_is_rejected_without_reading_its_target(self) -> None:
        marker = b"OUTSIDE_TARGET_MARKER"
        outside = self.root.parent / f"nscb-policy-target-{os.getpid()}"
        outside.write_bytes(marker)
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        link = self.path("notes/link.txt")
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside)
        self.fixture.register_untracked_path("notes/link.txt")
        result = self.check()
        self.assertEqual(result.returncode, 2, self.report(result))
        self.assertIn("ERROR UNSAFE_FILE_TYPE", self.report(result))
        self.assertNotIn(marker.decode(), self.report(result))
        self.assertNotIn(str(outside), self.report(result))

    def test_special_file_is_rejected_without_blocking(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("named pipes are not available")
        fifo = self.path("notes/pipe")
        fifo.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(fifo)
        self.fixture.register_untracked_path("notes/pipe")
        result = self.check()
        self.assertEqual(result.returncode, 2, self.report(result))
        self.assertIn("ERROR UNSAFE_FILE_TYPE", self.report(result))

    def test_staged_deletion_and_worktree_untracked_copy_are_both_checked(self) -> None:
        data = b"\x00registered fixture"
        relative_path = "tests/fixtures/sample.bin"
        self.stage(relative_path, data)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, data)]))
        self.stage(REGISTRY_PATH)
        self.fixture.unstage(relative_path)
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_FIXTURE_MISSING", report)
        self.assertIn("WORKTREE_FIXTURE_UNTRACKED", report)

    def test_unstaged_deletion_still_scans_index_blob(self) -> None:
        data = b"\x00registered fixture"
        relative_path = "tests/fixtures/sample.bin"
        self.stage(relative_path, data)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, data)]))
        self.stage(REGISTRY_PATH)
        self.fixture.delete(relative_path)
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_FIXTURE_MISSING", report)
        self.assertNotIn("INDEX_FIXTURE_HASH_MISMATCH", report)

    def test_unmerged_index_conflicts_fail_before_blob_scanning(self) -> None:
        self.fixture.conflict("notes/conflict.txt")
        result = self.check()
        self.assertEqual(result.returncode, 2, self.report(result))
        self.assertIn("ERROR INDEX_CONFLICT", self.report(result))

    def test_mixed_sha1_and_sha256_index_objects_are_read_by_id(self) -> None:
        sha1_id = self.stage("notes/sha1.txt", b"sha1 content", algorithm="sha1")
        sha256_id = self.stage("notes/sha256.txt", b"sha256 content", algorithm="sha256")
        self.assertRegex(sha1_id, r"^[0-9a-f]{40}$")
        self.assertRegex(sha256_id, r"^[0-9a-f]{64}$")
        result = self.check()
        self.assertEqual(result.returncode, 0, self.report(result))

    def test_fixture_rejects_unsupported_git_commands(self) -> None:
        with self.assertRaises(UnsupportedGitCommand):
            self.fixture.command_output(["status", "--short"])

    def test_file_size_limit_fails_closed_with_sanitized_diagnostic(self) -> None:
        self.fixture.mark_untracked("notes/too-large.txt", b"1" * 65)
        with patch.object(content_policy, "MAX_FILE_BYTES", 64):
            result = self.check()
        self.assertEqual(result.returncode, 2, self.report(result))
        self.assertIn("ERROR RESOURCE_LIMIT", self.report(result))
        self.assertIn('"notes/too-large.txt"', self.report(result))
        self.assertNotIn("1" * 65, self.report(result))

    def test_invalid_repository_roots_fail_without_echoing_paths(self) -> None:
        file_root = self.path("not-a-repository")
        file_root.write_bytes(b"not a directory\n")
        missing_root = self.path("missing-root")
        for root in (file_root, missing_root):
            with self.subTest(root=root.name):
                result = self.check(root=root)
                self.assertEqual(result.returncode, 2, self.report(result))
                self.assertIn("ERROR ROOT_NOT_REPOSITORY", self.report(result))
                self.assertNotIn(str(root), self.report(result))

    def test_invalid_registry_json_is_a_finding_not_checker_failure(self) -> None:
        self.stage(REGISTRY_PATH, b"{")
        result = self.check()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_REGISTRY_INVALID", report)
        self.assertIn("WORKTREE_REGISTRY_INVALID", report)

    def test_symlink_loop_roots_fail_with_sanitized_errors(self) -> None:
        first = self.path("loop-a")
        second = self.path("loop-b")
        first.symlink_to(second)
        second.symlink_to(first)
        result = self.check(root=first)
        self.assertEqual(result.returncode, 2, self.report(result))
        self.assertIn("ERROR ROOT_NOT_REPOSITORY", self.report(result))
        self.assertNotIn(str(first), self.report(result))

    def test_findings_are_deterministic_bounded_and_redacted(self) -> None:
        secret = b"ghp_" + b"T" * 40
        for index in range(4):
            self.write(f"notes/{secret.decode()}/.env.{index}", b"benign\n")
        with patch.object(content_policy, "MAX_FINDINGS", 2):
            first = self.check()
            second = self.check()
        self.assertEqual(first, second)
        report = self.report(first)
        self.assertEqual(first.returncode, 1, report)
        self.assertEqual(report.count("WORKTREE_PROHIBITED_FILENAME"), 2)
        self.assertIn("FINDINGS_TRUNCATED omitted=2", report)
        self.assertIn("[redacted]", report)
        self.assertNotIn(secret.decode(), report)
        self.assertNotIn(str(self.root), report)


class GitCommandRunnerTests(unittest.TestCase):
    """Exercise the real bounded subprocess runner with controlled executables."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-runner-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        self.root = Path(self.temporary_directory.name)
        self.binary_directory = self.root / "bin"
        self.binary_directory.mkdir()
        self.guard = RoutineGitGuard([self.root])
        self.guard.start()

    def tearDown(self) -> None:
        self.guard.stop()
        self.temporary_directory.cleanup()

    def _install_fake_git(self, **options: object) -> None:
        write_fake_git_script(self.binary_directory / "git", **options)

    def _run(self, *, max_output_bytes: int = 1024, timeout_seconds: float = 2.0) -> bytes:
        environment = os.environ.copy()
        environment["PATH"] = (
            str(self.binary_directory) + os.pathsep + environment.get("PATH", "")
        )
        with patch.dict(os.environ, environment, clear=True):
            return _run_git_command(
                self.root,
                ["ls-files"],
                max_output_bytes=max_output_bytes,
                timeout_seconds=timeout_seconds,
            )

    def test_output_limit_fails_without_echoing_bytes(self) -> None:
        self._install_fake_git(stdout=b"0123456789")
        with self.assertRaises(CheckerFailure) as raised:
            self._run(max_output_bytes=4)
        self.assertEqual(raised.exception.code, "GIT_OUTPUT_LIMIT")
        self.assertIsNone(raised.exception.path)

    def test_successful_stderr_fails_closed_without_echoing_it(self) -> None:
        self._install_fake_git(stderr=b"sensitive warning")
        with self.assertRaises(CheckerFailure) as raised:
            self._run()
        self.assertEqual(raised.exception.code, "GIT_COMMAND_WARNING")

    def test_nonzero_exit_uses_caller_code(self) -> None:
        self._install_fake_git(exit_code=3)
        environment = os.environ.copy()
        environment["PATH"] = (
            str(self.binary_directory) + os.pathsep + environment.get("PATH", "")
        )
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaises(CheckerFailure) as raised:
                _run_git_command(
                    self.root,
                    ["ls-files"],
                    nonzero_exit_code="CUSTOM_FAILURE",
                )
        self.assertEqual(raised.exception.code, "CUSTOM_FAILURE")

    def test_timeout_kills_the_command(self) -> None:
        self._install_fake_git(delay_seconds=0.5)
        started = time.monotonic()
        with self.assertRaises(CheckerFailure) as raised:
            self._run(timeout_seconds=0.02)
        self.assertEqual(raised.exception.code, "GIT_COMMAND_TIMEOUT")
        self.assertLess(time.monotonic() - started, 0.4)

    def test_hardening_environment_flags_are_always_set(self) -> None:
        self._install_fake_git(include_environment=True)
        self.assertEqual(self._run(), b"1\n1")

    def test_missing_git_executable_fails_closed(self) -> None:
        environment = os.environ.copy()
        environment["PATH"] = str(self.binary_directory)
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaises(CheckerFailure) as raised:
                _run_git_command(self.root, ["ls-files"])
        self.assertEqual(raised.exception.code, "GIT_COMMAND_FAILED")

    def test_invalid_resource_bounds_fail_before_starting_process(self) -> None:
        with self.assertRaises(CheckerFailure) as negative:
            _run_git_command(self.root, ["ls-files"], max_output_bytes=-1)
        self.assertEqual(negative.exception.code, "GIT_OUTPUT_LIMIT")
        with self.assertRaises(CheckerFailure) as timeout:
            _run_git_command(self.root, ["ls-files"], timeout_seconds=0)
        self.assertEqual(timeout.exception.code, "GIT_COMMAND_TIMEOUT")


class ContentPolicyCliTests(ContentPolicyTestCase):
    """Smoke-test the real command-line boundary with a controlled fake Git."""

    def setUp(self) -> None:
        super().setUp()
        self.state_path = self.root / ".test-git-state.json"
        self.binary_directory = self.root / "fake-bin"
        self.binary_directory.mkdir()
        script = self.binary_directory / "git"
        script.write_text(
            "\n".join(
                [
                    f"#!{sys.executable}",
                    "import json",
                    "import os",
                    "import sys",
                    "from pathlib import Path",
                    "sys.path.insert(0, os.environ['NSCB_CONTENT_POLICY_TEST_SUPPORT'])",
                    "from content_policy_test_support import InMemoryGitFixture",
                    "if len(sys.argv) < 4 or sys.argv[1] != '-C':",
                    "    raise SystemExit(64)",
                    "state = json.loads(Path(os.environ['NSCB_FAKE_GIT_STATE']).read_text())",
                    "fixture = InMemoryGitFixture.from_state(state)",
                    "if Path(os.path.realpath(sys.argv[2])) != fixture.root:",
                    "    raise SystemExit(65)",
                    "sys.stdout.buffer.write(fixture.command_output(sys.argv[3:]))",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        script.chmod(0o755)

    def run_cli(self) -> subprocess.CompletedProcess[bytes]:
        self.state_path.write_text(json.dumps(self.fixture.export_state()))
        environment = os.environ.copy()
        environment["PATH"] = (
            str(self.binary_directory) + os.pathsep + environment.get("PATH", "")
        )
        environment["NSCB_FAKE_GIT_STATE"] = str(self.state_path)
        environment["NSCB_CONTENT_POLICY_TEST_SUPPORT"] = str(REPOSITORY_ROOT / "tests")
        return subprocess.run(
            [sys.executable, str(CHECKER), "--root", str(self.root)],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_cli_passes_then_reports_redacted_staged_secret(self) -> None:
        passing = self.run_cli()
        self.assertEqual(passing.returncode, 0, self.report(passing))
        token = b"ghp_" + b"U" * 40
        self.stage("notes/staged-secret.txt", token)
        failing = self.run_cli()
        report = self.report(failing)
        self.assertEqual(failing.returncode, 1, report)
        self.assertIn("INDEX_GITHUB_CREDENTIAL", report)
        self.assertNotIn(token.decode(), report)
        self.assertNotIn(str(self.root), report)
        self.assertFalse((self.root / ".git").exists())

    def test_cli_maps_unmerged_index_to_checker_failure(self) -> None:
        self.fixture.conflict("notes/conflict.txt")
        result = self.run_cli()
        self.assertEqual(result.returncode, 2, self.report(result))
        self.assertIn("ERROR INDEX_CONFLICT", self.report(result))


if __name__ == "__main__":
    unittest.main()
