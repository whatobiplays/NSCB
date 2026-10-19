"""Genuine Git integration tests for repository content-policy enforcement.

This suite is intentionally separate from routine validation because it creates
short-lived repositories and exercises real Git index, replacement, and conflict
behavior. It is a required hosted-CI gate and never runs from ``make test`` or
``make all``.
"""

from __future__ import annotations

import errno
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_TEMP_DIRECTORY_BASE = Path(os.path.realpath(tempfile.gettempdir()))
CHECKER = REPOSITORY_ROOT / "scripts" / "check_content_policy.py"
REGISTRY_PATH = "tests/fixtures/registry.json"
_DIAGNOSTIC_SECRET = re.compile(
    r"(?i)(?:gh[pousr]_[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{12,}|[0-9a-f]{32,})"
)


def registry_document(fixtures: list[dict[str, object]] | None = None) -> bytes:
    """Return a valid version-one registry document."""
    return (
        json.dumps({"schema_version": 1, "fixtures": fixtures or []}, indent=2) + "\n"
    ).encode()


def synthetic_entry(path: str, data: bytes) -> dict[str, object]:
    """Describe deterministic synthetic fixture bytes."""
    import hashlib

    return {
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "source": "Generated deterministically for Git integration tests",
        "provenance": {
            "kind": "synthetic",
            "generator": "tests/test_content_policy_git.py",
            "reproduction": "Run the integration test that creates the repository",
        },
        "license_basis": "Original synthetic bytes created for this test",
    }


def _safe_diagnostic_path(path: str) -> str:
    safe = _DIAGNOSTIC_SECRET.sub("[redacted]", path)
    return json.dumps(safe[:160], ensure_ascii=True)


def _cleanup_inventory(
    root: Path, *, max_entries: int = 8, max_depth: int = 3
) -> dict[str, object]:
    """Return a bounded, content-free inventory for cleanup diagnostics."""
    _reject_symlink_cleanup_root(root)
    entries: list[dict[str, str]] = []
    complete = True

    def visit(directory: Path, depth: int) -> None:
        nonlocal complete
        try:
            children = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError:
            complete = False
            return
        for child in children:
            if len(entries) >= max_entries:
                complete = False
                return
            relative = child.path[len(str(root)) + 1 :]
            try:
                is_directory = child.is_dir(follow_symlinks=False)
                is_symlink = child.is_symlink()
            except OSError:
                complete = False
                is_directory = False
                is_symlink = False
            kind = "symlink" if is_symlink else "directory" if is_directory else "file"
            entries.append({"path": _safe_diagnostic_path(relative), "kind": kind})
            if is_directory:
                if depth >= max_depth:
                    complete = False
                else:
                    visit(Path(child.path), depth + 1)

    visit(root, 0)
    return {"complete": complete, "entries": entries}


def _reject_symlink_cleanup_root(root: Path) -> None:
    """Reject a cleanup root reached through any symbolic-link component."""
    absolute = Path(os.path.abspath(root))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current = current / component
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise OSError(
                errno.ELOOP,
                "cleanup root has a symbolic-link ancestor",
                str(current),
            )


def _cleanup_with_diagnostic(root: Path, diagnostic_path: Path) -> bool:
    """Remove a repository, writing only bounded sanitized metadata on failure."""
    _reject_symlink_cleanup_root(root)
    last_error: OSError | None = None
    for attempt in range(3):
        try:
            shutil.rmtree(root)
            return True
        except OSError as error:
            last_error = error
            if error.errno not in {errno.EBUSY, errno.EEXIST, errno.ENOTEMPTY} or attempt == 2:
                break
    diagnostic = {
        "error": errno.errorcode.get((last_error.errno if last_error else 0) or 0, "OSError"),
        "inventory": _cleanup_inventory(root),
    }
    diagnostic_path.write_text(json.dumps(diagnostic), encoding="utf-8")
    return False


class RealGitContentPolicyTests(unittest.TestCase):
    """Exercise production Git inspection against actual repository state."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="nscb-policy-git-", dir=CANONICAL_TEMP_DIRECTORY_BASE))
        self.write("README.md", b"A real Git repository used by integration tests.\n")
        self.write(REGISTRY_PATH, registry_document())
        self.git("init", "--quiet")
        self.git("add", "--all")
        self.commit("baseline")

    def tearDown(self) -> None:
        descriptor, diagnostic_name = tempfile.mkstemp(
            prefix="nscb-policy-cleanup-", suffix=".json"
        )
        os.close(descriptor)
        diagnostic = Path(diagnostic_name)
        try:
            if not _cleanup_with_diagnostic(self.root, diagnostic):
                metadata = json.loads(diagnostic.read_text(encoding="utf-8"))
                self.fail(f"repository cleanup failed with sanitized metadata {metadata}")
        finally:
            diagnostic.unlink(missing_ok=True)

    def path(self, relative_path: str) -> Path:
        return self.root / relative_path

    def write(self, relative_path: str, data: bytes) -> Path:
        path = self.path(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def git(self, *arguments: str, input_bytes: bytes | None = None) -> bytes:
        environment = os.environ.copy()
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        environment["GIT_CONFIG_GLOBAL"] = os.devnull
        result = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(f"git {arguments[0]} failed while preparing integration fixture")
        return result.stdout

    def commit(self, message: str) -> None:
        self.git(
            "-c",
            "user.name=Policy Test",
            "-c",
            "user.email=policy-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            message,
        )

    def run_checker(self) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [sys.executable, str(CHECKER), "--root", str(self.root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    @staticmethod
    def report(result: subprocess.CompletedProcess[bytes]) -> str:
        return (result.stdout + result.stderr).decode("utf-8", errors="replace")

    def test_initialization_staging_and_commit_pass(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, self.report(result))
        self.assertTrue((self.root / ".git").is_dir())

    def test_staged_secret_survives_benign_worktree_replacement(self) -> None:
        token = b"ghp_" + b"V" * 40
        marker = b"STAGED_SECRET_MARKER"
        relative_path = "notes/credential-sample.txt"
        binary_path = "notes/staged-only.data"
        self.write(relative_path, token + b" " + marker)
        self.write(binary_path, b"\x00staged binary marker")
        self.git("add", relative_path)
        self.git("add", binary_path)
        self.write(relative_path, b"benign working-tree replacement\n")
        self.write(binary_path, b"benign working-tree text\n")
        result = self.run_checker()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_GITHUB_CREDENTIAL", report)
        self.assertIn("INDEX_BINARY_UNREGISTERED", report)
        self.assertNotIn("WORKTREE_GITHUB_CREDENTIAL", report)
        self.assertNotIn("WORKTREE_BINARY_UNREGISTERED", report)
        self.assertNotIn(token.decode(), report)
        self.assertNotIn(marker.decode(), report)
        self.assertNotIn("staged binary marker", report)
        self.assertNotIn(str(self.root), report)

    def test_tracked_untracked_and_ignored_paths_are_distinguished(self) -> None:
        self.write("notes/tracked.txt", b"tracked benign text\n")
        self.git("add", "notes/tracked.txt")
        self.write("notes/untracked.bin", b"\x00untracked")
        self.write("notes/ignored.bin", b"\x00ignored")
        self.write(".gitignore", b"notes/ignored.bin\n")
        self.git("add", ".gitignore")
        result = self.run_checker()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn('WORKTREE_BINARY_UNREGISTERED path="notes/untracked.bin"', report)
        self.assertNotIn("notes/ignored.bin", report)
        self.assertNotIn("notes/tracked.txt", report)

    def test_staged_deletion_and_worktree_untracked_copy_are_both_checked(self) -> None:
        data = b"\x00registered fixture"
        relative_path = "tests/fixtures/sample.bin"
        self.write(relative_path, data)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, data)]))
        self.git("add", "--all")
        self.commit("fixture")
        self.git("rm", "--cached", "--quiet", relative_path)
        result = self.run_checker()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_FIXTURE_MISSING", report)
        self.assertIn("WORKTREE_FIXTURE_UNTRACKED", report)

    def test_unstaged_deletion_still_scans_index_blob(self) -> None:
        data = b"\x00registered fixture"
        relative_path = "tests/fixtures/sample.bin"
        self.write(relative_path, data)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, data)]))
        self.git("add", "--all")
        self.commit("fixture")
        self.path(relative_path).unlink()
        result = self.run_checker()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_FIXTURE_MISSING", report)
        self.assertNotIn("INDEX_FIXTURE_HASH_MISMATCH", report)

    def test_index_and_worktree_registries_are_independent(self) -> None:
        original = b"\x00original bytes"
        updated = b"\x00updated bytes"
        relative_path = "tests/fixtures/sample.bin"
        self.write(relative_path, updated)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, updated)]))
        self.git("add", relative_path, REGISTRY_PATH)
        self.write(relative_path, original)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, original)]))
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, self.report(result))

        self.git("update-index", "--force-remove", relative_path, REGISTRY_PATH)
        self.path(relative_path).unlink()
        self.write(REGISTRY_PATH, registry_document())
        untracked_registry = self.run_checker()
        untracked_report = self.report(untracked_registry)
        self.assertEqual(untracked_registry.returncode, 0, untracked_report)
        self.assertNotIn("WORKTREE_REGISTRY_MISSING", untracked_report)

    def test_unmerged_index_stages_fail_before_blob_scanning(self) -> None:
        relative_path = "notes/conflict.txt"
        self.write(relative_path, b"base\n")
        self.git("add", relative_path)
        self.commit("conflict base")
        self.git("update-index", "--force-remove", relative_path)
        object_ids = [
            self.git(
                "hash-object",
                "-w",
                "--stdin",
                input_bytes=f"stage {stage}\n".encode(),
            )
            .decode("ascii")
            .strip()
            for stage in (1, 2, 3)
        ]
        index_info = b"".join(
            f"100644 {object_id} {stage}\t{relative_path}\0".encode()
            for stage, object_id in enumerate(object_ids, start=1)
        )
        self.git("update-index", "-z", "--index-info", input_bytes=index_info)
        result = self.run_checker()
        self.assertEqual(result.returncode, 2, self.report(result))
        self.assertIn("ERROR INDEX_CONFLICT", self.report(result))

    def test_git_replace_cannot_redirect_index_blob_inspection(self) -> None:
        token = b"ghp_" + b"W" * 40
        relative_path = "notes/replaced-credential.txt"
        self.write(relative_path, token + b" staged secret marker")
        self.git("add", relative_path)
        index_record = self.git("ls-files", "--stage", "-z", "--", relative_path)
        original_id = index_record.split(b"\t", 1)[0].split()[1].decode("ascii")
        replacement_id = (
            self.git("hash-object", "-w", "--stdin", input_bytes=b"benign replacement\n")
            .decode("ascii")
            .strip()
        )
        self.git("replace", original_id, replacement_id)
        self.write(relative_path, b"benign working-tree content\n")
        result = self.run_checker()
        report = self.report(result)
        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_GITHUB_CREDENTIAL", report)
        self.assertNotIn("WORKTREE_GITHUB_CREDENTIAL", report)
        self.assertNotIn(token.decode(), report)

    def test_cleanup_inventory_never_follows_symlinks_or_reads_content(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nscb-cleanup-inventory-",
            dir=CANONICAL_TEMP_DIRECTORY_BASE,
        ) as directory:
            root = Path(directory)
            target = root / "outside-secret.txt"
            target.write_bytes(b"OUTSIDE_SECRET_CONTENT")
            link = root / "external-link"
            link.symlink_to(target)
            inventory = _cleanup_inventory(root)
            rendered = json.dumps(inventory)
            self.assertIn('"kind": "symlink"', rendered)
            self.assertNotIn("OUTSIDE_SECRET_CONTENT", rendered)
            self.assertNotIn(str(root), rendered)

            outside_root = root / "outside-root"
            outside_root.mkdir()
            linked_ancestor = root / "linked-ancestor"
            linked_ancestor.symlink_to(outside_root, target_is_directory=True)
            linked_root = linked_ancestor / "root"
            (outside_root / "root").mkdir()
            with patch("os.scandir") as scandir:
                with self.assertRaises(OSError):
                    _cleanup_with_diagnostic(linked_root, root / "diagnostic.json")
                scandir.assert_not_called()

    def test_cleanup_inventory_caps_depth_and_redacts_paths(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nscb-cleanup-inventory-",
            dir=CANONICAL_TEMP_DIRECTORY_BASE,
        ) as directory:
            root = Path(directory)
            secret = "ghp_" + "X" * 40
            deep = root / secret / "one" / "two" / "three"
            deep.mkdir(parents=True)
            inventory = _cleanup_inventory(root, max_entries=4, max_depth=1)
            rendered = json.dumps(inventory)
            self.assertFalse(inventory["complete"])
            self.assertIn("[redacted]", rendered)
            self.assertNotIn(secret, rendered)
            self.assertLessEqual(len(inventory["entries"]), 4)

    def test_cleanup_failure_emits_only_sanitized_metadata(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nscb-cleanup-inventory-",
            dir=CANONICAL_TEMP_DIRECTORY_BASE,
        ) as directory:
            root = Path(directory)
            secret = "ghp_" + "Y" * 40
            artifact = root / secret / "failed-object"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"DO_NOT_ECHO_CLEANUP_CONTENT")
            descriptor, diagnostic_name = tempfile.mkstemp(
                prefix="nscb-cleanup-", suffix=".json"
            )
            os.close(descriptor)
            diagnostic = Path(diagnostic_name)
            try:
                with patch(
                    "shutil.rmtree",
                    side_effect=OSError(errno.ENOTEMPTY, "not empty"),
                ):
                    succeeded = _cleanup_with_diagnostic(root, diagnostic)
                self.assertFalse(succeeded)
                metadata = diagnostic.read_text(encoding="utf-8")
                self.assertIn('"error": "ENOTEMPTY"', metadata)
                self.assertIn("[redacted]", metadata)
                self.assertNotIn(secret, metadata)
                self.assertNotIn("DO_NOT_ECHO_CLEANUP_CONTENT", metadata)
                self.assertNotIn(str(root), metadata)
            finally:
                diagnostic.unlink(missing_ok=True)

    def test_cleanup_retries_transient_failure_before_reporting(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nscb-cleanup-inventory-",
            dir=CANONICAL_TEMP_DIRECTORY_BASE,
        ) as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            (root / "artifact").write_bytes(b"transient cleanup content")
            diagnostic = Path(directory) / "diagnostic.json"
            original_rmtree = shutil.rmtree
            calls = 0

            def flaky_rmtree(path: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise OSError(errno.ENOTEMPTY, "transient")
                original_rmtree(path)

            with patch("shutil.rmtree", side_effect=flaky_rmtree):
                self.assertTrue(_cleanup_with_diagnostic(root, diagnostic))
            self.assertEqual(calls, 2)
            self.assertFalse(root.exists())
            self.assertFalse(diagnostic.exists())


if __name__ == "__main__":
    unittest.main()
