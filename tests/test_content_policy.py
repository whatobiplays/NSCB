"""Behavioral tests for the repository content-policy command."""

from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from collections import deque
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
# Canonicalize the platform temp base before creating roots; supplied roots remain unresolved.
CANONICAL_TEMP_DIRECTORY_BASE = Path(os.path.realpath(tempfile.gettempdir()))
CHECKER = REPOSITORY_ROOT / "scripts" / "check_content_policy.py"
REGISTRY_PATH = "tests/fixtures/registry.json"
sys.path.insert(0, str(CHECKER.parent))
from check_content_policy import CheckerFailure, ContentPolicyChecker, MAX_FINDINGS
from git_ai_isolation import (
    ISOLATION_ENVIRONMENT_VALUE,
    ISOLATION_ENVIRONMENT_VARIABLE,
)


_CLEANUP_ENTRY_LIMIT = 128
_CLEANUP_DEPTH_LIMIT = 8
_CLEANUP_PATH_LIMIT = 160
_CLEANUP_ARTIFACT_LIMIT = 64 * 1024
_CLEANUP_ARTIFACT_EVENT_LIMIT = 4
_CLEANUP_SECRET_PATH = re.compile(
    r"(?i)(?:gh[pousr]_[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{12,}|sk-[A-Za-z0-9_-]{12,})"
)
_CLEANUP_DIAGNOSTICS: list[dict[str, object]] = []
_CLEANUP_DIAGNOSTICS_TRUNCATED = False


def _directory_flags() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise OSError(errno.ENOTSUP, "safe directory diagnostics are unavailable")
    return os.O_RDONLY | no_follow | directory | getattr(os, "O_CLOEXEC", 0)


def _open_absolute_directory(path: Path) -> int:
    """Open a directory by walking every absolute path component without following links."""
    raw_path = os.fspath(path)
    if not os.path.isabs(raw_path):
        raise OSError(errno.EINVAL, "diagnostic root must be absolute")
    components = raw_path.split(os.sep)
    if any(component in {".", ".."} for component in components):
        raise OSError(errno.EINVAL, "diagnostic root has an unsafe component")

    flags = _directory_flags()
    current_fd = os.open(os.sep, flags)
    try:
        for component in components:
            if component:
                next_fd = os.open(component, flags, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _open_cleanup_root(path: Path) -> int:
    """Open a supplied root without resolving or following any path component."""
    return _open_absolute_directory(path)


def _open_relative_directory(root_fd: int, relative_path: str) -> int:
    """Open a directory beneath an anchored root without following any component."""
    components = [] if relative_path in {"", "."} else relative_path.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise OSError(errno.EINVAL, "diagnostic path has an unsafe component")

    flags = _directory_flags()
    current_fd = os.dup(root_fd)
    try:
        for component in components:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _safe_diagnostic_path(relative_path: str) -> str:
    """Keep diagnostic names relative, printable, bounded, and credential-redacted."""
    printable = "".join(character if character.isprintable() else "?" for character in relative_path)
    redacted = _CLEANUP_SECRET_PATH.sub("<redacted>", printable)
    if len(redacted) > _CLEANUP_PATH_LIMIT:
        return redacted[: _CLEANUP_PATH_LIMIT - 3] + "..."
    return redacted


def _entry_type(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    return "other"


def _cleanup_inventory(
    root_fd: int, started_ns: int, priority_path: str | None = None
) -> dict[str, object]:
    """Capture bounded, descriptor-anchored metadata without following links or reading files."""
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    pending: deque[tuple[str, int, int]] = deque()
    scanned = 0
    read_errors = 0
    truncated = False
    priority_status = "not-requested"

    def record(parent_fd: int, name: str, relative: str) -> os.stat_result | None:
        nonlocal scanned, read_errors
        if scanned >= _CLEANUP_ENTRY_LIMIT:
            return None
        scanned += 1
        try:
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            read_errors += 1
            return None
        safe_path = _safe_diagnostic_path(relative)
        if relative not in seen:
            seen.add(relative)
            item: dict[str, object] = {
                "path": safe_path,
                "type": _entry_type(metadata.st_mode),
                "inode": metadata.st_ino,
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
            }
            if stat.S_ISREG(metadata.st_mode):
                item["size_bytes"] = metadata.st_size
            entries.append(item)
        return metadata

    def scan_children(directory_fd: int, base: str) -> None:
        nonlocal read_errors, truncated
        try:
            with os.scandir(directory_fd) as children:
                for child in children:
                    if scanned >= _CLEANUP_ENTRY_LIMIT:
                        truncated = True
                        break
                    relative = f"{base}/{child.name}" if base else child.name
                    record(directory_fd, child.name, relative)
        except OSError:
            read_errors += 1

    if priority_path is not None:
        try:
            components = [] if priority_path in {"", "."} else priority_path.split("/")
            if any(component in {"", ".", ".."} for component in components):
                raise OSError(errno.EINVAL, "unsafe failure path")
            if len(components) > _CLEANUP_DEPTH_LIMIT:
                priority_status = "depth-limit"
                truncated = True
            elif not components:
                target_fd = os.dup(root_fd)
                priority_status = "captured"
                scan_children(target_fd, "")
                os.close(target_fd)
            else:
                parent_path = "/".join(components[:-1])
                parent_fd = _open_relative_directory(root_fd, parent_path)
                try:
                    leaf = components[-1]
                    metadata = record(parent_fd, leaf, priority_path)
                    if metadata is None or not stat.S_ISDIR(metadata.st_mode):
                        priority_status = "path-not-directory-or-unavailable"
                    elif len(components) >= _CLEANUP_DEPTH_LIMIT:
                        priority_status = "captured-depth-limit"
                        truncated = True
                    else:
                        target_fd = os.open(leaf, _directory_flags(), dir_fd=parent_fd)
                        try:
                            priority_status = "captured"
                            scan_children(target_fd, priority_path)
                        finally:
                            os.close(target_fd)
                finally:
                    os.close(parent_fd)
        except OSError:
            priority_status = "unsafe-or-unavailable"
            read_errors += 1

    root_copy = os.dup(root_fd)
    pending.append(("", root_copy, 0))
    visited_directories: set[str] = {""}
    try:
        while pending:
            base, directory_fd, depth = pending.popleft()
            try:
                with os.scandir(directory_fd) as children:
                    for child in children:
                        if scanned >= _CLEANUP_ENTRY_LIMIT:
                            truncated = True
                            break
                        relative = f"{base}/{child.name}" if base else child.name
                        metadata = record(directory_fd, child.name, relative)
                        if metadata is not None and stat.S_ISDIR(metadata.st_mode):
                            child_depth = depth + 1
                            if child_depth >= _CLEANUP_DEPTH_LIMIT:
                                truncated = True
                                continue
                            if relative in visited_directories:
                                continue
                            visited_directories.add(relative)
                            try:
                                child_fd = os.open(
                                    child.name, _directory_flags(), dir_fd=directory_fd
                                )
                            except OSError:
                                read_errors += 1
                            else:
                                pending.append((relative, child_fd, depth + 1))
            except OSError:
                read_errors += 1
            finally:
                os.close(directory_fd)
            if scanned >= _CLEANUP_ENTRY_LIMIT:
                truncated = truncated or bool(pending)
                break
    finally:
        while pending:
            _, directory_fd, _ = pending.popleft()
            os.close(directory_fd)

    return {
        "safe": True,
        "entries": entries,
        "truncated": truncated,
        "read_error_count": read_errors,
        "priority_path_status": priority_status,
        "elapsed_ms": max(0, (time.monotonic_ns() - started_ns) // 1_000_000),
    }


def _failed_relative_path(root: Path, failure: OSError) -> str | None:
    """Return a lexical path beneath root without resolving any filesystem links."""
    filename = failure.filename if failure.filename is not None else failure.filename2
    if filename is None:
        return None
    raw_path = os.fsdecode(filename) if isinstance(filename, bytes) else os.fspath(filename)
    if not os.path.isabs(raw_path):
        return None
    root_path = os.path.abspath(os.fspath(root))
    candidate = os.path.abspath(raw_path)
    try:
        relative = os.path.relpath(candidate, root_path)
    except ValueError:
        return None
    if relative == os.pardir or relative.startswith(os.pardir + os.sep) or os.path.isabs(relative):
        return None
    return relative.replace(os.sep, "/")


def _write_all(file_descriptor: int, contents: bytes) -> None:
    offset = 0
    while offset < len(contents):
        written = os.write(file_descriptor, contents[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "diagnostic artifact write made no progress")
        offset += written


def _write_cleanup_artifact(document: dict[str, object]) -> None:
    """Atomically write bounded JSON beneath the primary checkout's ignored review area."""
    root_fd = _open_cleanup_root(REPOSITORY_ROOT)
    directory_fd = root_fd
    temporary_name: str | None = None
    replaced = False
    try:
        flags = _directory_flags()
        for component in (".chatgpt", "reviews", "issue-4-cleanup-diagnosis"):
            try:
                os.mkdir(component, mode=0o700, dir_fd=directory_fd)
            except FileExistsError:
                pass
            next_fd = os.open(component, flags, dir_fd=directory_fd)
            if directory_fd != root_fd:
                os.close(directory_fd)
            directory_fd = next_fd

        contents = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(contents) > _CLEANUP_ARTIFACT_LIMIT:
            raise OSError(errno.EFBIG, "cleanup diagnostic artifact exceeds its size limit")
        temporary_name = f".cleanup-diagnosis-{time.monotonic_ns()}.tmp"
        artifact_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            _write_all(artifact_fd, contents)
            os.fsync(artifact_fd)
        finally:
            os.close(artifact_fd)
        os.replace(
            temporary_name,
            "cleanup-diagnosis.json",
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        replaced = True
    finally:
        if temporary_name is not None and not replaced:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
        if directory_fd != root_fd:
            os.close(directory_fd)
        os.close(root_fd)


def _record_cleanup_diagnostic(event: dict[str, object]) -> None:
    global _CLEANUP_DIAGNOSTICS_TRUNCATED
    _CLEANUP_DIAGNOSTICS.append(event)
    if len(_CLEANUP_DIAGNOSTICS) > _CLEANUP_ARTIFACT_EVENT_LIMIT:
        del _CLEANUP_DIAGNOSTICS[0]
        _CLEANUP_DIAGNOSTICS_TRUNCATED = True
    document: dict[str, object] = {
        "schema_version": 1,
        "truncated": _CLEANUP_DIAGNOSTICS_TRUNCATED,
        "diagnostics": _CLEANUP_DIAGNOSTICS,
    }
    try:
        sys.stderr.write(
            "NSCB_CLEANUP_DIAGNOSTIC "
            + json.dumps(event, separators=(",", ":"), sort_keys=True)
            + "\n"
        )
    except Exception:
        pass
    try:
        _write_cleanup_artifact(document)
    except Exception:
        pass


def _await_git_ai_before_metadata_cleanup(
    temporary_directory: tempfile.TemporaryDirectory[str], root: Path
) -> str:
    """Best-effort daemon drain before pruning a disposable Git repository.

    The beta await command drains existing daemon work, but does not prevent
    new work from arriving after it returns. Its absence or failure cannot
    replace the existing strict cleanup and one-retry boundary.
    """
    if (
        not isinstance(temporary_directory, tempfile.TemporaryDirectory)
        or root != Path(temporary_directory.name)
        or root.parent != CANONICAL_TEMP_DIRECTORY_BASE
        or not root.name.startswith("nscb-policy-")
    ):
        return "not_applicable"

    if os.environ.get(ISOLATION_ENVIRONMENT_VARIABLE) == ISOLATION_ENVIRONMENT_VALUE:
        return "isolation_verified"

    executable = shutil.which("git-ai")
    if executable is None:
        return "not_installed"

    environment = os.environ.copy()
    # Git AI's beta await command otherwise starts a daemon when none exists.
    # Keep CI and local test teardown from changing global daemon state.
    environment["_GITAI_INTERNAL_DISABLE_WRAPPER_DAEMON_AUTOSPAWN"] = "1"
    environment.pop("GIT_AI", None)
    try:
        result = subprocess.run(
            [executable, "await", "--timeout", "5"],
            cwd=CANONICAL_TEMP_DIRECTORY_BASE,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "process_timeout"
    except OSError:
        return "unavailable"
    return "drained" if result.returncode == 0 else "not_drained"


def _remove_disposable_git_ai_metadata(
    temporary_directory: tempfile.TemporaryDirectory[str], root: Path
) -> bool:
    """Prune Git AI artifacts only inside our own disposable policy-test repository."""
    if (
        not isinstance(temporary_directory, tempfile.TemporaryDirectory)
        or root != Path(temporary_directory.name)
        or root.parent != CANONICAL_TEMP_DIRECTORY_BASE
        or not root.name.startswith("nscb-policy-")
    ):
        return False

    try:
        root_fd = _open_cleanup_root(root)
    except FileNotFoundError:
        return False
    try:
        try:
            git_fd = _open_relative_directory(root_fd, ".git")
        except FileNotFoundError:
            return False
        try:
            removed = False
            for refs_path in ("refs", "logs/refs"):
                try:
                    refs_fd = _open_relative_directory(git_fd, refs_path)
                except FileNotFoundError:
                    continue
                try:
                    try:
                        notes_fd = os.open("notes", _directory_flags(), dir_fd=refs_fd)
                    except FileNotFoundError:
                        continue
                    try:
                        try:
                            metadata = os.stat(
                                "ai", dir_fd=notes_fd, follow_symlinks=False
                            )
                        except FileNotFoundError:
                            pass
                        else:
                            if not stat.S_ISREG(metadata.st_mode):
                                raise OSError(
                                    errno.EINVAL, "unexpected Git AI note-ref type"
                                )
                            try:
                                os.unlink("ai", dir_fd=notes_fd)
                            except FileNotFoundError:
                                pass
                            else:
                                removed = True
                    finally:
                        os.close(notes_fd)

                    # Also remove an empty notes directory left by a concurrent writer.
                    try:
                        os.rmdir("notes", dir_fd=refs_fd)
                    except FileNotFoundError:
                        pass
                    except OSError as failure:
                        if failure.errno != errno.ENOTEMPTY:
                            raise
                    else:
                        removed = True
                finally:
                    os.close(refs_fd)

            try:
                metadata = os.stat("ai", dir_fd=git_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISDIR(metadata.st_mode):
                    raise OSError(errno.EINVAL, "unexpected Git AI metadata type")
                if not shutil.rmtree.avoids_symlink_attacks:
                    raise OSError(errno.ENOTSUP, "symlink-safe cleanup unavailable")
                try:
                    shutil.rmtree("ai", dir_fd=git_fd)
                except FileNotFoundError:
                    pass
                else:
                    removed = True
            return removed
        finally:
            os.close(git_fd)
    finally:
        os.close(root_fd)


def _cleanup_with_diagnostics(
    temporary_directory: tempfile.TemporaryDirectory[str], root: Path, test_id: str
) -> None:
    """Preserve cleanup errors while capturing bounded metadata and phase timestamps."""
    started_ns = time.monotonic_ns()

    def phase_timestamp() -> dict[str, int]:
        return {
            "wallclock_unix_ns": time.time_ns(),
            "elapsed_ns": max(0, time.monotonic_ns() - started_ns),
        }

    timeline: dict[str, dict[str, int]] = {
        "snapshot_start": {
            "wallclock_unix_ns": time.time_ns(),
            "elapsed_ns": 0,
        }
    }
    try:
        root_fd = _open_cleanup_root(root)
    except BaseException:
        root_fd = None

    if root_fd is None:
        before: dict[str, object] = {
            "safe": False,
            "reason": "unsafe-or-unavailable-root",
            "entries": [],
            "truncated": False,
            "read_error_count": 0,
            "elapsed_ms": 0,
        }
    else:
        try:
            before = _cleanup_inventory(root_fd, started_ns)
        except BaseException:
            before = {
                "safe": True,
                "reason": "inventory-error",
                "entries": [],
                "truncated": False,
                "read_error_count": 1,
                "elapsed_ms": max(0, (time.monotonic_ns() - started_ns) // 1_000_000),
            }

    timeline["snapshot_end"] = phase_timestamp()
    # Let the shared Git AI daemon drain before the first attempt to remove the
    # temporary repository. This is only a point-in-time barrier, not a lock.
    git_ai_initial_await_status = _await_git_ai_before_metadata_cleanup(
        temporary_directory, root
    )
    timeline["cleanup_start"] = phase_timestamp()
    git_ai_await_status = "not_attempted"
    try:
        try:
            temporary_directory.cleanup()
        except OSError as failure:
            # A concurrent writer can repopulate .git after rmtree scans it.
            # Wait again before pruning its known artifacts; even a successful
            # await cannot guarantee that new background work never starts.
            if failure.errno != errno.ENOTEMPTY:
                raise
            git_ai_await_status = _await_git_ai_before_metadata_cleanup(
                temporary_directory, root
            )
            # Only a known Git AI artifact permits one cleanup retry.
            if not _remove_disposable_git_ai_metadata(temporary_directory, root):
                raise
            temporary_directory.cleanup()
    except OSError as failure:
        timeline["failure_end"] = phase_timestamp()
        try:
            failed_path = _failed_relative_path(root, failure)
            if root_fd is None:
                after: dict[str, object] = {
                    "safe": False,
                    "reason": "unsafe-or-unavailable-root",
                    "entries": [],
                    "truncated": False,
                    "read_error_count": 0,
                    "elapsed_ms": max(0, (time.monotonic_ns() - started_ns) // 1_000_000),
                }
            else:
                try:
                    after = _cleanup_inventory(root_fd, started_ns, failed_path)
                except Exception:
                    after = {
                        "safe": True,
                        "reason": "inventory-error",
                        "entries": [],
                        "truncated": False,
                        "read_error_count": 1,
                        "elapsed_ms": max(0, (time.monotonic_ns() - started_ns) // 1_000_000),
                    }
            _record_cleanup_diagnostic(
                {
                    "test_id": _safe_diagnostic_path(test_id),
                    "error": {
                        "errno": failure.errno,
                        "code": errno.errorcode.get(failure.errno, "UNKNOWN"),
                        "relative_path": (
                            _safe_diagnostic_path(failed_path) if failed_path is not None else None
                        ),
                    },
                    "before": before,
                    "after": after,
                    "timeline": timeline,
                    "inventory_comparison_complete": bool(
                        before.get("safe")
                        and after.get("safe")
                        and not before.get("truncated")
                        and not after.get("truncated")
                        and not before.get("read_error_count")
                        and not after.get("read_error_count")
                    ),
                    "git_ai_initial_await_status": git_ai_initial_await_status,
                    "git_ai_await_status": git_ai_await_status,
                    "process_observation": "not-collected; actor unknown",
                }
            )
        except BaseException:
            pass
        raise
    finally:
        if root_fd is not None:
            try:
                os.close(root_fd)
            except BaseException:
                pass


def registry_document(fixtures: list[dict[str, object]] | None = None) -> bytes:
    return (json.dumps({"schema_version": 1, "fixtures": fixtures or []}, indent=2) + "\n").encode()


def synthetic_entry(path: str, data: bytes) -> dict[str, object]:
    return {
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "source": "Generated deterministically for policy tests",
        "provenance": {
            "kind": "synthetic",
            "generator": "tests/test_content_policy.py",
            "reproduction": "Run the policy test that creates this temporary repository",
        },
        "license_basis": "Original synthetic bytes created for this test",
    }


def git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"git {arguments[0]} failed while preparing a test repository")
    return result.stdout


class ContentPolicyCommandTests(unittest.TestCase):
    """Exercise the checker against real Git indexes and isolated worktrees."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        self.root = Path(self.temporary_directory.name)
        git(self.root, "init", "--quiet")
        self.write("README.md", b"A temporary repository used by the content-policy tests.\n")
        self.write(REGISTRY_PATH, registry_document())
        git(self.root, "add", "--all")
        git(
            self.root,
            "-c",
            "user.name=Policy Test",
            "-c",
            "user.email=policy-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "test baseline",
        )

    def tearDown(self) -> None:
        _cleanup_with_diagnostics(self.temporary_directory, self.root, self.id())

    def write(self, relative_path: str, data: bytes) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def run_checker(
        self, env: dict[str, str] | None = None, root: Path | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--root",
                str(self.root if root is None else root),
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def report(self, result: subprocess.CompletedProcess[bytes]) -> str:
        return (result.stdout + result.stderr).decode("utf-8", errors="replace")

    def git_stub_environment(
        self, command: list[str], response: str
    ) -> dict[str, str]:
        actual_git = shutil.which("git")
        if actual_git is None:
            raise RuntimeError("Git is required to run the content-policy tests")
        wrapper_directory = self.root / "git-wrapper"
        wrapper_directory.mkdir(exist_ok=True)
        wrapper = wrapper_directory / "git"
        response_lines = "".join(f"    {line}\n" for line in response.splitlines())
        wrapper.write_text(
            f"#!{sys.executable}\n"
            "import os\n"
            "import sys\n"
            f"if sys.argv[1:2] == ['-C'] and sys.argv[3:] == {command!r}:\n"
            f"{response_lines}"
            f"os.execv({actual_git!r}, [{actual_git!r}, *sys.argv[1:]])\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = (
            str(wrapper_directory) + os.pathsep + environment.get("PATH", "")
        )
        return environment

    def test_empty_registry_and_benign_documentation_pass(self) -> None:
        self.write(
            "docs/policy-notes.md",
            b"Nintendo keys and ticket files are prohibited. Use synthetic fixtures.\n"
            b"A regex description may mention master_key_00 and hexadecimal placeholders.\n",
        )

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, self.report(result))
        self.assertIn("passed", self.report(result).lower())

    def test_initial_unstaged_registry_is_scanned_as_worktree_content(self) -> None:
        git(self.root, "rm", "--cached", "--quiet", REGISTRY_PATH)

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 0, report)
        self.assertNotIn("INDEX_REGISTRY_MISSING", report)
        self.assertNotIn("WORKTREE_REGISTRY_MISSING", report)

    def test_registered_synthetic_binary_passes_with_matching_hash(self) -> None:
        data = b"PFS0\x00synthetic-only"
        relative_path = "tests/fixtures/synthetic.bin"
        self.write(relative_path, data)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, data)]))
        git(self.root, "add", "--all")
        git(self.root, "-c", "user.name=Policy Test", "-c", "user.email=policy-test@example.invalid", "commit", "--quiet", "-m", "fixture")

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, self.report(result))

    def test_unregistered_untracked_binary_is_rejected_only_in_worktree(self) -> None:
        self.write("notes/opaque.bin", b"\x00synthetic payload")

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_BINARY_UNREGISTERED", report)
        self.assertNotIn("INDEX_BINARY_UNREGISTERED", report)

    def test_invalid_utf8_is_binary_even_without_a_known_extension(self) -> None:
        self.write("notes/opaque.data", b"\xff\xfe")

        result = self.run_checker()

        self.assertEqual(result.returncode, 1, self.report(result))
        self.assertIn("WORKTREE_BINARY_UNREGISTERED", self.report(result))

    def test_worktree_fixture_tampering_is_checked_against_worktree_registry(self) -> None:
        original = b"\x00original synthetic bytes"
        relative_path = "tests/fixtures/sample.bin"
        self.write(relative_path, original)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, original)]))
        git(self.root, "add", "--all")
        git(self.root, "-c", "user.name=Policy Test", "-c", "user.email=policy-test@example.invalid", "commit", "--quiet", "-m", "fixture")
        self.write(relative_path, b"\x00tampered working copy")

        result = self.run_checker()

        self.assertEqual(result.returncode, 1, self.report(result))
        self.assertIn("WORKTREE_FIXTURE_HASH_MISMATCH", self.report(result))
        self.assertNotIn("INDEX_FIXTURE_HASH_MISMATCH", self.report(result))

    def test_staged_fixture_tampering_is_checked_against_index_registry(self) -> None:
        original = b"\x00original synthetic bytes"
        relative_path = "tests/fixtures/sample.bin"
        self.write(relative_path, original)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, original)]))
        git(self.root, "add", "--all")
        git(self.root, "-c", "user.name=Policy Test", "-c", "user.email=policy-test@example.invalid", "commit", "--quiet", "-m", "fixture")
        self.write(relative_path, b"\x00staged tampering")
        git(self.root, "add", relative_path)
        self.write(relative_path, original)

        result = self.run_checker()

        self.assertEqual(result.returncode, 1, self.report(result))
        self.assertIn("INDEX_FIXTURE_HASH_MISMATCH", self.report(result))
        self.assertNotIn("WORKTREE_FIXTURE_HASH_MISMATCH", self.report(result))

    def test_staged_secret_is_found_after_working_copy_is_replaced(self) -> None:
        token = b"ghp_" + b"Q" * 40
        marker = b"STAGED_SECRET_MARKER"
        relative_path = "notes/credential-sample.txt"
        self.write(relative_path, token + b" " + marker)
        git(self.root, "add", relative_path)
        self.write(relative_path, b"benign working-tree replacement\n")

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_GITHUB_CREDENTIAL", report)
        self.assertNotIn(token.decode(), report)
        self.assertNotIn(marker.decode(), report)
        self.assertNotIn(str(self.root), report)

    def test_staged_secret_survives_git_replace_ref_to_benign_blob(self) -> None:
        token = b"ghp_" + b"Q" * 40
        relative_path = "notes/replaced-credential.txt"
        self.write(relative_path, token + b" staged secret marker")
        git(self.root, "add", relative_path)

        index_record = git(
            self.root, "ls-files", "--stage", "-z", "--", relative_path
        ).split(b"\0", 1)[0]
        original_oid = index_record.split(b"\t", 1)[0].split()[1].decode("ascii")
        replacement_oid = git(
            self.root,
            "hash-object",
            "-w",
            "--stdin",
            input_bytes=b"benign replacement\n",
        ).decode("ascii").strip()
        git(self.root, "replace", original_oid, replacement_oid)
        self.write(relative_path, b"benign working-tree content\n")

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_GITHUB_CREDENTIAL", report)
        self.assertNotIn("WORKTREE_GITHUB_CREDENTIAL", report)
        self.assertNotIn(token.decode(), report)

    def test_staged_binary_is_found_after_working_copy_becomes_text(self) -> None:
        relative_path = "notes/staged.data"
        self.write(relative_path, b"\x00staged binary marker")
        git(self.root, "add", relative_path)
        self.write(relative_path, b"benign working-tree text\n")

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_BINARY_UNREGISTERED", report)
        self.assertNotIn("WORKTREE_BINARY_UNREGISTERED", report)
        self.assertNotIn("staged binary marker", report)

    def test_staged_binary_is_rejected_when_registry_remains_untracked(self) -> None:
        git(self.root, "rm", "--cached", "--quiet", REGISTRY_PATH)
        relative_path = "tests/fixtures/staged.bin"
        data = b"\x00synthetic staged fixture"
        self.write(relative_path, data)
        git(self.root, "add", relative_path)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, data)]))

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_REGISTRY_MISSING", report)
        self.assertIn("INDEX_BINARY_UNREGISTERED", report)
        self.assertNotIn("WORKTREE_BINARY_UNREGISTERED", report)

    def test_index_and_worktree_registry_snapshots_are_validated_independently(self) -> None:
        original = b"\x00original bytes"
        updated = b"\x00updated bytes"
        relative_path = "tests/fixtures/sample.bin"
        self.write(relative_path, original)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, original)]))
        git(self.root, "add", "--all")
        git(self.root, "-c", "user.name=Policy Test", "-c", "user.email=policy-test@example.invalid", "commit", "--quiet", "-m", "fixture")
        self.write(relative_path, updated)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, updated)]))
        git(self.root, "add", relative_path, REGISTRY_PATH)
        self.write(relative_path, original)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, original)]))

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, self.report(result))

    def test_registry_rejects_wrong_schema_hash_and_missing_provenance(self) -> None:
        fixture = b"\x00fixture"
        relative_path = "tests/fixtures/sample.bin"
        self.write(relative_path, fixture)
        valid = synthetic_entry(relative_path, fixture)
        invalid_documents = [
            {"schema_version": 9, "fixtures": [valid]},
            {"schema_version": 1.0, "fixtures": [valid]},
            {"schema_version": 1, "fixtures": [{**valid, "sha256": "ABC" * 21 + "A"}]},
            {
                "schema_version": 1,
                "fixtures": [{**valid, "provenance": {"kind": "synthetic"}}],
            },
        ]

        for document in invalid_documents:
            with self.subTest(document=document):
                self.write(REGISTRY_PATH, (json.dumps(document) + "\n").encode())
                result = self.run_checker()
                self.assertEqual(result.returncode, 1, self.report(result))
                self.assertIn("WORKTREE_REGISTRY_INVALID", self.report(result))

    def test_registry_rejects_duplicate_and_escaping_paths(self) -> None:
        data = b"\x00fixture"
        entry = synthetic_entry("tests/fixtures/sample.bin", data)
        documents = [
            registry_document([entry, entry]),
            registry_document([synthetic_entry("../outside.bin", data)]),
            registry_document([synthetic_entry("/absolute.bin", data)]),
            registry_document([synthetic_entry("tests\\fixtures\\sample.bin", data)]),
        ]

        for document in documents:
            with self.subTest(document=document):
                self.write(REGISTRY_PATH, document)
                result = self.run_checker()
                self.assertEqual(result.returncode, 1, self.report(result))
                self.assertIn("WORKTREE_REGISTRY_INVALID", self.report(result))

    def test_registry_rejects_missing_and_untracked_fixture_paths(self) -> None:
        absent = synthetic_entry("tests/fixtures/missing.bin", b"\x00fixture")
        self.write(REGISTRY_PATH, registry_document([absent]))

        missing_result = self.run_checker()
        self.assertEqual(missing_result.returncode, 1, self.report(missing_result))
        self.assertIn("WORKTREE_FIXTURE_MISSING", self.report(missing_result))

        untracked_path = "tests/fixtures/untracked.bin"
        data = b"\x00untracked fixture"
        self.write(untracked_path, data)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(untracked_path, data)]))

        untracked_result = self.run_checker()
        self.assertEqual(untracked_result.returncode, 1, self.report(untracked_result))
        self.assertIn("WORKTREE_FIXTURE_UNTRACKED", self.report(untracked_result))

    def test_prohibited_filename_is_rejected_without_matching_prose(self) -> None:
        self.write("docs/prohibited-name-example.txt", b"A prod.keys file must never be committed.\n")
        self.write("tests/fixtures/prod.keys", b"benign text is still forbidden by the filename")

        result = self.run_checker()

        self.assertEqual(result.returncode, 1, self.report(result))
        self.assertIn("WORKTREE_PROHIBITED_FILENAME", self.report(result))
        self.assertIn('"tests/fixtures/prod.keys"', self.report(result))
        self.assertNotIn('"docs/prohibited-name-example.txt"', self.report(result))

    def test_private_key_header_is_detected_without_echoing_sample_bytes(self) -> None:
        marker = b"PRIVATE_MATERIAL_MARKER"
        begin = b"-----BEGIN "
        private_key_suffix = b"PRIVATE" + b" KEY-----"
        headers = (
            begin + private_key_suffix,
            begin + b"RSA " + private_key_suffix,
            begin + b"EC " + private_key_suffix,
            begin + b"DSA " + private_key_suffix,
            begin + b"OPENSSH " + private_key_suffix,
            begin + b"ENCRYPTED " + private_key_suffix,
        )
        for index, header in enumerate(headers):
            self.write(f"notes/sample-{index}.txt", header + b"\n" + marker + b"\n")

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertEqual(report.count("WORKTREE_PRIVATE_KEY_HEADER"), len(headers))
        self.assertNotIn(marker.decode(), report)
        for header in headers:
            self.assertNotIn(header.decode(), report)

    def test_aws_access_key_shape_is_detected_without_echoing_value(self) -> None:
        marker = b"AWS_VALUE_MARKER"
        value = b"AKIA" + b"0" * 16
        self.write("notes/config.txt", b"aws_access_key_id = " + value + b" " + marker)

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_AWS_CREDENTIAL", report)
        self.assertNotIn(value.decode(), report)
        self.assertNotIn(marker.decode(), report)

    def test_aws_secret_value_in_path_is_redacted_from_diagnostics(self) -> None:
        secret = b"0123456789abcdef" * 2 + b"ghijklmn"
        relative_path = f"{secret.decode()}.txt"
        self.write(
            relative_path,
            b"aws_secret_access_key = " + secret + b"\n",
        )

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_AWS_CREDENTIAL", report)
        self.assertIn("[redacted]", report)
        self.assertNotIn(secret.decode(), report)
        self.assertNotIn(secret[:8].decode(), report)
        self.assertNotIn(secret[-8:].decode(), report)

    def test_aws_secret_assignment_with_windows_newline_is_detected(self) -> None:
        secret = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
        path = "notes/windows-aws-secret.txt"
        self.write(path, b"aws_secret_access_key = " + secret + b"\r\n")

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_AWS_CREDENTIAL", report)
        self.assertNotIn(secret.decode(), report)

        self.write(path, b"aws_secret_access_key = <placeholder>\r\n")
        placeholder_result = self.run_checker()
        self.assertEqual(
            placeholder_result.returncode, 0, self.report(placeholder_result)
        )

    def test_aws_json_secret_assignment_is_detected_without_echoing_value(self) -> None:
        secret = b"Q7" * 20
        marker = b"JSON_AWS_SECRET_MARKER"
        path = "notes/aws-config.json"
        self.write(
            path,
            b'{"aws_secret_access_key": "' + secret + b'", "marker": "' + marker + b'"}\n',
        )

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_AWS_CREDENTIAL", report)
        self.assertNotIn(secret.decode(), report)
        self.assertNotIn(marker.decode(), report)

    def test_aws_cli_json_secret_access_key_is_detected(self) -> None:
        secret = b"S8" * 20
        path = "notes/aws-cli-credentials.json"
        self.write(path, b'{"SecretAccessKey": "' + secret + b'"}\n')

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_AWS_CREDENTIAL", report)
        self.assertNotIn(secret.decode(), report)

    def test_aws_json_secret_value_longer_than_forty_characters_is_not_matched(self) -> None:
        secret = b"T4" * 20 + b"X"
        self.write(
            "notes/aws-cli-placeholder.json",
            b'{"SecretAccessKey": "' + secret + b'"}\n',
        )

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, self.report(result))

    def test_aws_json_secret_value_in_path_is_redacted(self) -> None:
        secret = b"R3" * 20
        path = f"notes/{secret.decode()}.json"
        self.write(
            path,
            b'{\n  "aws_secret_access_key": "' + secret + b'"\n}\n',
        )

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_AWS_CREDENTIAL", report)
        self.assertIn("[redacted]", report)
        self.assertNotIn(secret.decode(), report)
        self.assertNotIn(secret[:8].decode(), report)
        self.assertNotIn(secret[-8:].decode(), report)

    def test_benign_aws_json_documentation_and_placeholders_pass(self) -> None:
        self.write(
            "docs/aws-configuration.md",
            b"The aws_secret_access_key field should not be committed.\n"
            b'{"aws_secret_access_key": "<replace-with-your-secret>"}\n'
            b'"aws_secret_access_key": "<placeholder>"\n'
            b"aws_secret_access_key = <example>\n",
        )

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, self.report(result))

    def test_concrete_nintendo_key_assignment_is_detected(self) -> None:
        key_shape = b"0123456789abcdef" * 2
        assignment = b"master_key_00 = " + key_shape
        self.write("notes/key-sample.txt", assignment + b"\n")

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_NINTENDO_KEY_ASSIGNMENT", report)
        self.assertNotIn(key_shape.decode(), report)

        self.write(
            "notes/key-sample.txt",
            b"The pattern master_key_[0-9]+ = [0-9a-f]{32} describes a key format.\n"
            b"Use <hex value> as a placeholder.\n"
            b"key = 00000000000000000000000000000000\n",
        )
        benign_result = self.run_checker()
        self.assertEqual(benign_result.returncode, 0, self.report(benign_result))

    def test_long_nonmatching_nintendo_assignment_is_ignored(self) -> None:
        identifier = b"key" * 4096
        self.write("notes/long-assignment.txt", identifier + b" = not-a-hex-value\n")

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, self.report(result))

    def test_nintendo_key_assignment_with_windows_newlines_is_detected(self) -> None:
        key_shape = b"0123456789abcdef" * 2
        self.write("notes/windows-key.txt", b"master_key_00 = " + key_shape + b"\r\n")

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_NINTENDO_KEY_ASSIGNMENT", report)

    def test_nintendo_placeholder_with_windows_newlines_is_ignored(self) -> None:
        self.write("notes/windows-placeholder.txt", b"key = " + b"0" * 32 + b"\r\n")

        result = self.run_checker()

        self.assertEqual(result.returncode, 0, self.report(result))

    def test_symlink_is_rejected_without_reading_its_target(self) -> None:
        marker = "SYMLINK_TARGET_MARKER"
        outside = self.root.parent / (self.root.name + "-outside.txt")
        outside.write_text(marker, encoding="utf-8")
        try:
            (self.root / "notes").mkdir()
            os.symlink(outside, self.root / "notes" / "linked.bin")

            result = self.run_checker()
            report = self.report(result)

            self.assertEqual(result.returncode, 2, report)
            self.assertIn("ERROR UNSAFE_FILE_TYPE", report)
            self.assertNotIn(marker, report)
            self.assertNotIn(str(outside), report)
        finally:
            outside.unlink(missing_ok=True)

    def test_special_file_is_rejected_without_blocking(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable on this platform")
        fifo = self.root / "README.md"
        fifo.unlink()
        os.mkfifo(fifo)

        result = self.run_checker()

        self.assertEqual(result.returncode, 2, self.report(result))
        self.assertIn("ERROR UNSAFE_FILE_TYPE", self.report(result))

    def test_staged_deletion_and_worktree_untracked_copy_are_both_checked(self) -> None:
        data = b"\x00registered fixture"
        relative_path = "tests/fixtures/sample.bin"
        self.write(relative_path, data)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, data)]))
        git(self.root, "add", "--all")
        git(self.root, "-c", "user.name=Policy Test", "-c", "user.email=policy-test@example.invalid", "commit", "--quiet", "-m", "fixture")
        git(self.root, "rm", "--quiet", "--cached", relative_path)

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("INDEX_FIXTURE_MISSING", report)
        self.assertIn("WORKTREE_FIXTURE_UNTRACKED", report)

    def test_unstaged_deletion_still_scans_index_blob_and_detects_stale_worktree_registry(self) -> None:
        data = b"\x00registered fixture"
        relative_path = "tests/fixtures/sample.bin"
        self.write(relative_path, data)
        self.write(REGISTRY_PATH, registry_document([synthetic_entry(relative_path, data)]))
        git(self.root, "add", "--all")
        git(self.root, "-c", "user.name=Policy Test", "-c", "user.email=policy-test@example.invalid", "commit", "--quiet", "-m", "fixture")
        (self.root / relative_path).unlink()

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 1, report)
        self.assertIn("WORKTREE_FIXTURE_MISSING", report)
        self.assertNotIn("INDEX_FIXTURE_HASH_MISMATCH", report)

    def test_unresolved_index_conflicts_fail_before_blob_scanning(self) -> None:
        relative_path = "notes/conflict.txt"
        self.write(relative_path, b"base\n")
        git(self.root, "add", relative_path)
        git(self.root, "-c", "user.name=Policy Test", "-c", "user.email=policy-test@example.invalid", "commit", "--quiet", "-m", "conflict base")
        git(self.root, "update-index", "--force-remove", relative_path)
        object_ids = [git(self.root, "hash-object", "-w", "--stdin", input_bytes=value).strip().decode() for value in (b"base\n", b"ours\n", b"theirs\n")]
        records = b"".join(
            f"100644 {object_id} {stage}\t{relative_path}\n".encode()
            for stage, object_id in enumerate(object_ids, start=1)
        )
        git(self.root, "update-index", "--index-info", input_bytes=records)

        result = self.run_checker()

        self.assertEqual(result.returncode, 2, self.report(result))
        self.assertIn("ERROR INDEX_CONFLICT", self.report(result))

    def test_file_size_limit_fails_closed_with_sanitized_diagnostic(self) -> None:
        relative_path = "notes/oversized.bin"
        marker = b"OVERSIZE_CONTENT_MARKER"
        self.write(relative_path, b"\x00" + marker + b"x" * (16 * 1024 * 1024))

        result = self.run_checker()
        report = self.report(result)

        self.assertEqual(result.returncode, 2, report)
        self.assertIn("ERROR RESOURCE_LIMIT", report)
        self.assertNotIn(marker.decode(), report)

    def test_invalid_repository_and_invalid_json_exit_as_checker_errors(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nscb-not-git-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        ) as directory:
            result = subprocess.run(
                [sys.executable, str(CHECKER), "--root", directory],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(result.returncode, 2, self.report(result))
        self.assertIn("ERROR ROOT_NOT_REPOSITORY", self.report(result))

        self.write(REGISTRY_PATH, b"not valid JSON\n")
        invalid_json = self.run_checker()
        self.assertEqual(invalid_json.returncode, 1, self.report(invalid_json))
        self.assertIn("WORKTREE_REGISTRY_INVALID", self.report(invalid_json))
        self.assertNotIn("not valid JSON", self.report(invalid_json))

    def test_symlink_loop_roots_fail_with_sanitized_errors(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nscb-policy-loop-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        ) as directory:
            loop = Path(directory) / "loop"
            os.symlink("loop", loop)

            input_result = self.run_checker(root=loop)
            input_report = self.report(input_result)
            self.assertEqual(input_result.returncode, 2, input_report)
            self.assertEqual(input_report, "ERROR ROOT_NOT_REPOSITORY\n")
            self.assertNotIn(str(loop), input_report)

            environment = self.git_stub_environment(
                ["rev-parse", "--show-toplevel"],
                f"sys.stdout.write({str(loop)!r})\nraise SystemExit(0)",
            )
            reported_result = self.run_checker(env=environment)
            reported_report = self.report(reported_result)
            self.assertEqual(reported_result.returncode, 2, reported_report)
            self.assertEqual(reported_report, "ERROR ROOT_NOT_REPOSITORY\n")
            self.assertNotIn(str(loop), reported_report)

    def test_oversized_git_output_fails_closed_without_echoing_output(self) -> None:
        environment = self.git_stub_environment(
            ["rev-parse", "--show-toplevel"],
            "sys.stdout.buffer.write(b'x' * 4097)\nraise SystemExit(0)",
        )

        result = self.run_checker(env=environment)

        self.assertEqual(result.returncode, 2, self.report(result))
        self.assertEqual(self.report(result), "ERROR GIT_OUTPUT_LIMIT\n")

    def test_successful_git_warning_fails_closed_without_echoing_warning(self) -> None:
        environment = self.git_stub_environment(
            ["ls-files", "--unmerged", "-z"],
            "sys.stderr.buffer.write(b'warning: skipped unreadable directory\\n')\n"
            "raise SystemExit(0)",
        )

        result = self.run_checker(env=environment)

        self.assertEqual(result.returncode, 2, self.report(result))
        self.assertEqual(self.report(result), "ERROR GIT_COMMAND_WARNING\n")

    def test_git_commands_disable_lazy_fetch_and_replacement_objects(self) -> None:
        response = (
            "if os.environ.get('GIT_NO_REPLACE_OBJECTS') != '1' or "
            "os.environ.get('GIT_NO_LAZY_FETCH') != '1':\n"
            "    raise SystemExit(23)\n"
            f"sys.stdout.write({str(self.root)!r})\n"
            "raise SystemExit(0)"
        )
        environment = self.git_stub_environment(
            ["rev-parse", "--show-toplevel"], response
        )

        result = self.run_checker(env=environment)

        self.assertEqual(result.returncode, 0, self.report(result))

    def test_git_command_timeout_fails_closed(self) -> None:
        wrapper_directory = self.root / "git-wrapper"
        wrapper_directory.mkdir()
        wrapper = wrapper_directory / "git"
        wrapper.write_text(
            f"#!{sys.executable}\nimport time\ntime.sleep(5)\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = (
            str(wrapper_directory) + os.pathsep + environment.get("PATH", "")
        )
        checker = ContentPolicyChecker(self.root)

        with patch.dict(os.environ, environment):
            with self.assertRaises(CheckerFailure) as failure:
                checker._git_at(self.root, ["hang"], timeout_seconds=0.05)

        self.assertEqual(failure.exception.code, "GIT_COMMAND_TIMEOUT")

    def test_findings_are_deterministic_bounded_and_do_not_echo_absolute_paths(self) -> None:
        marker = b"DETERMINISTIC_SECRET_MARKER"
        self.write("zeta/sample.txt", b"AKIA" + b"1" * 16 + marker)
        self.write("alpha/sample.bin", b"\x00binary marker")

        first = self.run_checker()
        second = self.run_checker()

        self.assertEqual(first.returncode, 1, self.report(first))
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stderr, second.stderr)
        report = self.report(first)
        self.assertNotIn(str(self.root), report)
        self.assertNotIn(marker.decode(), report)
        self.assertLessEqual(len(report.splitlines()), 101)
        self.assertEqual(sorted(report.splitlines()), report.splitlines())

    def test_finding_storage_is_bounded_and_counts_omitted_findings(self) -> None:
        checker = ContentPolicyChecker(self.root)
        total = MAX_FINDINGS + 5

        for index in range(total):
            checker._add_finding("WORKTREE", "TEST_RULE", f"notes/{index:03}.txt")

        self.assertEqual(len(checker.findings), MAX_FINDINGS)
        self.assertEqual(checker.omitted_findings, 5)
        self.assertEqual(checker.findings[0].path, "notes/000.txt")
        self.assertEqual(checker.findings[-1].path, "notes/099.txt")

    def test_git_ai_await_uses_bounded_non_autostarting_subprocess(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        root = Path(temporary_directory.name)
        try:
            with (
                patch.dict(os.environ),
                patch.object(shutil, "which", return_value="/synthetic/git-ai"),
                patch.object(
                    subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        ["/synthetic/git-ai", "await", "--timeout", "5"], 0
                    ),
                ) as run,
            ):
                os.environ.pop(ISOLATION_ENVIRONMENT_VARIABLE, None)
                status = _await_git_ai_before_metadata_cleanup(temporary_directory, root)

            self.assertEqual(status, "drained")
            run.assert_called_once()
            args, kwargs = run.call_args
            self.assertEqual(
                args[0], ["/synthetic/git-ai", "await", "--timeout", "5"]
            )
            self.assertEqual(kwargs["cwd"], CANONICAL_TEMP_DIRECTORY_BASE)
            self.assertEqual(
                kwargs["env"]["_GITAI_INTERNAL_DISABLE_WRAPPER_DAEMON_AUTOSPAWN"], "1"
            )
            self.assertNotIn("GIT_AI", kwargs["env"])
            self.assertEqual(kwargs["timeout"], 8)
            self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
            self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
            self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
            self.assertIs(kwargs["check"], False)
        finally:
            temporary_directory.cleanup()

    def test_git_ai_await_does_not_skip_for_unverified_isolation_marker(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        root = Path(temporary_directory.name)
        try:
            with (
                patch.dict(
                    os.environ,
                    {ISOLATION_ENVIRONMENT_VARIABLE: "unverified"},
                ),
                patch.object(shutil, "which", return_value="/synthetic/git-ai"),
                patch.object(
                    subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        ["/synthetic/git-ai", "await", "--timeout", "5"], 0
                    ),
                ) as run,
            ):
                status = _await_git_ai_before_metadata_cleanup(temporary_directory, root)

            self.assertEqual(status, "drained")
            run.assert_called_once()
        finally:
            temporary_directory.cleanup()

    def test_git_ai_await_skips_after_verified_isolation(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        root = Path(temporary_directory.name)
        try:
            with (
                patch.dict(
                    os.environ,
                    {
                        ISOLATION_ENVIRONMENT_VARIABLE:
                        ISOLATION_ENVIRONMENT_VALUE
                    },
                ),
                patch.object(shutil, "which", return_value="/fake/git-ai") as which,
                patch.object(subprocess, "run") as run,
            ):
                result = _await_git_ai_before_metadata_cleanup(temporary_directory, root)

            self.assertEqual(result, "isolation_verified")
            which.assert_not_called()
            run.assert_not_called()
        finally:
            temporary_directory.cleanup()

    def test_git_ai_await_skips_unavailable_binary_and_unowned_root(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        root = Path(temporary_directory.name)
        try:
            with patch.dict(
                os.environ,
                {ISOLATION_ENVIRONMENT_VARIABLE: "unverified"},
            ):
                with (
                    patch.object(shutil, "which", return_value=None),
                    patch.object(subprocess, "run") as run,
                ):
                    self.assertEqual(
                        _await_git_ai_before_metadata_cleanup(temporary_directory, root),
                        "not_installed",
                    )
                    run.assert_not_called()

                with (
                    patch.object(shutil, "which") as which,
                    patch.object(subprocess, "run") as run,
                ):
                    self.assertEqual(
                        _await_git_ai_before_metadata_cleanup(
                            temporary_directory, root / "not-the-owner"
                        ),
                        "not_applicable",
                    )
                    which.assert_not_called()
                    run.assert_not_called()
        finally:
            temporary_directory.cleanup()

    def test_git_ai_await_does_not_retry_on_timeout_or_nonzero_exit(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        root = Path(temporary_directory.name)
        command = ["/synthetic/git-ai", "await", "--timeout", "5"]
        try:
            with patch.dict(
                os.environ,
                {ISOLATION_ENVIRONMENT_VARIABLE: "unverified"},
            ):
                with (
                    patch.object(shutil, "which", return_value=command[0]),
                    patch.object(
                        subprocess,
                        "run",
                        side_effect=subprocess.TimeoutExpired(command, 8),
                    ) as run,
                ):
                    self.assertEqual(
                        _await_git_ai_before_metadata_cleanup(temporary_directory, root),
                        "process_timeout",
                    )
                    run.assert_called_once()

                with (
                    patch.object(shutil, "which", return_value=command[0]),
                    patch.object(
                        subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess(command, 1),
                    ) as run,
                ):
                    self.assertEqual(
                        _await_git_ai_before_metadata_cleanup(temporary_directory, root),
                        "not_drained",
                    )
                    run.assert_called_once()
        finally:
            temporary_directory.cleanup()

    def test_git_ai_await_precedes_initial_temporary_repo_deletion(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        root = Path(temporary_directory.name)
        (root / ".git").mkdir()
        original_cleanup = temporary_directory.cleanup
        events: list[str] = []

        def record_await(*_args: object) -> str:
            events.append("await")
            return "drained"

        def record_cleanup() -> None:
            events.append("cleanup")
            original_cleanup()

        try:
            with (
                patch.object(temporary_directory, "cleanup", side_effect=record_cleanup),
                patch.object(
                    sys.modules[__name__],
                    "_await_git_ai_before_metadata_cleanup",
                    side_effect=record_await,
                ),
            ):
                _cleanup_with_diagnostics(temporary_directory, root, self.id())
            self.assertEqual(events, ["await", "cleanup"])
            self.assertFalse(root.exists())
        finally:
            original_cleanup()

    def test_git_ai_await_precedes_metadata_cleanup_after_enotempty(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        root = Path(temporary_directory.name)
        (root / ".git").mkdir()
        original_cleanup = temporary_directory.cleanup
        events: list[str] = []

        def racing_cleanup() -> None:
            events.append("cleanup")
            if events.count("cleanup") == 1:
                raise OSError(errno.ENOTEMPTY, "directory not empty", str(root / ".git"))
            original_cleanup()

        def record_await(*_args: object) -> str:
            events.append("await")
            return "drained"

        def record_prune(*_args: object) -> bool:
            events.append("prune")
            return True

        try:
            with (
                patch.object(temporary_directory, "cleanup", side_effect=racing_cleanup),
                patch.object(
                    sys.modules[__name__],
                    "_await_git_ai_before_metadata_cleanup",
                    side_effect=record_await,
                    create=True,
                ),
                patch.object(
                    sys.modules[__name__],
                    "_remove_disposable_git_ai_metadata",
                    side_effect=record_prune,
                ),
            ):
                _cleanup_with_diagnostics(temporary_directory, root, self.id())
            self.assertEqual(
                events, ["await", "cleanup", "await", "prune", "cleanup"]
            )
            self.assertFalse(root.exists())
        finally:
            original_cleanup()

    def test_cleanup_removes_git_ai_metadata_created_during_teardown(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        root = Path(temporary_directory.name)
        (root / ".git").mkdir()
        original_cleanup = temporary_directory.cleanup
        calls = 0

        def cleanup_with_late_git_ai_write() -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                note = root / ".git" / "refs" / "notes" / "ai"
                note.parent.mkdir(parents=True)
                note.write_text("synthetic notes ref", encoding="utf-8")
                log = root / ".git" / "logs" / "refs" / "notes" / "ai"
                log.parent.mkdir(parents=True)
                log.write_text("synthetic notes reflog", encoding="utf-8")
                working_logs = root / ".git" / "ai" / "working_logs"
                working_logs.mkdir(parents=True)
                (working_logs / "synthetic.json").write_text("{}", encoding="utf-8")
                raise OSError(errno.ENOTEMPTY, "directory not empty", str(root / ".git"))
            original_cleanup()

        try:
            with (
                patch.object(
                    temporary_directory, "cleanup", side_effect=cleanup_with_late_git_ai_write
                ),
                patch.object(
                    sys.modules[__name__],
                    "_await_git_ai_before_metadata_cleanup",
                    return_value="drained",
                ),
            ):
                _cleanup_with_diagnostics(temporary_directory, root, self.id())
            self.assertEqual(calls, 2)
            self.assertFalse(root.exists())
        finally:
            original_cleanup()

    def test_cleanup_recovers_an_empty_git_ai_notes_directory(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        root = Path(temporary_directory.name)
        (root / ".git").mkdir()
        original_cleanup = temporary_directory.cleanup
        calls = 0

        def cleanup_with_late_empty_directory() -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                (root / ".git" / "refs" / "notes").mkdir(parents=True)
                raise OSError(errno.ENOTEMPTY, "directory not empty", str(root / ".git"))
            original_cleanup()

        try:
            with (
                patch.object(
                    temporary_directory, "cleanup", side_effect=cleanup_with_late_empty_directory
                ),
                patch.object(
                    sys.modules[__name__],
                    "_await_git_ai_before_metadata_cleanup",
                    return_value="drained",
                ),
            ):
                _cleanup_with_diagnostics(temporary_directory, root, self.id())
            self.assertEqual(calls, 2)
            self.assertFalse(root.exists())
        finally:
            original_cleanup()

    def test_cleanup_preserves_unrelated_enotempty_failure(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        root = Path(temporary_directory.name)
        (root / ".git").mkdir()
        original_cleanup = temporary_directory.cleanup
        failure = OSError(errno.ENOTEMPTY, "directory not empty", str(root / ".git"))
        try:
            with (
                patch.object(temporary_directory, "cleanup", side_effect=failure) as cleanup,
                patch.object(
                    sys.modules[__name__],
                    "_await_git_ai_before_metadata_cleanup",
                    return_value="not_drained",
                ),
                redirect_stderr(io.StringIO()),
            ):
                with self.assertRaises(OSError) as raised:
                    _cleanup_with_diagnostics(temporary_directory, root, self.id())
            self.assertIs(raised.exception, failure)
            cleanup.assert_called_once_with()
        finally:
            original_cleanup()

    def test_cleanup_never_follows_git_ai_metadata_symlinks(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-policy-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        outside = tempfile.TemporaryDirectory(
            prefix="nscb-cleanup-outside-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        )
        root = Path(temporary_directory.name)
        outside_marker = Path(outside.name) / "marker.txt"
        outside_marker.write_text("untouched", encoding="utf-8")
        (root / ".git").mkdir()
        (root / ".git" / "ai").symlink_to(outside.name, target_is_directory=True)
        original_cleanup = temporary_directory.cleanup
        failure = OSError(errno.ENOTEMPTY, "directory not empty", str(root / ".git"))
        try:
            with (
                patch.object(temporary_directory, "cleanup", side_effect=failure) as cleanup,
                patch.object(
                    sys.modules[__name__],
                    "_await_git_ai_before_metadata_cleanup",
                    return_value="drained",
                ),
                redirect_stderr(io.StringIO()),
            ):
                with self.assertRaises(OSError) as raised:
                    _cleanup_with_diagnostics(temporary_directory, root, self.id())
            self.assertEqual(raised.exception.errno, errno.EINVAL)
            self.assertEqual(outside_marker.read_text(encoding="utf-8"), "untouched")
            cleanup.assert_called_once_with()
        finally:
            original_cleanup()
            outside.cleanup()

    def test_cleanup_failure_emits_bounded_sanitized_metadata(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nscb-cleanup-diagnostic-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        ) as root_name:
            with tempfile.TemporaryDirectory(
                prefix="nscb-cleanup-outside-", dir=CANONICAL_TEMP_DIRECTORY_BASE
            ) as outside_name:
                root = Path(root_name)
                failed_directory = root / "blocked"
                failed_directory.mkdir()
                credential_name = "ghp_" + "A" * 40
                (failed_directory / credential_name).write_text("private payload", encoding="utf-8")
                outside_path = Path(outside_name) / "outside-marker"
                outside_path.write_text("OUTSIDE_CONTENT_MARKER", encoding="utf-8")
                (failed_directory / "linked").symlink_to(outside_path)

                cleanup = Mock()
                failure = OSError(errno.ENOTEMPTY, "directory not empty", str(failed_directory))

                def fail_cleanup() -> None:
                    (failed_directory / "new-entry.bin").write_bytes(b"CLEANUP_CONTENT_MARKER")
                    raise failure

                cleanup.cleanup.side_effect = fail_cleanup
                stderr = io.StringIO()
                with (
                    patch.object(sys.modules[__name__], "REPOSITORY_ROOT", self.root),
                    patch.object(sys.modules[__name__], "_CLEANUP_DIAGNOSTICS", []),
                    patch.object(sys.modules[__name__], "_CLEANUP_DIAGNOSTICS_TRUNCATED", False),
                    redirect_stderr(stderr),
                ):
                    with self.assertRaises(OSError) as raised:
                        _cleanup_with_diagnostics(cleanup, root, self.id())

                self.assertIs(raised.exception, failure)
                output = stderr.getvalue()
                prefix = "NSCB_CLEANUP_DIAGNOSTIC "
                self.assertTrue(output.startswith(prefix))
                event = json.loads(output[len(prefix) :])
                self.assertEqual(event["test_id"], self.id())
                self.assertEqual(event["error"]["errno"], errno.ENOTEMPTY)
                self.assertEqual(event["error"]["relative_path"], "blocked")
                self.assertEqual(event["after"]["priority_path_status"], "captured")
                self.assertTrue(event["inventory_comparison_complete"])
                timeline = event["timeline"]
                phases = (
                    "snapshot_start",
                    "snapshot_end",
                    "cleanup_start",
                    "failure_end",
                )
                self.assertEqual(set(timeline), set(phases))
                elapsed_ns = [timeline[phase]["elapsed_ns"] for phase in phases]
                self.assertEqual(elapsed_ns, sorted(elapsed_ns))
                for phase in phases:
                    self.assertGreater(timeline[phase]["wallclock_unix_ns"], 0)
                    self.assertGreaterEqual(timeline[phase]["elapsed_ns"], 0)

                before_paths = {entry["path"] for entry in event["before"]["entries"]}
                after_entries = {
                    entry["path"]: entry["type"] for entry in event["after"]["entries"]
                }
                self.assertNotIn("blocked/new-entry.bin", before_paths)
                self.assertEqual(after_entries["blocked/linked"], "symlink")
                self.assertIn("blocked/new-entry.bin", after_entries)
                self.assertIn("<redacted>", " ".join(after_entries))

                artifact = (
                    self.root
                    / ".chatgpt"
                    / "reviews"
                    / "issue-4-cleanup-diagnosis"
                    / "cleanup-diagnosis.json"
                )
                artifact_bytes = artifact.read_bytes()
                self.assertTrue(artifact_bytes.endswith(b"\n"))
                self.assertEqual(json.loads(artifact_bytes)["diagnostics"][0], event)
                for forbidden in (
                    credential_name,
                    str(root),
                    str(outside_path),
                    "private payload",
                    "OUTSIDE_CONTENT_MARKER",
                    "CLEANUP_CONTENT_MARKER",
                ):
                    self.assertNotIn(forbidden, output)
                    self.assertNotIn(forbidden.encode(), artifact_bytes)

                overflow = root / "overflow"
                overflow.mkdir()
                for index in range(_CLEANUP_ENTRY_LIMIT + 8):
                    (overflow / f"entry-{index:02}.txt").touch()
                root_fd = _open_cleanup_root(root)
                try:
                    inventory = _cleanup_inventory(root_fd, time.monotonic_ns())
                finally:
                    os.close(root_fd)
                self.assertEqual(len(inventory["entries"]), _CLEANUP_ENTRY_LIMIT)
                self.assertTrue(inventory["truncated"])

    def test_cleanup_inventory_caps_synthetic_metadata_during_scan(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nscb-cleanup-inventory-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        ) as root_name:
            root = Path(root_name)
            overflow = root / "overflow"
            overflow.mkdir()
            for index in range(_CLEANUP_ENTRY_LIMIT + 1):
                (overflow / f"entry-{index:03}.txt").touch()

            original_stat = os.stat
            follow_symlink_arguments: list[bool] = []

            def synthetic_stat(
                path: str | bytes,
                *,
                dir_fd: int | None = None,
                follow_symlinks: bool = True,
            ) -> SimpleNamespace:
                actual = original_stat(
                    path, dir_fd=dir_fd, follow_symlinks=follow_symlinks
                )
                follow_symlink_arguments.append(follow_symlinks)
                return SimpleNamespace(
                    st_mode=actual.st_mode,
                    st_size=actual.st_size,
                    st_ino=987654,
                    st_mtime_ns=1_700_000_000_123_456_789,
                    st_ctime_ns=1_700_000_000_987_654_321,
                )

            root_fd = _open_cleanup_root(root)
            try:
                with patch.object(os, "stat", side_effect=synthetic_stat) as stat_call:
                    inventory = _cleanup_inventory(root_fd, time.monotonic_ns())
            finally:
                os.close(root_fd)

            self.assertEqual(len(inventory["entries"]), _CLEANUP_ENTRY_LIMIT)
            self.assertTrue(inventory["truncated"])
            self.assertEqual(stat_call.call_count, _CLEANUP_ENTRY_LIMIT)
            self.assertEqual(follow_symlink_arguments, [False] * _CLEANUP_ENTRY_LIMIT)
            root_entry = next(
                entry for entry in inventory["entries"] if entry["path"] == "overflow"
            )
            self.assertEqual(root_entry["inode"], 987654)
            self.assertEqual(root_entry["mtime_ns"], 1_700_000_000_123_456_789)
            self.assertEqual(root_entry["ctime_ns"], 1_700_000_000_987_654_321)

    def test_cleanup_root_rejects_symlink_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nscb-cleanup-symlink-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        ) as parent_name:
            parent = Path(parent_name)
            outside_root = parent / "outside"
            (outside_root / "root").mkdir(parents=True)
            (outside_root / "root" / "marker").write_text("private", encoding="utf-8")
            symlink_ancestor = parent / "linked"
            symlink_ancestor.symlink_to(outside_root, target_is_directory=True)

            with patch.object(os, "scandir") as scandir:
                with self.assertRaises(OSError):
                    _open_cleanup_root(symlink_ancestor / "root")
                scandir.assert_not_called()

    def test_cleanup_depth_limit_marks_comparison_incomplete(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="nscb-cleanup-depth-", dir=CANONICAL_TEMP_DIRECTORY_BASE
        ) as root_name:
            root = Path(root_name)
            failed_directory = root
            for index in range(_CLEANUP_DEPTH_LIMIT):
                failed_directory = failed_directory / f"level-{index}"
                failed_directory.mkdir()

            cleanup = Mock()
            cleanup.cleanup.side_effect = OSError(
                errno.ENOTEMPTY, "directory not empty", str(failed_directory)
            )
            stderr = io.StringIO()
            with (
                patch.object(sys.modules[__name__], "REPOSITORY_ROOT", self.root),
                patch.object(sys.modules[__name__], "_CLEANUP_DIAGNOSTICS", []),
                patch.object(sys.modules[__name__], "_CLEANUP_DIAGNOSTICS_TRUNCATED", False),
                redirect_stderr(stderr),
            ):
                with self.assertRaises(OSError):
                    _cleanup_with_diagnostics(cleanup, root, self.id())

            prefix = "NSCB_CLEANUP_DIAGNOSTIC "
            event = json.loads(stderr.getvalue()[len(prefix) :])
            self.assertTrue(event["before"]["truncated"])
            self.assertTrue(event["after"]["truncated"])
            self.assertFalse(event["inventory_comparison_complete"])


if __name__ == "__main__":
    unittest.main()
