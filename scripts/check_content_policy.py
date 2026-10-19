#!/usr/bin/env python3
"""Check repository content and fixture provenance in Git and the worktree.

The checker reads the stage-zero Git index and the current working tree as two
independent snapshots. It reports policy findings without displaying matched
content, and it fails closed when Git or filesystem state cannot be inspected
within the documented resource limits.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
from typing import Any, Protocol


REGISTRY_PATH = "tests/fixtures/registry.json"
MAX_FILES = 10_000
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_GIT_STDERR_BYTES = 64 * 1024
MAX_GIT_COMMAND_SECONDS = 10.0
MAX_FINDINGS = 100
MAX_DISPLAY_PATH = 160

_BINARY_EXTENSIONS = frozenset(
    {
        ".7z",
        ".a",
        ".apk",
        ".bin",
        ".bz2",
        ".cert",
        ".db",
        ".der",
        ".dll",
        ".dylib",
        ".elf",
        ".exe",
        ".gif",
        ".gz",
        ".jpeg",
        ".jpg",
        ".keystore",
        ".mkv",
        ".mp3",
        ".mp4",
        ".nca",
        ".nro",
        ".nsp",
        ".nsz",
        ".otf",
        ".p12",
        ".pfs0",
        ".pfx",
        ".pdf",
        ".pem",
        ".png",
        ".rar",
        ".so",
        ".sqlite",
        ".tar",
        ".tik",
        ".ttf",
        ".wasm",
        ".wav",
        ".webp",
        ".xci",
        ".xcz",
        ".xz",
        ".zip",
        ".zst",
    }
)

_PRIVATE_KEY_HEADER = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
_GITHUB_CREDENTIAL = re.compile(
    rb"(?i)(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})"
)
_AWS_ACCESS_KEY = re.compile(rb"(?i)\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_AWS_SECRET_ASSIGNMENT = re.compile(
    rb"(?im)^[ \t]*aws_secret_access_key[ \t]*=[ \t]*"
    rb"([A-Za-z0-9/+=]{40})[ \t]*\r?$"
)
# JSON credentials store the field name and 40-character secret as strings.
_AWS_SECRET_JSON_ASSIGNMENT = re.compile(
    rb'(?i)"(?:aws_secret_access_key|SecretAccessKey)"[ \t\r\n]*:[ \t\r\n]*"'
    rb'[A-Za-z0-9/+=]{40}"'
)
_NINTENDO_KEY_MARKERS = (
    b"master_key",
    b"titlekek",
    b"key_area_key",
    b"header_key",
    b"aes_kek",
    b"rsa_kek",
    b"key",
    b"kek",
    b"seed",
)
_PATH_CREDENTIAL = re.compile(
    r"(?i)(?:(?<![a-z0-9/+=])[a-z0-9/+=]{40,}(?![a-z0-9/+=])|"
    r"gh[pousr]_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|[0-9a-f]{32,})"
)
_LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CheckerFailure(Exception):
    """A sanitized failure that prevents a complete repository scan."""

    def __init__(self, code: str, path: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.path = path


@dataclass(frozen=True, order=True)
class Finding:
    """One policy violation identified in a named repository snapshot."""

    snapshot: str
    rule: str
    path: str


@dataclass(frozen=True)
class IndexEntry:
    """A stage-zero file record read from the Git index."""

    mode: str
    object_id: str
    path: str


@dataclass(frozen=True)
class FileInfo:
    """Content facts retained for registry checks after a file is scanned."""

    size: int
    sha256: str
    is_binary: bool


class ScanBudget:
    """Bound file enumeration and bytes read across both snapshots."""

    def __init__(self) -> None:
        self.bytes_read = 0

    def check_file_count(self, file_versions: int) -> None:
        """Reject a combined index and worktree scan with too many file versions."""
        if file_versions > MAX_FILES:
            raise CheckerFailure("RESOURCE_LIMIT")

    def reserve_bytes(self, size: int, path: str) -> None:
        """Charge one file version against the shared scan byte ceiling."""
        if size < 0 or self.bytes_read + size > MAX_TOTAL_BYTES:
            raise CheckerFailure("RESOURCE_LIMIT", path)
        self.bytes_read += size


class GitCommandRunner(Protocol):
    """Narrow read-only Git command boundary used by content inspection."""

    def __call__(
        self,
        root: Path,
        arguments: list[str],
        *,
        max_output_bytes: int,
        timeout_seconds: float,
        nonzero_exit_code: str,
    ) -> bytes:
        """Return bounded stdout for one Git query or raise a safe checker failure."""
        ...


def _run_git_command(
    root: Path,
    arguments: list[str],
    *,
    max_output_bytes: int = MAX_GIT_OUTPUT_BYTES,
    timeout_seconds: float = MAX_GIT_COMMAND_SECONDS,
    nonzero_exit_code: str = "GIT_COMMAND_FAILED",
) -> bytes:
    """Run one Git query with bounded output, timeout, and safe diagnostics."""
    if max_output_bytes < 0:
        raise CheckerFailure("GIT_OUTPUT_LIMIT")
    if timeout_seconds <= 0:
        raise CheckerFailure("GIT_COMMAND_TIMEOUT")
    try:
        environment = os.environ.copy()
        environment["GIT_NO_REPLACE_OBJECTS"] = "1"
        environment["GIT_NO_LAZY_FETCH"] = "1"
        process = subprocess.Popen(
            ["git", "-C", str(root), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=environment,
        )
    except (OSError, ValueError) as error:
        raise CheckerFailure("GIT_COMMAND_FAILED") from error

    assert process.stdout is not None and process.stderr is not None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {
        "stdout": max_output_bytes,
        "stderr": MAX_GIT_STDERR_BYTES,
    }
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    try:
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise CheckerFailure("GIT_COMMAND_TIMEOUT")
            events = selector.select(remaining_time)
            if not events:
                raise CheckerFailure("GIT_COMMAND_TIMEOUT")
            for key, _ in events:
                stream_name = key.data
                remaining_output = limits[stream_name] + 1 - len(output[stream_name])
                chunk = os.read(
                    key.fileobj.fileno(), min(64 * 1024, remaining_output)
                )
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[stream_name].extend(chunk)
                if len(output[stream_name]) > limits[stream_name]:
                    raise CheckerFailure("GIT_OUTPUT_LIMIT")
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            raise CheckerFailure("GIT_COMMAND_TIMEOUT")
        try:
            return_code = process.wait(timeout=remaining_time)
        except subprocess.TimeoutExpired as error:
            raise CheckerFailure("GIT_COMMAND_TIMEOUT") from error
    except CheckerFailure:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise
    except (OSError, ValueError) as error:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise CheckerFailure("GIT_COMMAND_FAILED") from error
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()

    if return_code != 0:
        raise CheckerFailure(nonzero_exit_code)
    if output["stderr"]:
        raise CheckerFailure("GIT_COMMAND_WARNING")
    return bytes(output["stdout"])


class ContentPolicyChecker:
    """Inspect repository files and fixture registries in both Git snapshots."""

    def __init__(
        self, root: Path, *, runner: GitCommandRunner = _run_git_command
    ) -> None:
        self._runner = runner
        self.requested_root = root
        self.root = self._resolve_repository_root(root)
        self.budget = ScanBudget()
        self.findings: list[Finding] = []
        self.omitted_findings = 0

    def run(self) -> list[Finding]:
        """Scan the index and worktree independently, then validate each registry."""
        self._reject_unmerged_index()
        index_entries = self._read_index_entries()
        untracked_paths = self._read_untracked_paths()
        worktree_paths = set(index_entries) | untracked_paths
        self.budget.check_file_count(len(index_entries) + len(worktree_paths))

        index_info, index_registry = self._scan_index(index_entries)
        worktree_info, worktree_registry = self._scan_worktree(worktree_paths)

        self._validate_registry(
            snapshot="INDEX",
            registry_bytes=index_registry,
            file_info=index_info,
            tracked_paths=set(index_entries),
            required=False,
        )
        self._validate_registry(
            snapshot="WORKTREE",
            registry_bytes=worktree_registry,
            file_info=worktree_info,
            tracked_paths=set(index_entries),
            required=True,
        )
        return self.findings

    def _resolve_repository_root(self, root: Path) -> Path:
        """Resolve the Git top-level directory without exposing command output."""
        try:
            candidate = root.expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise CheckerFailure("ROOT_NOT_REPOSITORY") from error
        if not candidate.is_dir():
            raise CheckerFailure("ROOT_NOT_REPOSITORY")
        result = self._git_at(
            candidate,
            ["rev-parse", "--show-toplevel"],
            max_output_bytes=4096,
            nonzero_exit_code="ROOT_NOT_REPOSITORY",
        )
        reported_root = result[:-1] if result.endswith(b"\n") else result
        try:
            resolved = Path(os.fsdecode(reported_root)).resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise CheckerFailure("ROOT_NOT_REPOSITORY") from error
        if not resolved.is_dir():
            raise CheckerFailure("ROOT_NOT_REPOSITORY")
        return resolved

    def _git_at(
        self,
        root: Path,
        arguments: list[str],
        *,
        max_output_bytes: int = MAX_GIT_OUTPUT_BYTES,
        timeout_seconds: float = MAX_GIT_COMMAND_SECONDS,
        nonzero_exit_code: str = "GIT_COMMAND_FAILED",
    ) -> bytes:
        """Run one Git query through the configured read-only command runner."""
        return self._runner(
            root,
            arguments,
            max_output_bytes=max_output_bytes,
            timeout_seconds=timeout_seconds,
            nonzero_exit_code=nonzero_exit_code,
        )

    def _reject_unmerged_index(self) -> None:
        """Stop before reading content if the index contains conflict stages."""
        try:
            self._git_at(
                self.root,
                ["ls-files", "--unmerged", "-z"],
                max_output_bytes=0,
            )
        except CheckerFailure as failure:
            if failure.code == "GIT_OUTPUT_LIMIT":
                raise CheckerFailure("INDEX_CONFLICT") from failure
            raise

    def _read_index_entries(self) -> dict[str, IndexEntry]:
        """Read stage-zero paths and object IDs without resolving path revisions."""
        records = self._git_at(self.root, ["ls-files", "--stage", "-z"])
        entries: dict[str, IndexEntry] = {}
        for record in records.split(b"\0"):
            if not record:
                continue
            metadata, separator, raw_path = record.partition(b"\t")
            fields = metadata.split(b" ")
            if not separator or len(fields) != 3:
                raise CheckerFailure("INDEX_READ_FAILED")
            mode_bytes, object_id_bytes, stage_bytes = fields
            if stage_bytes != b"0":
                raise CheckerFailure("INDEX_CONFLICT")
            path = os.fsdecode(raw_path)
            self._validate_repository_path(path)
            if path in entries:
                raise CheckerFailure("INDEX_READ_FAILED", path)
            try:
                mode = mode_bytes.decode("ascii", errors="strict")
                object_id = object_id_bytes.decode("ascii", errors="strict")
            except UnicodeDecodeError as error:
                raise CheckerFailure("INDEX_READ_FAILED", path) from error
            if mode not in {"100644", "100755"}:
                raise CheckerFailure("UNSAFE_FILE_TYPE", path)
            if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id):
                raise CheckerFailure("INDEX_READ_FAILED", path)
            entries[path] = IndexEntry(mode, object_id, path)
        return entries

    def _read_untracked_paths(self) -> set[str]:
        """Enumerate nonignored untracked files through Git's NUL-delimited output."""
        records = self._git_at(
            self.root, ["ls-files", "--others", "--exclude-standard", "-z"]
        )
        paths: set[str] = set()
        for record in records.split(b"\0"):
            if not record:
                continue
            path = os.fsdecode(record)
            self._validate_repository_path(path)
            paths.add(path)
        return paths

    def _validate_repository_path(self, path: str) -> None:
        """Require a portable, repository-relative path with no traversal parts."""
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or path == ".git"
            or path.startswith(".git/")
        ):
            raise CheckerFailure("UNSAFE_PATH")

    def _read_index_blob(self, entry: IndexEntry) -> bytes:
        """Read one bounded index blob by object ID, never by a path expression."""
        size_bytes = self._git_at(
            self.root,
            ["cat-file", "-s", entry.object_id],
            max_output_bytes=128,
        )
        try:
            size_text = size_bytes.decode("ascii").strip()
            size = int(size_text)
        except (UnicodeDecodeError, ValueError) as error:
            raise CheckerFailure("INDEX_READ_FAILED", entry.path) from error
        limit = self._file_limit(entry.path)
        if size > limit:
            raise CheckerFailure("RESOURCE_LIMIT", entry.path)
        self.budget.reserve_bytes(size, entry.path)
        content = self._git_at(
            self.root,
            ["cat-file", "blob", entry.object_id],
            max_output_bytes=size,
        )
        if len(content) != size:
            raise CheckerFailure("INDEX_READ_FAILED", entry.path)
        return content

    def _scan_index(
        self, entries: dict[str, IndexEntry]
    ) -> tuple[dict[str, FileInfo], bytes | None]:
        """Inspect each stage-zero blob and retain only the registry bytes."""
        info: dict[str, FileInfo] = {}
        registry_bytes: bytes | None = None
        for path in sorted(entries):
            content = self._read_index_blob(entries[path])
            info[path] = self._inspect_content("INDEX", path, content)
            if path == REGISTRY_PATH:
                registry_bytes = content
        return info, registry_bytes

    def _scan_worktree(self, paths: set[str]) -> tuple[dict[str, FileInfo], bytes | None]:
        """Inspect tracked worktree files and nonignored untracked files safely."""
        info: dict[str, FileInfo] = {}
        registry_bytes: bytes | None = None
        for path in sorted(paths):
            content = self._read_worktree_file(path)
            if content is None:
                continue
            info[path] = self._inspect_content("WORKTREE", path, content)
            if path == REGISTRY_PATH:
                registry_bytes = content
        return info, registry_bytes

    def _read_worktree_file(self, path: str) -> bytes | None:
        """Open a path component-by-component without following links or special files."""
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory_flag is None or os.open not in os.supports_dir_fd:
            raise CheckerFailure("SAFE_OPEN_UNAVAILABLE", path)

        directory_fd: int | None = None
        file_fd: int | None = None
        try:
            directory_fd = os.open(self.root, os.O_RDONLY | directory_flag)
            components = path.split("/")
            for component in components[:-1]:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | directory_flag | nofollow,
                    dir_fd=directory_fd,
                )
                os.close(directory_fd)
                directory_fd = next_fd
            file_fd = os.open(
                components[-1],
                os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory_fd,
            )
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise CheckerFailure("UNSAFE_FILE_TYPE", path)
            limit = self._file_limit(path)
            if before.st_size > limit:
                raise CheckerFailure("RESOURCE_LIMIT", path)
            self.budget.reserve_bytes(before.st_size, path)

            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(file_fd, min(64 * 1024, remaining))
                if not chunk:
                    raise CheckerFailure("WORKTREE_CHANGED_DURING_SCAN", path)
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            after = os.fstat(file_fd)
            if (
                len(content) != before.st_size
                or before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
            ):
                raise CheckerFailure("WORKTREE_CHANGED_DURING_SCAN", path)
            return content
        except FileNotFoundError:
            return None
        except CheckerFailure:
            raise
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise CheckerFailure("UNSAFE_FILE_TYPE", path) from error
            raise CheckerFailure("WORKTREE_READ_FAILED", path) from error
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if directory_fd is not None:
                os.close(directory_fd)

    def _file_limit(self, path: str) -> int:
        """Return the tighter registry ceiling for the registry document."""
        if path == REGISTRY_PATH:
            return MAX_REGISTRY_BYTES
        return MAX_FILE_BYTES

    def _inspect_content(self, snapshot: str, path: str, content: bytes) -> FileInfo:
        """Classify bytes, compute their digest, and scan for prohibited patterns."""
        if self._is_prohibited_filename(path):
            self._add_finding(snapshot, "PROHIBITED_FILENAME", path)
        if _PRIVATE_KEY_HEADER.search(content):
            self._add_finding(snapshot, "PRIVATE_KEY_HEADER", path)
        if _GITHUB_CREDENTIAL.search(content):
            self._add_finding(snapshot, "GITHUB_CREDENTIAL", path)
        if (
            _AWS_ACCESS_KEY.search(content)
            or _AWS_SECRET_ASSIGNMENT.search(content)
            or _AWS_SECRET_JSON_ASSIGNMENT.search(content)
        ):
            self._add_finding(snapshot, "AWS_CREDENTIAL", path)
        if self._contains_nintendo_key_assignment(content):
            self._add_finding(snapshot, "NINTENDO_KEY_ASSIGNMENT", path)

        is_binary = self._is_binary(path, content)
        return FileInfo(len(content), hashlib.sha256(content).hexdigest(), is_binary)

    def _is_binary(self, path: str, content: bytes) -> bool:
        """Recognize binary content by bytes, UTF-8 validity, or a known extension."""
        suffix = Path(path).suffix.casefold()
        if suffix in _BINARY_EXTENSIONS or b"\0" in content:
            return True
        try:
            content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return True
        return False

    def _contains_nintendo_key_assignment(self, content: bytes) -> bool:
        """Scan assignment lines in linear time while allowing common placeholders."""
        line_start = 0
        content_size = len(content)
        while line_start <= content_size:
            line_break = content.find(b"\n", line_start)
            if line_break < 0:
                line_end = content_size
            else:
                line_end = line_break
            if (
                line_break >= 0
                and line_end > line_start
                and content[line_end - 1] == ord("\r")
            ):
                line_end -= 1
            if self._line_contains_nintendo_key_assignment(
                content, line_start, line_end
            ):
                return True
            if line_break < 0:
                break
            line_start = line_break + 1
        return False

    @staticmethod
    def _line_contains_nintendo_key_assignment(
        content: bytes, line_start: int, line_end: int
    ) -> bool:
        """Check one line without a backtracking expression over overlapping tokens."""
        while line_start < line_end and content[line_start] in (ord(" "), ord("\t")):
            line_start += 1

        equals = content.find(b"=", line_start, line_end)
        if equals < 0:
            return False
        name_end = equals
        while name_end > line_start and content[name_end - 1] in (ord(" "), ord("\t")):
            name_end -= 1
        if name_end == line_start:
            return False

        name = content[line_start:name_end].lower()
        if not all(
            ord("a") <= byte <= ord("z")
            or ord("0") <= byte <= ord("9")
            or byte == ord("_")
            for byte in name
        ) or not any(marker in name for marker in _NINTENDO_KEY_MARKERS):
            return False

        value_start = equals + 1
        while value_start < line_end and content[value_start] in (
            ord(" "),
            ord("\t"),
        ):
            value_start += 1
        if content[value_start : value_start + 2].lower() == b"0x":
            value_start += 2

        value_end = value_start
        while value_end < line_end:
            byte = content[value_end]
            if not (
                ord("0") <= byte <= ord("9")
                or ord("a") <= byte <= ord("f")
                or ord("A") <= byte <= ord("F")
            ):
                break
            value_end += 1
        if not 32 <= value_end - value_start <= 128:
            return False

        suffix_start = value_end
        while suffix_start < line_end and content[suffix_start] in (
            ord(" "),
            ord("\t"),
        ):
            suffix_start += 1
        if suffix_start < line_end and content[suffix_start] != ord("#"):
            return False

        first = content[value_start]
        if ord("A") <= first <= ord("F"):
            first += ord("a") - ord("A")
        for position in range(value_start + 1, value_end):
            byte = content[position]
            if ord("A") <= byte <= ord("F"):
                byte += ord("a") - ord("A")
            if byte != first:
                return True
        return False

    def _is_prohibited_filename(self, path: str) -> bool:
        """Recognize obvious key, ticket, certificate, and credential-store names."""
        name = path.rsplit("/", 1)[-1].casefold()
        if name.startswith(".env"):
            return True
        if name in {
            "prod.keys",
            "dev.keys",
            "title.keys",
            "console.keys",
            "credentials",
            "credentials.json",
            "credentials.ini",
            "secrets",
            "secrets.json",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
        }:
            return True
        if name.startswith("credentials.") or name.startswith("secrets."):
            return True
        if name.endswith((".tik", ".ticket", ".cert", ".p12", ".pfx", ".pem", ".jks")):
            return True
        return False

    def _validate_registry(
        self,
        snapshot: str,
        registry_bytes: bytes | None,
        file_info: dict[str, FileInfo],
        tracked_paths: set[str],
        required: bool,
    ) -> None:
        """Validate one registry against only the file versions in its snapshot."""
        if registry_bytes is None:
            if required or any(item.is_binary for item in file_info.values()):
                self._add_finding(snapshot, "REGISTRY_MISSING", REGISTRY_PATH)
            for path, item in file_info.items():
                if item.is_binary:
                    self._add_finding(snapshot, "BINARY_UNREGISTERED", path)
            return

        document = self._parse_registry(snapshot, registry_bytes)
        if document is None:
            for path, item in file_info.items():
                if item.is_binary:
                    self._add_finding(snapshot, "BINARY_UNREGISTERED", path)
            return
        registered: set[str] = set()
        for entry in document:
            path = entry["path"]
            registered.add(path)
            item = file_info.get(path)
            if path not in tracked_paths:
                self._add_finding(snapshot, "FIXTURE_UNTRACKED", path)
            if item is None:
                self._add_finding(snapshot, "FIXTURE_MISSING", path)
                continue
            if not item.is_binary:
                self._add_finding(snapshot, "FIXTURE_NOT_BINARY", path)
            if item.sha256 != entry["sha256"]:
                self._add_finding(snapshot, "FIXTURE_HASH_MISMATCH", path)

        for path, item in file_info.items():
            if item.is_binary and path not in registered:
                self._add_finding(snapshot, "BINARY_UNREGISTERED", path)

    def _parse_registry(
        self, snapshot: str, content: bytes
    ) -> list[dict[str, Any]] | None:
        """Parse and validate the version-one registry without echoing its contents."""
        try:
            text = content.decode("utf-8", errors="strict")
            document = json.loads(text, object_pairs_hook=self._unique_json_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._add_finding(snapshot, "REGISTRY_INVALID", REGISTRY_PATH)
            return None
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "fixtures"}
            or document.get("schema_version") != 1
            or not isinstance(document.get("schema_version"), int)
            or isinstance(document.get("schema_version"), bool)
            or not isinstance(document.get("fixtures"), list)
            or len(document["fixtures"]) > MAX_FILES
        ):
            self._add_finding(snapshot, "REGISTRY_INVALID", REGISTRY_PATH)
            return None

        parsed: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        valid = True
        for entry in document["fixtures"]:
            if not isinstance(entry, dict) or set(entry) != {
                "path",
                "sha256",
                "source",
                "provenance",
                "license_basis",
            }:
                valid = False
                continue
            path = entry.get("path")
            sha256 = entry.get("sha256")
            source = entry.get("source")
            license_basis = entry.get("license_basis")
            provenance = entry.get("provenance")
            if not isinstance(path, str):
                valid = False
                continue
            try:
                self._validate_registry_path(path)
            except CheckerFailure:
                valid = False
                continue
            if path in seen_paths:
                valid = False
                continue
            seen_paths.add(path)
            if not isinstance(sha256, str) or not _LOWER_SHA256.fullmatch(sha256):
                valid = False
                continue
            if not self._valid_description(source) or not self._valid_description(license_basis):
                valid = False
                continue
            if not self._valid_provenance(provenance):
                valid = False
                continue
            parsed.append({"path": path, "sha256": sha256})

        if not valid:
            self._add_finding(snapshot, "REGISTRY_INVALID", REGISTRY_PATH)
            return None
        return parsed

    def _unique_json_object(self, pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """Reject duplicate object keys instead of accepting an ambiguous registry."""
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    def _validate_registry_path(self, path: str) -> None:
        """Apply Git-independent path checks to registry references."""
        self._validate_repository_path(path)

    def _valid_description(self, value: Any) -> bool:
        """Require bounded, nonempty provenance text without control characters."""
        return (
            isinstance(value, str)
            and 0 < len(value.strip()) <= 1024
            and all(character.isprintable() or character in "\t\n" for character in value)
        )

    def _valid_provenance(self, value: Any) -> bool:
        """Require generator details for synthetic assets and evidence for others."""
        if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
            return False
        kind = value["kind"]
        if kind == "synthetic":
            return (
                set(value) == {"kind", "generator", "reproduction"}
                and self._valid_description(value.get("generator"))
                and self._valid_description(value.get("reproduction"))
            )
        if kind == "redistributable":
            return set(value) == {"kind", "details"} and self._valid_description(
                value.get("details")
            )
        return False

    def _add_finding(self, snapshot: str, rule: str, path: str) -> None:
        """Retain at most the display limit and count every omitted finding."""
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append(Finding(snapshot, rule, path))
        else:
            self.omitted_findings += 1


def _display_path(path: str) -> str:
    """Escape, redact, and bound a repository-relative diagnostic path."""
    safe = _PATH_CREDENTIAL.sub("[redacted]", path)
    safe = safe[:MAX_DISPLAY_PATH]
    return json.dumps(safe, ensure_ascii=True)


def _print_failure(failure: CheckerFailure) -> None:
    """Write one bounded checker diagnostic without subprocess details."""
    suffix = f" path={_display_path(failure.path)}" if failure.path else ""
    print(f"ERROR {failure.code}{suffix}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    """Run the checker and return 0 for pass, 1 for findings, or 2 for failure."""
    if sys.version_info < (3, 11):
        print("ERROR PYTHON_VERSION", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository directory to inspect (defaults to the current directory)",
    )
    arguments = parser.parse_args(argv)
    try:
        checker = ContentPolicyChecker(arguments.root)
        findings = checker.run()
    except CheckerFailure as failure:
        _print_failure(failure)
        return 2
    except (MemoryError, RecursionError):
        print("ERROR CHECKER_RESOURCE_FAILURE", file=sys.stderr)
        return 2

    if findings:
        lines = sorted(
            f"{finding.snapshot}_{finding.rule} path={_display_path(finding.path)}"
            for finding in findings
        )
        for line in lines:
            print(line)
        if checker.omitted_findings:
            print(f"FINDINGS_TRUNCATED omitted={checker.omitted_findings}")
        return 1

    print("Content policy passed for the Git index and working tree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
