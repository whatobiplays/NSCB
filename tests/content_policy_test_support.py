"""Test-only support for exercising content policy without a Git repository.

The fixture models the small, read-only slice of Git used by
``scripts/check_content_policy.py``. It owns an isolated index, immutable blobs,
and independent worktree path registries. It deliberately does not model refs,
commits, packs, or a general object database.

Routine tests use the fixture through ``ContentPolicyChecker(..., runner=...)``.
The command output format also lets a small fake ``git`` executable exercise the
real command-line entry point without creating a ``.git`` directory.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping


class UnsupportedGitCommand(RuntimeError):
    """Raised when a test asks the synthetic Git model for unsupported behavior."""


class ProhibitedGitOperation(RuntimeError):
    """Raised when a routine test attempts a Git command or metadata creation."""


class ProhibitedGitMetadata(ProhibitedGitOperation):
    """Raised when a routine test attempts to create repository metadata."""


@dataclass(frozen=True)
class InMemoryIndexEntry:
    """One index record, including conflict stages where applicable."""

    mode: str
    object_id: str
    stage: int
    path: str


class InMemoryGitFixture:
    """A bounded, test-only model of the Git index and visible worktree paths."""

    def __init__(self, root: Path) -> None:
        self.root = Path(os.path.realpath(root))
        self._blobs: dict[str, bytes] = {}
        self._staged: dict[str, InMemoryIndexEntry] = {}
        self._conflicts: dict[str, dict[int, InMemoryIndexEntry]] = {}
        self._untracked: set[str] = set()
        self._ignored: set[str] = set()

    @property
    def staged_paths(self) -> frozenset[str]:
        """Return stage-zero paths without exposing mutable state."""
        return frozenset(self._staged)

    @property
    def untracked_paths(self) -> frozenset[str]:
        """Return nonignored untracked paths."""
        return frozenset(self._untracked)

    @property
    def ignored_paths(self) -> frozenset[str]:
        """Return ignored paths."""
        return frozenset(self._ignored)

    def stage(
        self,
        path: str,
        data: bytes | None = None,
        *,
        algorithm: str = "sha1",
        mode: str = "100644",
    ) -> str:
        """Write a worktree file and add its immutable blob at stage zero."""
        self._validate_path(path)
        if mode not in {"100644", "100755"}:
            raise ValueError("unsupported synthetic index mode")
        if data is None:
            data = (self.root / path).read_bytes()
        object_id = self._store_blob(data, algorithm=algorithm)
        entry = InMemoryIndexEntry(mode, object_id, 0, path)
        self._staged[path] = entry
        self._conflicts.pop(path, None)
        self._untracked.discard(path)
        self._ignored.discard(path)
        self._write_worktree(path, data)
        return object_id

    def unstage(self, path: str, *, keep_worktree: bool = True) -> None:
        """Remove a stage-zero entry, leaving a nonignored file untracked."""
        self._validate_path(path)
        removed = self._staged.pop(path, None)
        if removed is None:
            raise ValueError(f"path is not staged: {path}")
        self._conflicts.pop(path, None)
        if keep_worktree and (self.root / path).exists() and path not in self._ignored:
            self._untracked.add(path)

    def edit(self, path: str, data: bytes) -> None:
        """Change only the worktree bytes for a staged or untracked path."""
        self._validate_path(path)
        self._write_worktree(path, data)
        if path not in self._staged and path not in self._conflicts:
            if path not in self._ignored:
                self._untracked.add(path)

    def delete(self, path: str) -> None:
        """Delete only the worktree path; the index entry remains unchanged."""
        self._validate_path(path)
        self._untracked.discard(path)
        try:
            (self.root / path).unlink()
        except FileNotFoundError:
            pass

    def stage_deletion(self, path: str) -> None:
        """Delete a path from both the worktree and the stage-zero index."""
        self._validate_path(path)
        self._staged.pop(path, None)
        self._conflicts.pop(path, None)
        self._untracked.discard(path)
        self._ignored.discard(path)
        self.delete(path)

    def ignore(self, path: str, data: bytes | None = None) -> None:
        """Create or mark an untracked path as ignored."""
        self._validate_path(path)
        if path in self._staged or path in self._conflicts:
            raise ValueError("an indexed path cannot be ignored in the synthetic fixture")
        if data is not None:
            self._write_worktree(path, data)
        self._untracked.discard(path)
        self._ignored.add(path)

    def mark_untracked(self, path: str, data: bytes) -> None:
        """Write a nonignored untracked worktree path."""
        self._validate_path(path)
        if path in self._staged or path in self._conflicts:
            raise ValueError("an indexed path cannot become untracked without unstaging")
        self._ignored.discard(path)
        self._write_worktree(path, data)
        self._untracked.add(path)

    def register_untracked_path(self, path: str) -> None:
        """Record a pre-created untracked path such as a symlink or FIFO."""
        self._validate_path(path)
        if path in self._staged or path in self._conflicts:
            raise ValueError("an indexed path cannot become untracked without unstaging")
        self._ignored.discard(path)
        self._untracked.add(path)

    def conflict(
        self,
        path: str,
        stages: Mapping[int, bytes] | None = None,
        *,
        algorithm: str = "sha1",
        mode: str = "100644",
    ) -> None:
        """Create stage 1, 2, and 3 records for an unmerged path."""
        self._validate_path(path)
        stage_data = dict(stages or {1: b"base\n", 2: b"ours\n", 3: b"theirs\n"})
        if set(stage_data) != {1, 2, 3}:
            raise ValueError("conflict fixtures require exactly stages 1, 2, and 3")
        records: dict[int, InMemoryIndexEntry] = {}
        for stage, data in stage_data.items():
            object_id = self._store_blob(data, algorithm=algorithm)
            records[stage] = InMemoryIndexEntry(mode, object_id, stage, path)
        self._staged.pop(path, None)
        self._conflicts[path] = records
        self._untracked.discard(path)
        self._ignored.discard(path)
        self._write_worktree(path, b"<<<<<<< conflict\n")

    def command_output(self, arguments: list[str]) -> bytes:
        """Return the exact stdout for one supported read-only Git command."""
        if arguments == ["rev-parse", "--show-toplevel"]:
            return os.fsencode(str(self.root)) + b"\n"
        if arguments == ["ls-files", "--unmerged", "-z"]:
            records: list[InMemoryIndexEntry] = []
            for path in sorted(self._conflicts):
                records.extend(self._conflicts[path][stage] for stage in (1, 2, 3))
            return b"".join(self._format_record(entry) for entry in records)
        if arguments == ["ls-files", "--stage", "-z"]:
            return b"".join(
                self._format_record(self._staged[path]) for path in sorted(self._staged)
            )
        if arguments == ["ls-files", "--others", "--exclude-standard", "-z"]:
            return b"".join(
                os.fsencode(path) + b"\0"
                for path in sorted(self._untracked - self._ignored)
            )
        if len(arguments) == 3 and arguments[:2] == ["cat-file", "-s"]:
            return str(len(self._blob(arguments[2]))).encode("ascii")
        if len(arguments) == 3 and arguments[:2] == ["cat-file", "blob"]:
            return self._blob(arguments[2])
        raise UnsupportedGitCommand("unsupported synthetic Git command")

    def run_command(
        self,
        root: Path,
        arguments: list[str],
        *,
        max_output_bytes: int,
        timeout_seconds: float,
        nonzero_exit_code: str,
    ) -> bytes:
        """Serve one checker command using the in-memory model."""
        from check_content_policy import CheckerFailure

        del nonzero_exit_code
        if Path(os.path.realpath(root)) != self.root:
            raise CheckerFailure("ROOT_NOT_REPOSITORY")
        if max_output_bytes < 0:
            raise CheckerFailure("GIT_OUTPUT_LIMIT")
        if timeout_seconds <= 0:
            raise CheckerFailure("GIT_COMMAND_TIMEOUT")
        output = self.command_output(arguments)
        if len(output) > max_output_bytes:
            raise CheckerFailure("GIT_OUTPUT_LIMIT")
        return output

    def export_state(self) -> dict[str, object]:
        """Serialize model state for the fake command-line Git executable."""
        return {
            "root": str(self.root),
            "blobs": {
                object_id: base64.b64encode(data).decode("ascii")
                for object_id, data in sorted(self._blobs.items())
            },
            "staged": [self._entry_state(entry) for entry in self._staged.values()],
            "conflicts": [
                self._entry_state(entry)
                for records in self._conflicts.values()
                for entry in records.values()
            ],
            "untracked": sorted(self._untracked),
            "ignored": sorted(self._ignored),
        }

    @classmethod
    def from_state(cls, state: Mapping[str, object]) -> InMemoryGitFixture:
        """Recreate a fixture from ``export_state`` output."""
        fixture = cls(Path(str(state["root"])))
        raw_blobs = state.get("blobs", {})
        if not isinstance(raw_blobs, dict):
            raise ValueError("invalid synthetic blob state")
        fixture._blobs = {
            str(object_id): base64.b64decode(str(encoded), validate=True)
            for object_id, encoded in raw_blobs.items()
        }
        for raw_entry in state.get("staged", []):
            entry = cls._entry_from_state(raw_entry)
            if entry.stage != 0:
                raise ValueError("invalid stage-zero synthetic state")
            fixture._staged[entry.path] = entry
        for raw_entry in state.get("conflicts", []):
            entry = cls._entry_from_state(raw_entry)
            if entry.stage not in {1, 2, 3}:
                raise ValueError("invalid conflict-stage synthetic state")
            fixture._conflicts.setdefault(entry.path, {})[entry.stage] = entry
        fixture._untracked = {str(path) for path in state.get("untracked", [])}
        fixture._ignored = {str(path) for path in state.get("ignored", [])}
        return fixture

    def _store_blob(self, data: bytes, *, algorithm: str) -> str:
        if algorithm not in {"sha1", "sha256"}:
            raise ValueError("unsupported synthetic object format")
        digest = hashlib.new(algorithm, data).hexdigest()
        existing = self._blobs.get(digest)
        if existing is not None and existing != data:
            raise ValueError("synthetic object IDs must remain immutable")
        self._blobs[digest] = data
        return digest

    def _blob(self, object_id: str) -> bytes:
        try:
            return self._blobs[object_id]
        except KeyError as error:
            raise UnsupportedGitCommand("unknown synthetic Git object") from error

    def _write_worktree(self, path: str, data: bytes) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def _format_record(self, entry: InMemoryIndexEntry) -> bytes:
        metadata = f"{entry.mode} {entry.object_id} {entry.stage}\t".encode("ascii")
        return metadata + os.fsencode(entry.path) + b"\0"

    def _validate_path(self, path: str) -> None:
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or path == ".git"
            or path.startswith(".git/")
        ):
            raise ValueError("unsafe synthetic repository path")

    @staticmethod
    def _entry_state(entry: InMemoryIndexEntry) -> dict[str, object]:
        return {
            "mode": entry.mode,
            "object_id": entry.object_id,
            "stage": entry.stage,
            "path": entry.path,
        }

    @staticmethod
    def _entry_from_state(raw_entry: object) -> InMemoryIndexEntry:
        if not isinstance(raw_entry, dict):
            raise ValueError("invalid synthetic index entry")
        return InMemoryIndexEntry(
            str(raw_entry["mode"]),
            str(raw_entry["object_id"]),
            int(raw_entry["stage"]),
            str(raw_entry["path"]),
        )


class RoutineGitGuard:
    """Fail-closed test guard against real Git mutation and ``.git`` creation."""

    _ALLOWED_SUBCOMMANDS = frozenset({"rev-parse", "ls-files", "cat-file"})
    _VALUE_OPTIONS = frozenset(
        {
            "-C",
            "-c",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--config-env",
        }
    )

    def __init__(self, roots: Iterable[Path]) -> None:
        self.roots = tuple(Path(os.path.realpath(root)) for root in roots)
        self._originals: list[tuple[object, str, object]] = []

    def start(self) -> None:
        """Install subprocess and filesystem guards."""
        if self._originals:
            raise RuntimeError("the routine Git guard is already active")
        self._replace(subprocess, "Popen", self._guard_popen)
        self._replace(os, "system", self._guard_system)
        for name, guard in (
            ("execv", self._guard_execv),
            ("execve", self._guard_execve),
            ("execl", self._guard_execl),
            ("execlp", self._guard_execlp),
            ("execvp", self._guard_execvp),
            ("execvpe", self._guard_execvpe),
            ("spawnv", self._guard_spawnv),
            ("spawnve", self._guard_spawnve),
            ("spawnl", self._guard_spawnl),
            ("spawnle", self._guard_spawnle),
            ("spawnlp", self._guard_spawnlp),
            ("spawnlpe", self._guard_spawnlpe),
            ("spawnvp", self._guard_spawnvp),
            ("spawnvpe", self._guard_spawnvpe),
            ("posix_spawn", self._guard_posix_spawn),
            ("posix_spawnp", self._guard_posix_spawnp),
            ("startfile", self._guard_startfile),
        ):
            if hasattr(os, name):
                self._replace(os, name, guard)
        self._replace(os, "mkdir", self._guard_mkdir)
        self._replace(os, "symlink", self._guard_symlink)
        self._replace(os, "rename", self._guard_rename)
        self._replace(os, "replace", self._guard_replace)

    def stop(self) -> None:
        """Restore every wrapped callable, including after a failed test."""
        while self._originals:
            owner, name, original = self._originals.pop()
            setattr(owner, name, original)

    def assert_no_git_metadata(self, root: Path) -> None:
        """Fail if any test-created path is named ``.git``."""
        root = Path(root)
        for directory, names, _files in os.walk(root, followlinks=False):
            for name in names:
                if name == ".git":
                    raise ProhibitedGitMetadata(
                        f"routine test created Git metadata below {directory}"
                    )

    def _replace(self, owner: object, name: str, replacement: object) -> None:
        original = getattr(owner, name)
        self._originals.append((owner, name, original))
        setattr(owner, name, replacement)

    def _guard_popen(self, command: object, *args: object, **kwargs: object) -> object:
        self.assert_command_allowed(command, shell=bool(kwargs.get("shell", False)))
        original = self._original("Popen")
        return original(command, *args, **kwargs)

    def _guard_system(self, command: str) -> int:
        self.assert_command_allowed(command, shell=True)
        original = self._original("system")
        return original(command)

    def _guard_execv(self, path: object, args: object) -> object:
        self.assert_process_allowed(path, args)
        return self._original("execv")(path, args)

    def _guard_execve(self, path: object, args: object, env: object) -> object:
        self.assert_process_allowed(path, args)
        return self._original("execve")(path, args, env)

    def _guard_execl(self, path: object, arg0: object, *args: object) -> object:
        self.assert_process_allowed(path, (arg0, *args))
        return self._original("execl")(path, arg0, *args)

    def _guard_execlp(self, file: object, arg0: object, *args: object) -> object:
        self.assert_process_allowed(file, (arg0, *args))
        return self._original("execlp")(file, arg0, *args)

    def _guard_execvp(self, file: object, args: object) -> object:
        self.assert_process_allowed(file, args)
        return self._original("execvp")(file, args)

    def _guard_execvpe(self, file: object, args: object, env: object) -> object:
        self.assert_process_allowed(file, args)
        return self._original("execvpe")(file, args, env)

    def _guard_spawnv(self, mode: int, path: object, args: object) -> int:
        self.assert_process_allowed(path, args)
        return self._original("spawnv")(mode, path, args)

    def _guard_spawnve(self, mode: int, path: object, args: object, env: object) -> int:
        self.assert_process_allowed(path, args)
        return self._original("spawnve")(mode, path, args, env)

    def _guard_spawnl(self, mode: int, path: object, arg0: object, *args: object) -> int:
        self.assert_process_allowed(path, (arg0, *args))
        return self._original("spawnl")(mode, path, arg0, *args)

    def _guard_spawnle(self, mode: int, path: object, arg0: object, *args: object) -> int:
        # The final positional argument is the child environment, not argv.
        self.assert_process_allowed(path, (arg0, *args[:-1]))
        return self._original("spawnle")(mode, path, arg0, *args)

    def _guard_spawnlp(self, mode: int, file: object, arg0: object, *args: object) -> int:
        self.assert_process_allowed(file, (arg0, *args))
        return self._original("spawnlp")(mode, file, arg0, *args)

    def _guard_spawnlpe(self, mode: int, file: object, arg0: object, *args: object) -> int:
        # The final positional argument is the child environment, not argv.
        self.assert_process_allowed(file, (arg0, *args[:-1]))
        return self._original("spawnlpe")(mode, file, arg0, *args)

    def _guard_spawnvp(self, mode: int, file: object, args: object) -> int:
        self.assert_process_allowed(file, args)
        return self._original("spawnvp")(mode, file, args)

    def _guard_spawnvpe(self, mode: int, file: object, args: object, env: object) -> int:
        self.assert_process_allowed(file, args)
        return self._original("spawnvpe")(mode, file, args, env)

    def _guard_posix_spawn(
        self, path: object, argv: object, env: object, **kwargs: object
    ) -> int:
        self.assert_process_allowed(path, argv)
        return self._original("posix_spawn")(path, argv, env, **kwargs)

    def _guard_posix_spawnp(
        self, file: object, argv: object, env: object, **kwargs: object
    ) -> int:
        self.assert_process_allowed(file, argv)
        return self._original("posix_spawnp")(file, argv, env, **kwargs)

    def _guard_startfile(
        self,
        path: object,
        operation: object = None,
        arguments: object = None,
        cwd: object = None,
        show_cmd: object = None,
    ) -> None:
        self.assert_command_allowed(path, shell=False)
        return self._original("startfile")(path, operation, arguments, cwd, show_cmd)

    def _guard_mkdir(self, path: object, *args: object, **kwargs: object) -> None:
        self.assert_metadata_path_allowed(path)
        original = self._original("mkdir")
        return original(path, *args, **kwargs)

    def _guard_symlink(self, src: object, dst: object, *args: object, **kwargs: object) -> None:
        self.assert_metadata_path_allowed(dst)
        original = self._original("symlink")
        return original(src, dst, *args, **kwargs)

    def _guard_rename(self, src: object, dst: object, *args: object, **kwargs: object) -> None:
        self.assert_metadata_path_allowed(dst)
        original = self._original("rename")
        return original(src, dst, *args, **kwargs)

    def _guard_replace(self, src: object, dst: object, *args: object, **kwargs: object) -> None:
        self.assert_metadata_path_allowed(dst)
        original = self._original("replace")
        return original(src, dst, *args, **kwargs)

    def _original(self, name: str) -> object:
        for owner, original_name, original in reversed(self._originals):
            if original_name == name:
                return original
        raise RuntimeError("routine Git guard is not active")

    def assert_process_allowed(self, path: object, args: object) -> None:
        """Validate an executable path and argv before a low-level launch."""
        arguments = [os.fsdecode(argument) for argument in args]  # type: ignore[arg-type]
        self.assert_command_allowed(arguments, shell=False)
        executable = Path(os.fsdecode(path))
        if executable.name.casefold() in {"git", "git.exe"}:
            if not arguments:
                raise ProhibitedGitOperation("could not determine Git subcommand")
            tokens = [str(executable), *arguments[1:]]
            subcommand = self._git_subcommand(tokens, 1)
            if subcommand not in self._ALLOWED_SUBCOMMANDS:
                raise ProhibitedGitOperation(
                    f"routine tests may not execute Git subcommand {subcommand!r}"
                )

    def assert_command_allowed(self, command: object, *, shell: bool) -> None:
        """Reject every Git command outside the synthetic read-only surface."""
        if isinstance(command, (str, bytes, os.PathLike)):
            text = os.fsdecode(command)
            try:
                tokens = shlex.split(text)
            except ValueError as error:
                if "git" in text.casefold():
                    raise ProhibitedGitOperation("could not parse shell command") from error
                return
        else:
            tokens = [os.fsdecode(token) for token in command]  # type: ignore[arg-type]
            expanded: list[str] = []
            for index, token in enumerate(tokens):
                expanded.append(token)
                if token in {"-c", "/c"} and index + 1 < len(tokens):
                    try:
                        expanded.extend(shlex.split(tokens[index + 1]))
                    except ValueError as error:
                        if "git" in tokens[index + 1].casefold():
                            raise ProhibitedGitOperation(
                                "could not parse nested shell command"
                            ) from error
            tokens = expanded
        for index, token in enumerate(tokens):
            if Path(token).name.casefold() not in {"git", "git.exe"}:
                continue
            subcommand = self._git_subcommand(tokens, index + 1)
            if subcommand not in self._ALLOWED_SUBCOMMANDS:
                raise ProhibitedGitOperation(
                    f"routine tests may not execute Git subcommand {subcommand!r}"
                )
        if shell and not tokens:
            raise ProhibitedGitOperation("could not parse shell command")

    def assert_metadata_path_allowed(self, path: object) -> None:
        """Reject creation of any path whose components include ``.git``."""
        if ".git" in Path(os.fsdecode(path)).parts:
            raise ProhibitedGitMetadata("routine tests may not create .git metadata")

    def _git_subcommand(self, tokens: list[str], index: int) -> str:
        while index < len(tokens):
            token = tokens[index]
            if token in self._VALUE_OPTIONS:
                index += 2
                continue
            if token.startswith(
                (
                    "--git-dir=",
                    "--work-tree=",
                    "--namespace=",
                    "--config-env=",
                )
            ):
                index += 1
                continue
            if token.startswith("-"):
                index += 1
                continue
            return token
        raise ProhibitedGitOperation("could not determine Git subcommand")


def write_fake_git_script(
    path: Path,
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
    exit_code: int = 0,
    delay_seconds: float = 0.0,
    include_environment: bool = False,
) -> None:
    """Write a bounded fake Git executable for runner and CLI tests."""
    script = [
        f"#!{sys.executable}",
        "import base64",
        "import os",
        "import sys",
        "import time",
        f"time.sleep({delay_seconds!r})",
    ]
    if include_environment:
        script.extend(
            [
                "sys.stdout.buffer.write(",
                "    (os.environ.get('GIT_NO_REPLACE_OBJECTS', '') + '\\n' +",
                "     os.environ.get('GIT_NO_LAZY_FETCH', '')).encode('ascii')",
                ") ",
            ]
        )
    else:
        script.extend(
            [
                f"sys.stdout.buffer.write(base64.b64decode({base64.b64encode(stdout)!r}))",
            ]
        )
    script.extend(
        [
            "sys.stdout.buffer.flush()",
            f"sys.stderr.buffer.write(base64.b64decode({base64.b64encode(stderr)!r}))",
            "sys.stderr.buffer.flush()",
            f"raise SystemExit({exit_code})",
        ]
    )
    path.write_text("\n".join(script) + "\n", encoding="utf-8")
    path.chmod(0o755)
