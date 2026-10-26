"""Remove conventional target/ and Python bytecode from an idle Git worktree.

Only read-only Git queries are run. No Cargo command is needed. The operator
stops artifact producers before cleanup; ordinary filesystem operations suffice.
Exit 0 means complete, 1 means a category failed, 2 means cleanup was skipped,
and 130 means interrupted. Make maps nonzero recipe exits to 2.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib


PROTECTED = frozenset({
    ".git", ".chatgpt", ".serena", ".codegraph", ".tokensave", "docs", "src", ".cargo",
    ".venv", "venv", "virtualenv", "env", ".tox", ".nox", "__pypackages__", "operation",
    "fixtures", "providers", "provider", "provider-cache", "application-state",
    "application-data", "publication", "recovery", "node_modules", "vendor",
    "site-packages", "test-results", "coverage",
})
# Generated Cargo documentation and package trees legitimately contain source,
# manifests and fixtures. Only durable state namespaces veto whole-target removal.
CARGO_PROTECTED = PROTECTED - {"docs", "src", "fixtures", "vendor", "test-results", "coverage"}
MAX_DEPTH = 128


def protected(name: str, names=PROTECTED) -> bool:
    """Recognize durable namespaces, including common case aliases."""
    name = name.casefold()
    return name in names or name.startswith(".nscb-") or name.endswith(".nscb-split.json")


def git_metadata(root: Path) -> set[str]:
    """Verify this checkout and collect tracked paths without touching its index."""
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1")

    def query(*arguments: str) -> bytes:
        return subprocess.run(
            ["git", *arguments], cwd=root, env=environment, check=True,
            capture_output=True, timeout=15,
        ).stdout

    actual = Path(os.fsdecode(query("rev-parse", "--show-toplevel")).strip()).resolve()
    if actual != root:
        raise ValueError("worktree-root-mismatch")
    return {os.fsdecode(path).casefold() for path in query("ls-files", "-z").split(b"\0") if path}


def custom_cargo_location(root: Path) -> bool:
    """Detect custom locations without resolving them or invoking Cargo.

    Check both Cargo config spellings in the checkout's ancestors and Cargo
    home. Any custom location conservatively skips the Cargo category.
    """
    if any(os.environ.get(key) for key in (
        "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_BUILD_DIR",
    )):
        return True
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    if not cargo_home.is_absolute():
        cargo_home = root / cargo_home
    directories = [directory / ".cargo" for directory in (root, *root.parents)]
    directories.append(cargo_home)
    for directory in dict.fromkeys(directories):
        for name in ("config", "config.toml"):
            path = directory / name
            if path.is_file():
                document = tomllib.loads(path.read_text(encoding="utf-8"))
                build = document.get("build", {})
                if not isinstance(build, dict):
                    raise ValueError("invalid-cargo-configuration")
                if "target-dir" in build or "build-dir" in build:
                    return True
    return False


def entries(directory: Path):
    """Walk ordinary directories without following symlinked descendants."""
    def error(failure):
        raise failure
    return os.walk(directory, topdown=True, followlinks=False, onerror=error)


def clean_cargo(root: Path, tracked: set[str], result: dict) -> None:
    target = root / "target"
    if custom_cargo_location(root):
        result.update(status="skipped", reason="custom-cargo-location-outside-scope")
        return
    if target.is_symlink():
        result.update(status="skipped", reason="symlinked-target")
        return
    if not target.exists():
        return
    if not target.is_dir() or target.resolve().parent != root:
        result.update(status="skipped", reason="unexpected-target-root")
        return
    if any(path == "target" or path.startswith("target/") for path in tracked):
        result.update(status="skipped", reason="tracked-target-content")
        return
    files = byte_count = 0
    for directory, directories, names in entries(target):
        for name in directories + names:
            path = Path(directory) / name
            if protected(name, CARGO_PROTECTED):
                result.update(status="skipped", reason="protected-target-content")
                return
            if path.is_file() and not path.is_symlink():
                files += 1
                byte_count += path.stat().st_size
    # Internal generated lock files and unknown development output are disposable.
    shutil.rmtree(target)
    result.update(status="removed", files=files, bytes=byte_count)


def clean_python(root: Path, tracked: set[str], result: dict) -> None:
    """Remove untracked bytecode; retain unknown files and protected subtrees."""
    for name in ("scripts", "tests"):
        source = root / name
        if source.is_symlink():
            result.update(status="skipped", reason="symlinked-python-root")
            continue
        if not source.exists():
            continue
        caches = []
        for directory, directories, files in entries(source):
            parent = Path(directory)
            if len(parent.relative_to(source).parts) >= MAX_DEPTH:
                directories.clear()
                result.update(status="skipped", reason="python-depth-limit")
                continue
            if parent.name == "__pycache__":
                caches.append(parent)
            directories[:] = [child for child in directories if not protected(child) and not (parent / child).is_symlink()]
            for filename in files:
                path = parent / filename
                relative = path.relative_to(root).as_posix().casefold()
                if filename.endswith(".pyc") and not protected(filename) and relative not in tracked and not path.is_symlink() and path.is_file():
                    size = path.stat().st_size
                    path.unlink()
                    result["files"] += 1
                    result["bytes"] += size
                    if result["status"] != "skipped":
                        result["status"] = "removed"
        # Remove only empty cache directories so unknown and tracked files survive.
        for path in reversed(caches):
            if not any(path.iterdir()):
                path.rmdir()
                if result["status"] == "absent":
                    result["status"] = "removed"


def main(arguments=None) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    results = {name: dict(status="absent", files=0, bytes=0, reason="none") for name in ("cargo", "python")}
    try:
        cleaner = Path(__file__).absolute()
        root = cleaner.parent.parent.resolve()
        if arguments or cleaner.is_symlink() or cleaner.parent.is_symlink():
            raise ValueError("unexpected-arguments-or-cleaner-path")
        if Path.cwd().resolve() != root:
            raise ValueError("invoke-from-worktree-root")
        tracked = git_metadata(root)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        for result in results.values():
            result.update(status="skipped", reason=str(error).splitlines()[0])
    else:
        for name, action in (("cargo", clean_cargo), ("python", clean_python)):
            try:
                action(root, tracked, results[name])
            except KeyboardInterrupt:
                results[name].update(status="failed", reason="interrupted")
                report(results)
                return 130
            except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
                results[name].update(status="failed", reason=type(error).__name__)
    report(results)
    statuses = {result["status"] for result in results.values()}
    return 1 if "failed" in statuses else 2 if "skipped" in statuses else 0


def report(results: dict) -> None:
    """Report successful removals even when another category skips or fails."""
    for name, result in results.items():
        print(f"{name}: {result['status']} files={result['files']} bytes={result['bytes']} reason={result['reason']}")
    complete = all(result["status"] in {"removed", "absent"} for result in results.values())
    print("result=" + ("complete" if complete else "incomplete"))


if __name__ == "__main__":
    raise SystemExit(main())
