"""Prepare the pinned PAC-6 source and hash-locked Windows wheelhouse."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

UPSTREAM_URL = "https://github.com/julesontheroad/NSC_BUILDER.git"
UPSTREAM_COMMIT = "92690c0137f520b6ee4d6c20b6f5abe8a3ce5738"
UPSTREAM_TREE = "358d753fe6cca11d5de8a2c60f7c1f25dad88442"
LOCK_RELATIVE_PATH = Path("qualification/pac6/requirements-win-cp312.lock")
SCRIPT_NAMES = ("fixture.py", "run_matrix.py", "block-python-egress.ps1", "wfp_audit.py")
EXCLUDED_KEY_FILES = {"keys_template.txt", "title.keys", "prod.keys", "dev.keys", "keys.txt"}


def digest_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def run(args: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return completed.stdout.strip()


def isolated_git_environment() -> dict[str, str]:
    names = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "PATHEXT")
    env = {key: os.environ[key] for key in names if key in os.environ}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = "NUL"
    return env


def validate_lock(lock_path: Path) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    for raw_line in lock_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name_version, hash_arg = line.split()
        name, version = name_version.split("==", 1)
        prefix = "--hash=sha256:"
        if not hash_arg.startswith(prefix):
            raise ValueError(f"lock entry lacks a SHA-256 hash: {name}")
        normalized = name.lower().replace("_", "-").replace(".", "-")
        if normalized in entries:
            raise ValueError(f"duplicate dependency in lock: {name}")
        entries[normalized] = (version, hash_arg[len(prefix) :])
    if not entries:
        raise ValueError("dependency lock is empty")
    return entries


def make_source_archive(repo: Path, output: Path, git_env: dict[str, str]) -> list[str]:
    raw_archive = output.with_suffix(".full.tar")
    run(
        ["git", "-c", "credential.helper=", "archive", "--format=tar", f"--output={raw_archive}", "HEAD", "py/ztools"],
        cwd=repo,
        env=git_env,
    )
    excluded: list[str] = []
    with tarfile.open(raw_archive, "r:") as original, tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as filtered:
        for member in original:
            path = PurePosixPath(member.name)
            if path.name.lower() in EXCLUDED_KEY_FILES or path.suffix.lower() in {".keys", ".key"}:
                excluded.append(member.name)
                continue
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise ValueError(f"unexpected non-regular source entry: {member.name}")
            if member.isfile():
                source = original.extractfile(member)
                if source is None:
                    raise OSError(f"unable to read pinned source file: {member.name}")
                filtered.addfile(member, source)
            else:
                filtered.addfile(member)
    raw_archive.unlink()
    if not any(name.endswith("/squirrel.py") for name in _archive_names(output)):
        raise ValueError("pinned source archive is missing squirrel.py")
    return sorted(excluded)


def _archive_names(path: Path) -> list[str]:
    with tarfile.open(path, "r:") as archive:
        return [member.name for member in archive]


def wheel_metadata(path: Path) -> tuple[str, str]:
    with ZipFile(path) as wheel:
        metadata_name = next(
            name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = BytesParser().parsebytes(wheel.read(metadata_name))
        return metadata["Name"], metadata["Version"]


def main() -> None:
    if sys.platform != "win32" or sys.version_info[:3] != (3, 12, 10):
        raise SystemExit("PAC-6 preparation requires the pinned CPython 3.12.10 Windows runtime")
    if os.environ.get("PAC6_HEAD_SHA") != os.environ.get("GITHUB_HEAD_SHA"):
        raise SystemExit("the checked-out task revision does not match the pull request head")

    checkout = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    work = runner_temp / "pac6-preparation"
    bundle = work / "bundle"
    source_repo = work / "upstream-source"
    wheelhouse = bundle / "wheelhouse"
    if work.exists():
        shutil.rmtree(work)
    wheelhouse.mkdir(parents=True)
    source_repo.mkdir(parents=True)

    git_env = isolated_git_environment()
    checked_out_head = run(["git", "rev-parse", "HEAD"], cwd=checkout, env=git_env)
    if checked_out_head != os.environ["PAC6_HEAD_SHA"]:
        raise SystemExit("the qualification checkout is not the approved pull request head")

    credential_config = subprocess.run(
        ["git", "config", "--local", "--get-regexp", r"^http\..*extraheader$"],
        cwd=checkout,
        env=git_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if credential_config.returncode == 0 and credential_config.stdout.strip():
        raise SystemExit("checkout credentials were persisted in local Git configuration")

    run(["git", "init", "--quiet"], cwd=source_repo, env=git_env)
    run(["git", "-c", "credential.helper=", "fetch", "--depth=1", "--no-tags", UPSTREAM_URL, UPSTREAM_COMMIT], cwd=source_repo, env=git_env)
    run(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=source_repo, env=git_env)
    actual_commit = run(["git", "rev-parse", "HEAD"], cwd=source_repo, env=git_env)
    actual_tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=source_repo, env=git_env)
    if (actual_commit, actual_tree) != (UPSTREAM_COMMIT, UPSTREAM_TREE):
        raise SystemExit("the fetched consumer source does not match the pinned commit and tree")

    source_archive = bundle / "consumer-source.tar"
    excluded_key_files = make_source_archive(source_repo, source_archive, git_env)

    lock_source = checkout / LOCK_RELATIVE_PATH
    expected_distributions = validate_lock(lock_source)
    lock_copy = bundle / "requirements-win-cp312.lock"
    shutil.copyfile(lock_source, lock_copy)
    pip_version = run([sys.executable, "-m", "pip", "--version"], env=git_env)
    pip_env = git_env.copy()
    pip_env["PIP_CONFIG_FILE"] = "NUL"
    run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--disable-pip-version-check",
            "--no-deps",
            "--only-binary=:all:",
            "--require-hashes",
            "--index-url",
            "https://pypi.org/simple",
            "--dest",
            str(wheelhouse),
            "-r",
            str(lock_copy),
        ],
        env=pip_env,
    )

    distributions = []
    for path in sorted(wheelhouse.glob("*.whl")):
        name, version = wheel_metadata(path)
        normalized = name.lower().replace("_", "-").replace(".", "-")
        expected = expected_distributions.get(normalized)
        wheel_hash = digest_file(path)
        if expected != (version, wheel_hash):
            raise SystemExit(f"wheel does not match the reviewed lock: {path.name}")
        distributions.append(
            {
                "name": name,
                "version": version,
                "filename": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": wheel_hash,
            }
        )
    if len(distributions) != len(expected_distributions):
        raise SystemExit("downloaded wheel set does not match the dependency lock")
    if not distributions:
        raise SystemExit("the pinned dependency lock produced no Windows wheels")

    scripts = Path(__file__).resolve().parent
    for script_name in SCRIPT_NAMES:
        shutil.copyfile(scripts / script_name, bundle / script_name)

    dependency_manifest = {
        "python": sys.version,
        "pip": pip_version,
        "wheel_platform": "CPython 3.12, Windows x64",
        "index_url": "https://pypi.org/simple",
        "lock_sha256": digest_file(lock_copy),
        "distributions": distributions,
    }
    (bundle / "dependency-manifest.json").write_text(
        json.dumps(dependency_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    bundled_files = {}
    for path in sorted(bundle.rglob("*")):
        if path.is_file() and path.name != "bundle-manifest.json":
            bundled_files[path.relative_to(bundle).as_posix()] = digest_file(path)
    manifest = {
        "schema_version": 1,
        "task": "NSCB Issue 14 Slice C PAC-6",
        "tested_revision": os.environ["PAC6_HEAD_SHA"],
        "consumer_source": {
            "repository": UPSTREAM_URL,
            "commit": actual_commit,
            "tree": actual_tree,
            "archive_sha256": digest_file(source_archive),
            "excluded_key_data_files": excluded_key_files,
        },
        "dependencies": dependency_manifest,
        "bundle_files": bundled_files,
    }
    (bundle / "bundle-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "tested_revision": manifest["tested_revision"],
        "consumer_commit": actual_commit,
        "consumer_tree": actual_tree,
        "dependency_count": len(distributions),
        "wheelhouse_bytes": sum(item["size_bytes"] for item in distributions),
        "lock_sha256": dependency_manifest["lock_sha256"],
        "bundle_manifest": str(bundle / "bundle-manifest.json"),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
