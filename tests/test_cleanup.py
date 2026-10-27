"""Git-free cleanup tests; every deletion is confined to a temporary fixture."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from content_policy_test_support import RoutineGitGuard


REPOSITORY = Path(__file__).resolve().parents[1]


class CleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="nscb-simple-clean-")
        self.sandbox = Path(self.temporary.name).resolve()
        self.guard = RoutineGitGuard([self.sandbox])
        self.guard.start()
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(self.guard.stop)
        self.root = self.sandbox / "checkout with spaces"
        (self.root / "scripts").mkdir(parents=True)
        shutil.copy2(REPOSITORY / "scripts/clean.py", self.root / "scripts/clean.py")
        shutil.copy2(REPOSITORY / "Makefile", self.root / "Makefile")
        self.bin = self.sandbox / "bin"
        self.bin.mkdir()
        git = self.bin / "git"
        git.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "args = sys.argv[1:]\n"
            "if args == ['rev-parse', '--show-toplevel']:\n"
            "    print(os.environ['FAKE_ROOT'])\n"
            "elif args == ['ls-files', '-z']:\n"
            "    sys.stdout.buffer.write(b''.join(p.encode() + b'\\0' for p in json.loads(os.environ.get('FAKE_TRACKED', '[]'))))\n"
            "else: raise SystemExit(9)\n",
            encoding="utf-8",
        )
        git.chmod(0o755)
        self.environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("CARGO_", "GIT_"))
        }
        self.environment.update(
            PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
            HOME=str(self.sandbox / "home"),
            CARGO_HOME=str(self.sandbox / "cargo home"),
            PYTHONDONTWRITEBYTECODE="1",
            FAKE_ROOT=str(self.root),
        )

    def write(self, relative: str, data: bytes = b"sentinel\n") -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def run_clean(self, tracked: tuple[str, ...] = (), **updates: str):
        environment = dict(self.environment, FAKE_TRACKED=json.dumps(tracked), **updates)
        return subprocess.run(
            ["make", "-s", "clean"], cwd=self.root, env=environment,
            capture_output=True, text=True, check=False,
        )

    def test_entire_target_and_python_are_removed_with_outside_bytes_preserved(self):
        removed = [self.write(path, data) for path, data in (
            ("target/debug/deps/output", b"compiled"),
            ("target/debug/incremental/work", b"incremental"),
            ("target/debug/.cargo-lock", b"lock"),
            ("target/unknown.bin", b"disposable"),
        )]
        target_bytes = sum(path.stat().st_size for path in removed)
        caches = [self.write(path, b"bytecode") for path in (
            "scripts/testing/__pycache__/module.cpython-314.pyc",
            "tests/testing/module.pyc",
        )]
        preserved = {self.write(path): b"sentinel\n" for path in (
            "Cargo.lock", ".chatgpt/run/evidence", "docs/testing/evidence",
            "scripts/module.py", "tests/fixtures/fixture.pyc",
            "scripts/__pycache__/unknown.txt", "tests/tracked.pyc",
            ".serena/state", ".codegraph/index", ".tokensave/index",
            "scripts/.venv/cache.pyc", "tests/.nscb-recovery/cache.pyc",
        )}
        result = self.run_clean(("Cargo.lock", "tests/tracked.pyc"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "target").exists())
        self.assertIn(f"cargo: removed files=4 bytes={target_bytes}", result.stdout)
        self.assertIn("python: removed files=2 bytes=16", result.stdout)
        self.assertTrue(all(not path.exists() for path in caches))
        self.assertFalse((self.root / "scripts/testing/__pycache__").exists())
        for path, content in preserved.items():
            self.assertEqual(path.read_bytes(), content)
        self.guard.assert_no_git_metadata(self.sandbox)

    def test_empty_and_repeat_succeed(self):
        (self.root / "target").mkdir()
        (self.root / "tests/__pycache__").mkdir(parents=True)
        for _ in range(2):
            result = self.run_clean()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "target").exists())
        self.assertFalse((self.root / "tests/__pycache__").exists())

    def test_python_environment_and_operation_bytes_are_preserved(self):
        preserved = [self.write(path, b"durable evidence") for path in (
            "scripts/virtualenv/lib/cache.pyc",
            "tests/operation/evidence.pyc",
        )]
        eligible = self.write("tests/module.pyc", b"generated")
        result = self.run_clean()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(eligible.exists())
        for path in preserved:
            self.assertEqual(path.read_bytes(), b"durable evidence")

    def test_generated_documentation_and_package_sources_are_disposable(self):
        paths = (
            "target/doc/src/probe/lib.rs.html",
            "target/doc/probe/index.html",
            "target/package/probe-0.1.0/src/lib.rs",
            "target/package/probe-0.1.0/Cargo.toml",
            "target/package/probe-0.1.0/Cargo.lock",
            "target/package/probe-0.1.0/docs/README.md",
            "target/package/probe-0.1.0/fixtures/example.txt",
        )
        for path in paths:
            self.write(path, b"generated")
        lock = self.write("Cargo.lock", b"tracked project lock")
        result = self.run_clean(("Cargo.lock",))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cargo: removed files=7 bytes=63", result.stdout)
        self.assertFalse((self.root / "target").exists())
        self.assertEqual(lock.read_bytes(), b"tracked project lock")

    def test_tracked_or_protected_target_refuses_whole_category(self):
        for relative, tracked in (
            ("target/tracked.bin", ("target/tracked.bin",)),
            ("target/tracked.bin", ("Target/Tracked.BIN",)),
            ("target/.CHATGPT/evidence", ()),
            ("target/.nscb-recovery", ()),
            ("target/.venv/cache.pyc", ()),
            ("target/application-state/evidence", ()),
            ("target/providers/cache", ()),
            ("target/.cargo/config.toml", ()),
        ):
            with self.subTest(relative=relative):
                if (self.root / "target").exists():
                    shutil.rmtree(self.root / "target")
                protected = self.write(relative)
                ordinary = self.write("target/debug/output", b"keep too")
                bytecode = self.write("tests/module.pyc")
                result = self.run_clean(tracked)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("cargo: skipped", result.stdout)
                self.assertEqual(protected.read_bytes(), b"sentinel\n")
                self.assertEqual(ordinary.read_bytes(), b"keep too")
                self.assertFalse(bytecode.exists())

    @unittest.skipUnless(os.name == "posix", "symlink creation requires POSIX")
    def test_symlinks_never_delete_external_content(self):
        external = self.sandbox / "external"
        external.mkdir()
        sentinel = external / "sentinel.pyc"
        sentinel.write_bytes(b"external")
        (self.root / "target").symlink_to(external, target_is_directory=True)
        result = self.run_clean()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(sentinel.read_bytes(), b"external")
        (self.root / "target").unlink()
        (self.root / "target").mkdir()
        (self.root / "target/link").symlink_to(external, target_is_directory=True)
        (self.root / "scripts/link").symlink_to(external, target_is_directory=True)
        result = self.run_clean()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "target").exists())
        self.assertEqual(sentinel.read_bytes(), b"external")

    def test_custom_environment_and_configuration_are_outside_scope(self):
        target = self.write("target/debug/output")
        external = self.sandbox / "external target"
        external.mkdir()
        sentinel = external / "output"
        sentinel.write_bytes(b"external")
        for variable in ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_BUILD_DIR"):
            with self.subTest(variable=variable):
                result = self.run_clean(**{variable: str(external)})
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("custom-cargo-location-outside-scope", result.stdout)
                self.assertTrue(target.exists())
                self.assertEqual(sentinel.read_bytes(), b"external")
        for location in (self.root / ".cargo/config.toml", self.sandbox / ".cargo/config", Path(self.environment["CARGO_HOME"]) / "config.toml"):
            location.parent.mkdir(parents=True, exist_ok=True)
            location.write_text('[build]\nbuild-dir = "custom build"\n', encoding="utf-8")
            result = self.run_clean()
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertTrue(target.exists())
            location.unlink()

    def test_wrong_root_and_cli_override_reject_without_deletion(self):
        target = self.write("target/debug/output")
        result = self.run_clean(FAKE_ROOT=str(self.sandbox))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertTrue(target.exists())
        result = subprocess.run(
            [sys.executable, "-B", str(self.root / "scripts/clean.py"), "--target", str(self.sandbox)],
            cwd=self.root, env=self.environment, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertTrue(target.exists())

    def test_category_errors_are_truthful_independent_and_retryable(self):
        spec = importlib.util.spec_from_file_location("simple_cleanup_test", self.root / "scripts/clean.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        target = self.write("target/debug/output")
        bytecode = self.write("tests/module.pyc")
        output = io.StringIO()
        with mock.patch.dict(os.environ, self.environment, clear=True), mock.patch.object(module.Path, "cwd", return_value=self.root), mock.patch.object(module.shutil, "rmtree", side_effect=PermissionError("denied")), redirect_stdout(output):
            code = module.main([])
        self.assertEqual(code, 1)
        self.assertIn("cargo: failed", output.getvalue())
        self.assertIn("python: removed", output.getvalue())
        self.assertTrue(target.exists())
        self.assertFalse(bytecode.exists())
        self.assertEqual(self.run_clean().returncode, 0)

    def test_python_io_failure_keeps_successful_cargo_removal_and_retries(self):
        spec = importlib.util.spec_from_file_location("simple_cleanup_io", self.root / "scripts/clean.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.write("target/output")
        bytecode = self.write("tests/module.pyc")
        output = io.StringIO()
        with mock.patch.dict(os.environ, self.environment, clear=True), mock.patch.object(module.Path, "cwd", return_value=self.root), mock.patch.object(module.Path, "unlink", side_effect=OSError("injected IO")), redirect_stdout(output):
            code = module.main([])
        self.assertEqual(code, 1)
        self.assertIn("cargo: removed", output.getvalue())
        self.assertIn("python: failed", output.getvalue())
        self.assertFalse((self.root / "target").exists())
        self.assertTrue(bytecode.exists())
        self.assertEqual(self.run_clean().returncode, 0)

    def test_walk_is_bounded_and_malformed_config_does_not_block_python(self):
        deep = self.root / "tests" / Path(*(["d"] * 128))
        deep.mkdir(parents=True)
        deep_bytecode = deep / "module.pyc"
        deep_bytecode.write_bytes(b"beyond traversal limit")
        result = self.run_clean()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("python-depth-limit", result.stdout)
        self.assertTrue(deep_bytecode.exists())
        shutil.rmtree(self.root / "tests")
        self.write(".cargo/config.toml", b"[invalid")
        self.write("target/output")
        bytecode = self.write("tests/module.pyc")
        result = self.run_clean()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("cargo: failed", result.stdout)
        self.assertFalse(bytecode.exists())


if __name__ == "__main__":
    unittest.main()
