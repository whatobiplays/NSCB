"""Public make clean qualification in disposable genuine Git worktrees."""

from __future__ import annotations

import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]


class GenuineCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nscb-simple-git-")
        self.addCleanup(self.temporary.cleanup)
        self.sandbox = Path(self.temporary.name).resolve()
        self.root = self.sandbox / "first checkout"
        self.linked = self.sandbox / "linked checkout"
        self.root.mkdir()
        self.environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("CARGO_", "GIT_"))
        }
        self.environment.update(
            PYTHONDONTWRITEBYTECODE="1",
            HOME=str(self.sandbox / "home"),
            CARGO_HOME=str(self.sandbox / "cargo home"),
        )
        self.git("init", "--quiet")
        self.git("config", "user.name", "Cleanup Fixture")
        self.git("config", "user.email", "cleanup@example.invalid")
        (self.root / "scripts").mkdir()
        shutil.copy2(REPOSITORY / "scripts/clean.py", self.root / "scripts/clean.py")
        shutil.copy2(REPOSITORY / "Makefile", self.root / "Makefile")
        (self.root / "Cargo.lock").write_bytes(b"tracked manifest lock\n")
        (self.root / ".gitignore").write_text("target/\n__pycache__/\n*.pyc\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "disposable fixture")
        self.git("worktree", "add", "--quiet", "-b", "fixture-linked", str(self.linked))

    def git(self, *arguments):
        return subprocess.run(
            ["git", *arguments], cwd=self.root, env=self.environment,
            capture_output=True, text=True, check=True,
        )

    @staticmethod
    def snapshot(root):
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(root).parts
        }

    def populate(self, root):
        for relative, content in (
            ("target/debug/deps/output", b"compiled\n"),
            ("target/debug/incremental/state", b"incremental\n"),
            ("target/debug/.cargo-lock", b"generated lock\n"),
            ("target/unknown.bin", b"regenerable output\n"),
            (".chatgpt/evidence", b"provenance\n"),
            ("docs/testing/evidence", b"documentation\n"),
            ("tests/fixtures/fixture.pyc", b"durable fixture\n"),
            ("scripts/__pycache__/unknown.txt", b"unknown preserved\n"),
        ):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        source = root / "tests/generated.py"
        source.write_text("VALUE = 42\n", encoding="utf-8")
        bytecode = Path(py_compile.compile(str(source), doraise=True))
        return bytecode

    def clean(self, root, **updates):
        return subprocess.run(
            ["make", "-s", "clean"], cwd=root,
            env=dict(self.environment, **updates), capture_output=True, text=True,
        )

    def test_public_clean_removes_entire_target_and_real_bytecode_in_each_worktree(self):
        first_pyc = self.populate(self.root)
        self.populate(self.linked)
        linked_before = self.snapshot(self.linked)
        git_before = {path.relative_to(self.root / ".git").as_posix(): path.read_bytes()
                      for path in (self.root / ".git").rglob("*") if path.is_file()}
        outside = self.snapshot(self.root)
        target_entries = {name: content for name, content in outside.items() if name.startswith("target/")}
        python_bytes = first_pyc.stat().st_size
        outside = {name: content for name, content in outside.items()
                   if not name.startswith("target/") and name != first_pyc.relative_to(self.root).as_posix()}

        result = self.clean(self.root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"cargo: removed files=4 bytes={sum(map(len, target_entries.values()))}", result.stdout)
        self.assertIn(f"python: removed files=1 bytes={python_bytes}", result.stdout)
        self.assertFalse((self.root / "target").exists())
        self.assertFalse(first_pyc.exists())
        self.assertEqual(self.snapshot(self.root), outside)
        self.assertEqual(self.snapshot(self.linked), linked_before)
        self.assertEqual({path.relative_to(self.root / ".git").as_posix(): path.read_bytes()
                          for path in (self.root / ".git").rglob("*") if path.is_file()}, git_before)
        self.assertEqual(self.clean(self.root).returncode, 0)
        self.assertEqual(self.clean(self.linked).returncode, 0)
        self.assertFalse((self.linked / "target").exists())

    def test_tracked_target_and_tracked_bytecode_survive(self):
        bytecode = self.populate(self.root)
        self.git("add", "--force", "target/unknown.bin", str(bytecode.relative_to(self.root)))
        before = self.snapshot(self.root)
        result = self.clean(self.root)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("tracked-target-content", result.stdout)
        self.assertEqual(self.snapshot(self.root), before)

    def test_git_metadata_inside_target_refuses_deletion(self):
        self.populate(self.root)
        protected = self.root / "target/.git/config"
        protected.parent.mkdir()
        protected.write_bytes(b"unexpected durable Git state")
        result = self.clean(self.root)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("protected-target-content", result.stdout)
        self.assertEqual(protected.read_bytes(), b"unexpected durable Git state")
        self.assertTrue((self.root / "target/debug/deps/output").exists())

    @unittest.skipUnless(os.name == "posix", "symlink creation requires POSIX")
    def test_external_and_symlinked_target_are_not_followed(self):
        self.populate(self.root)
        external = self.sandbox / "external"
        external.mkdir()
        sentinel = external / "sentinel"
        sentinel.write_bytes(b"outside")
        result = self.clean(self.root, CARGO_TARGET_DIR=str(external))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(sentinel.read_bytes(), b"outside")
        shutil.rmtree(self.root / "target")
        (self.root / "target").symlink_to(external, target_is_directory=True)
        result = self.clean(self.root)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(sentinel.read_bytes(), b"outside")


if __name__ == "__main__":
    unittest.main()
