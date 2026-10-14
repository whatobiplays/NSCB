"""Deterministic tests for the opt-in Git AI isolation wrapper."""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from subprocess import TimeoutExpired
from typing import Callable
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIRECTORY = REPOSITORY_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIRECTORY))

WRAPPER_MODULE_PATH = SCRIPTS_DIRECTORY / "git_ai_isolation.py"
if not WRAPPER_MODULE_PATH.is_file():
    raise AssertionError(
        "Missing implementation: scripts/git_ai_isolation.py must provide the "
        "Git AI isolation API exercised by this test suite"
    )

import git_ai_isolation as isolation


class FakeClock:
    """Advance a monotonic clock when the wrapper sleeps."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, duration: float) -> None:
        self.now += duration


class FakeGitAI:
    """Model status, shutdown, and start without launching Git AI."""

    def __init__(
        self,
        *,
        running: bool,
        events: list[str] | None = None,
    ) -> None:
        self.running = running
        self.events = events if events is not None else []
        self.commands: list[tuple[str, ...]] = []
        self.timeouts: list[float] = []
        self.status_output: bytes | None = None
        self.status_returncode = 0
        self.status_timed_out = False
        self.shutdown_returncode = 0
        self.stop_on_shutdown = True
        self.start_returncode = 0
        self.start_on_success = True

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str,
        timeout: float,
        capture_stdout: bool,
    ) -> isolation.CommandResult:
        self.assert_safe_call(command, cwd, capture_stdout)
        self.commands.append(tuple(command[1:]))
        self.timeouts.append(timeout)
        action = " ".join(command[1:])
        self.events.append(action)

        if command[1:] == ["bg", "status"]:
            if self.status_timed_out:
                return isolation.CommandResult(returncode=None, timed_out=True)
            if self.status_output is not None:
                return isolation.CommandResult(
                    returncode=self.status_returncode, stdout=self.status_output
                )
            output = json.dumps(
                {
                    "ok": True,
                    "git_repo": False,
                    "daemon_running": self.running,
                }
            ).encode("utf-8")
            return isolation.CommandResult(
                returncode=self.status_returncode, stdout=output
            )

        if command[1:] == ["bg", "shutdown"]:
            if self.shutdown_returncode == 0 and self.stop_on_shutdown:
                self.running = False
            return isolation.CommandResult(returncode=self.shutdown_returncode)

        if command[1:] == ["bg", "start"]:
            if self.start_returncode == 0 and self.start_on_success:
                self.running = True
            return isolation.CommandResult(returncode=self.start_returncode)

        raise AssertionError(f"Unexpected Git AI command: {command[1:]!r}")

    def assert_safe_call(
        self, command: list[str], cwd: str, capture_stdout: bool
    ) -> None:
        if not command or command[0] != "/fake/git-ai":
            raise AssertionError(f"Unexpected executable: {command!r}")
        if cwd != isolation.NON_REPOSITORY_CWD:
            raise AssertionError(f"Git AI command used repository cwd: {cwd!r}")
        if capture_stdout != (command[1:] == ["bg", "status"]):
            raise AssertionError("Only status output may be captured")


class GitAIIsolationTests(unittest.TestCase):
    """Exercise wrapper decisions through fake command and suite boundaries."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="nscb-isolation-tests-"
        )
        self.addCleanup(self.temporary_directory.cleanup)
        self.lock_path = Path(self.temporary_directory.name) / "wrapper.lock"

    def invoke(
        self,
        git_ai: FakeGitAI,
        *,
        executable: str | None = "/fake/git-ai",
        suite_exit: int = 0,
        suite_behavior: Callable[..., int] | None = None,
        clock: FakeClock | None = None,
        diagnostics: list[str] | None = None,
        shutdown_timeout: float = 0.3,
        lock_timeout: float = 0.5,
        suite_entered: threading.Event | None = None,
        command_runner: Callable[..., isolation.CommandResult] | None = None,
    ) -> tuple[int, list[tuple[list[str], dict[str, str], object, object]]]:
        calls: list[tuple[list[str], dict[str, str], object, object]] = []
        messages = diagnostics if diagnostics is not None else []

        def run_suite(
            command: list[str],
            environment: dict[str, str],
            verify_isolation: Callable[[], None] | None,
            signal_state: isolation.SignalState,
        ) -> int:
            calls.append((command, environment, verify_isolation, signal_state))
            git_ai.events.append("suite")
            if suite_entered is not None:
                suite_entered.set()
            if suite_behavior is not None:
                return suite_behavior(command, environment, verify_isolation, signal_state)
            if verify_isolation is not None:
                verify_isolation()
            return suite_exit

        options: dict[str, object] = {
            "lock_path": self.lock_path,
            "executable_lookup": lambda _name: executable,
            "command_runner": command_runner or git_ai,
            "suite_runner": run_suite,
            "lock_timeout": lock_timeout,
            "shutdown_timeout": shutdown_timeout,
            "status_poll_interval": 0.1,
            "diagnostic": messages.append,
        }
        if clock is not None:
            options["clock"] = clock.monotonic
            options["sleep"] = clock.sleep
        return isolation.run_isolated_suite(**options), calls

    @staticmethod
    def synthetic_status_command(byte_count: int) -> list[str]:
        script = (
            "import sys; "
            "size = int(sys.argv[1]); "
            "prefix = b'{\"ok\":true,\"git_repo\":false,"
            "\"daemon_running\":true,\"padding\":\"'; "
            "suffix = b'\"}'; "
            "padding_size = size - len(prefix) - len(suffix); "
            "assert padding_size >= 0; "
            "sys.stdout.buffer.write(prefix + b'x' * padding_size + suffix)"
        )
        return [sys.executable, "-c", script, str(byte_count)]

    def run_synthetic_status(
        self,
        byte_count: int,
        read_observations: list[tuple[int, int]] | None = None,
    ) -> isolation.CommandResult:
        real_read = os.read

        def observed_read(file_descriptor: int, requested: int) -> bytes:
            chunk = real_read(file_descriptor, requested)
            if read_observations is not None:
                read_observations.append((requested, len(chunk)))
            return chunk

        with patch.object(isolation.os, "read", side_effect=observed_read):
            return isolation._run_git_ai_command(
                self.synthetic_status_command(byte_count),
                cwd=isolation.NON_REPOSITORY_CWD,
                timeout=isolation.GIT_AI_COMMAND_TIMEOUT,
                capture_stdout=True,
            )

    def test_module_import_succeeds_when_fcntl_is_unavailable(self) -> None:
        module_name = "_git_ai_isolation_without_fcntl_test"
        specification = importlib.util.spec_from_file_location(
            module_name, WRAPPER_MODULE_PATH
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)

        with (
            patch.dict(sys.modules, {"fcntl": None}),
            patch.object(os, "killpg", None, create=True),
        ):
            sys.modules[module_name] = module
            try:
                specification.loader.exec_module(module)
            finally:
                sys.modules.pop(module_name, None)

        self.assertIsNone(module.fcntl)
        self.assertEqual(
            module.ISOLATION_ENVIRONMENT_VARIABLE,
            isolation.ISOLATION_ENVIRONMENT_VARIABLE,
        )

    def test_unsupported_platform_fails_before_lock_or_lifecycle_operations(
        self,
    ) -> None:
        unsupported_capabilities = (
            patch.object(isolation.os, "name", "nt"),
            patch.object(isolation, "fcntl", None),
            patch.object(isolation.os, "killpg", None, create=True),
        )
        for index, unsupported in enumerate(unsupported_capabilities):
            with self.subTest(index=index):
                lock_path = Path(self.temporary_directory.name) / f"unsupported-{index}.lock"
                calls: list[str] = []
                diagnostics: list[str] = []

                with unsupported:
                    result = isolation.run_isolated_suite(
                        lock_path=lock_path,
                        executable_lookup=lambda _name: calls.append("lookup"),
                        command_runner=lambda *_args, **_kwargs: calls.append("command"),
                        suite_runner=lambda *_args, **_kwargs: calls.append("suite"),
                        diagnostic=diagnostics.append,
                    )

                self.assertEqual(result, 2)
                self.assertFalse(lock_path.exists())
                self.assertEqual(calls, [])
                self.assertEqual(len(diagnostics), 1)
                self.assertIn("requires POSIX", diagnostics[0])

    def test_missing_git_ai_runs_suite_without_isolation_or_lifecycle_calls(self) -> None:
        git_ai = FakeGitAI(running=False)
        result, calls = self.invoke(git_ai, executable=None)

        self.assertEqual(result, 0)
        self.assertEqual(git_ai.commands, [])
        self.assertEqual(len(calls), 1)
        command, environment, verify, _signals = calls[0]
        self.assertEqual(
            command,
            [
                "python3",
                "-B",
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_content_policy.py",
            ],
        )
        self.assertIsNone(verify)
        self.assertNotIn(isolation.ISOLATION_ENVIRONMENT_VARIABLE, environment)
        self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")

    def test_initially_stopped_daemon_is_verified_and_left_stopped(self) -> None:
        git_ai = FakeGitAI(running=False)
        result, calls = self.invoke(git_ai)

        self.assertEqual(result, 0)
        self.assertEqual(git_ai.commands.count(("bg", "shutdown")), 0)
        self.assertEqual(git_ai.commands.count(("bg", "start")), 0)
        self.assertFalse(git_ai.running)
        self.assertEqual(len(calls), 1)
        _command, environment, verify, _signals = calls[0]
        self.assertIsNotNone(verify)
        self.assertEqual(
            environment[isolation.ISOLATION_ENVIRONMENT_VARIABLE],
            isolation.ISOLATION_ENVIRONMENT_VALUE,
        )

    def test_running_daemon_is_stopped_before_suite_and_restored_after(self) -> None:
        events: list[str] = []
        git_ai = FakeGitAI(running=True, events=events)
        result, calls = self.invoke(git_ai)

        self.assertEqual(result, 0)
        self.assertTrue(git_ai.running)
        self.assertEqual(git_ai.commands.count(("bg", "shutdown")), 1)
        self.assertEqual(git_ai.commands.count(("bg", "start")), 1)
        self.assertLess(events.index("bg shutdown"), events.index("suite"))
        self.assertLess(events.index("suite"), events.index("bg start"))
        self.assertTrue(all(timeout <= isolation.GIT_AI_COMMAND_TIMEOUT for timeout in git_ai.timeouts))
        self.assertEqual(len(calls), 1)

    def test_shutdown_failure_aborts_without_running_suite(self) -> None:
        git_ai = FakeGitAI(running=True)
        git_ai.shutdown_returncode = 1
        diagnostics: list[str] = []

        result, calls = self.invoke(git_ai, diagnostics=diagnostics)

        self.assertNotEqual(result, 0)
        self.assertEqual(calls, [])
        self.assertTrue(git_ai.running)
        self.assertEqual(git_ai.commands.count(("bg", "start")), 0)
        self.assertTrue(any("shutdown" in message.lower() for message in diagnostics))

    def test_unresolved_shutdown_child_prevents_daemon_restoration(self) -> None:
        class SurvivingLifecycleChild:
            def __init__(self) -> None:
                self.pid = 8765
                self.returncode: int | None = None
                self.stdout = None
                self.wait_timeouts: list[float] = []
                self.terminate_calls = 0
                self.kill_calls = 0

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float) -> int:
                self.wait_timeouts.append(timeout)
                raise TimeoutExpired("/fake/git-ai bg shutdown", timeout)

            def terminate(self) -> None:
                self.terminate_calls += 1

            def kill(self) -> None:
                self.kill_calls += 1
                raise AssertionError("the Git AI lifecycle child must not be killed")

        git_ai = FakeGitAI(running=True)
        child = SurvivingLifecycleChild()
        shutdown_invocations: list[tuple[str, ...]] = []
        diagnostics: list[str] = []

        def command_runner(
            command: list[str],
            *,
            cwd: str,
            timeout: float,
            capture_stdout: bool,
        ) -> isolation.CommandResult:
            if command[1:] == ["bg", "shutdown"]:
                shutdown_invocations.append(tuple(command[1:]))
                git_ai.running = False
                return isolation._run_git_ai_command(
                    command,
                    cwd=cwd,
                    timeout=timeout,
                    capture_stdout=capture_stdout,
                )
            return git_ai(
                command,
                cwd=cwd,
                timeout=timeout,
                capture_stdout=capture_stdout,
            )

        with patch.object(isolation.subprocess, "Popen", return_value=child) as popen:
            result = isolation.run_isolated_suite(
                lock_path=self.lock_path,
                executable_lookup=lambda _name: "/fake/git-ai",
                command_runner=command_runner,
                diagnostic=diagnostics.append,
            )

        self.assertNotEqual(result, 0)
        self.assertEqual(shutdown_invocations, [("bg", "shutdown")])
        self.assertEqual(git_ai.commands, [("bg", "status")])
        self.assertFalse(git_ai.running)
        self.assertIsNone(child.poll())
        self.assertEqual(child.terminate_calls, 1)
        self.assertEqual(child.kill_calls, 0)
        self.assertEqual(len(child.wait_timeouts), 2)
        popen.assert_called_once()
        self.assertEqual(
            popen.call_args.args[0], ["/fake/git-ai", "bg", "shutdown"]
        )
        self.assertTrue(
            any(message.startswith("GIT AI CLI CHILD UNRESOLVED") for message in diagnostics),
            diagnostics,
        )

    def test_successful_shutdown_that_does_not_stop_daemon_times_out(self) -> None:
        git_ai = FakeGitAI(running=True)
        git_ai.stop_on_shutdown = False
        clock = FakeClock()
        diagnostics: list[str] = []

        result, calls = self.invoke(
            git_ai,
            clock=clock,
            shutdown_timeout=0.25,
            diagnostics=diagnostics,
        )

        self.assertNotEqual(result, 0)
        self.assertEqual(calls, [])
        self.assertTrue(git_ai.running)
        self.assertGreater(git_ai.commands.count(("bg", "status")), 1)
        self.assertTrue(any("timed out" in message.lower() for message in diagnostics))

    def test_suite_exit_code_is_preserved_after_restoration(self) -> None:
        for suite_exit in (0, 7):
            with self.subTest(suite_exit=suite_exit):
                git_ai = FakeGitAI(running=True)
                result, _calls = self.invoke(git_ai, suite_exit=suite_exit)
                self.assertEqual(result, suite_exit)
                self.assertTrue(git_ai.running)
                self.assertEqual(git_ai.commands.count(("bg", "start")), 1)

    def test_start_failure_is_reported_when_daemon_later_reports_running(
        self,
    ) -> None:
        git_ai = FakeGitAI(running=True)
        git_ai.start_returncode = 1
        diagnostics: list[str] = []

        def fail_start_after_daemon_becomes_running(
            command: list[str],
            *,
            cwd: str,
            timeout: float,
            capture_stdout: bool,
        ) -> isolation.CommandResult:
            result = git_ai(
                command,
                cwd=cwd,
                timeout=timeout,
                capture_stdout=capture_stdout,
            )
            if command[1:] == ["bg", "start"]:
                git_ai.running = True
            return result

        result, _calls = self.invoke(
            git_ai,
            diagnostics=diagnostics,
            command_runner=fail_start_after_daemon_becomes_running,
        )

        self.assertNotEqual(result, 0)
        self.assertTrue(git_ai.running)
        self.assertEqual(git_ai.commands.count(("bg", "start")), 1)
        self.assertTrue(
            any(
                "RESTORATION FAILED" in message
                and "start command failed" in message
                and "observed daemon status: running" in message
                for message in diagnostics
            )
        )

    def test_restore_failure_is_reported_and_returns_nonzero(self) -> None:
        git_ai = FakeGitAI(running=True)
        git_ai.start_returncode = 1
        git_ai.start_on_success = False
        clock = FakeClock()
        diagnostics: list[str] = []

        result, _calls = self.invoke(
            git_ai,
            clock=clock,
            shutdown_timeout=0.25,
            diagnostics=diagnostics,
        )

        self.assertNotEqual(result, 0)
        self.assertFalse(git_ai.running)
        self.assertEqual(git_ai.commands.count(("bg", "start")), 1)
        self.assertTrue(any("RESTORATION FAILED" in message for message in diagnostics))

    def test_sigint_restores_initially_running_daemon(self) -> None:
        self.assert_signal_restores_daemon(signal.SIGINT)

    def test_sigterm_restores_initially_running_daemon(self) -> None:
        self.assert_signal_restores_daemon(signal.SIGTERM)

    def assert_signal_restores_daemon(self, signum: int) -> None:
        git_ai = FakeGitAI(running=True)

        def interrupt(_command: object, _env: object, _verify: object, signals: isolation.SignalState) -> int:
            signals.request(signum)
            return 0

        result, _calls = self.invoke(git_ai, suite_behavior=interrupt)

        self.assertEqual(result, 128 + signum)
        self.assertTrue(git_ai.running)
        self.assertEqual(git_ai.commands.count(("bg", "start")), 1)

    def test_signal_during_restoration_is_returned_after_daemon_is_restored(self) -> None:
        git_ai = FakeGitAI(running=True)
        suite_signals: list[isolation.SignalState] = []

        def suite_succeeds(
            _command: object,
            _environment: object,
            _verify: object,
            signals: isolation.SignalState,
        ) -> int:
            suite_signals.append(signals)
            return 0

        def signal_during_start(
            command: list[str],
            *,
            cwd: str,
            timeout: float,
            capture_stdout: bool,
        ) -> isolation.CommandResult:
            result = git_ai(
                command,
                cwd=cwd,
                timeout=timeout,
                capture_stdout=capture_stdout,
            )
            if command[1:] == ["bg", "start"]:
                suite_signals[0].request(signal.SIGTERM)
            return result

        result, _calls = self.invoke(
            git_ai,
            suite_behavior=suite_succeeds,
            command_runner=signal_during_start,
        )

        self.assertEqual(result, 128 + signal.SIGTERM)
        self.assertEqual(suite_signals[0].requested_signal, signal.SIGTERM)
        self.assertTrue(git_ai.running)


    def test_concurrent_invocation_waits_until_first_run_restores_daemon(self) -> None:
        events: list[str] = []
        git_ai = FakeGitAI(running=True, events=events)
        first_entered = threading.Event()
        release_first = threading.Event()
        second_entered = threading.Event()
        invocation_count = 0
        invocation_lock = threading.Lock()
        outcomes: list[int] = []
        failures: list[BaseException] = []

        def suite_behavior(
            _command: object,
            _environment: object,
            verify: Callable[[], None] | None,
            _signals: isolation.SignalState,
        ) -> int:
            nonlocal invocation_count
            if verify is not None:
                verify()
            with invocation_lock:
                invocation_count += 1
                current = invocation_count
            if current == 1:
                first_entered.set()
                if not release_first.wait(timeout=2):
                    raise AssertionError("first invocation was not released")
            else:
                second_entered.set()
            return 0

        def worker() -> None:
            try:
                result, _calls = self.invoke(
                    git_ai,
                    suite_behavior=suite_behavior,
                    lock_timeout=1.5,
                )
                outcomes.append(result)
            except BaseException as error:
                failures.append(error)

        first = threading.Thread(target=worker)
        second = threading.Thread(target=worker)
        first.start()
        self.assertTrue(first_entered.wait(timeout=1))
        second.start()
        time.sleep(0.1)
        self.assertFalse(second_entered.is_set())
        release_first.set()
        first.join(timeout=2)
        second.join(timeout=2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(outcomes, [0, 0])
        self.assertEqual(invocation_count, 2)
        self.assertTrue(git_ai.running)

    def test_unexpected_daemon_restart_aborts_suite_and_preserves_running_state(self) -> None:
        git_ai = FakeGitAI(running=True)

        def restart_after_suite_exit(
            _command: object,
            _environment: object,
            _verify: Callable[[], None] | None,
            _signals: isolation.SignalState,
        ) -> int:
            git_ai.running = True
            return 0

        diagnostics: list[str] = []
        result, _calls = self.invoke(
            git_ai, suite_behavior=restart_after_suite_exit, diagnostics=diagnostics
        )

        self.assertNotEqual(result, 0)
        self.assertTrue(git_ai.running)
        self.assertEqual(git_ai.commands.count(("bg", "start")), 0)
        self.assertTrue(any("restarted" in message.lower() for message in diagnostics))

    def test_suite_group_is_killed_if_leader_exits_after_term(self) -> None:
        class ChildProcess:
            def __init__(self) -> None:
                self.pid = 5678
                self.returncode: int | None = None
                self.wait_timeouts: list[float] = []

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float) -> int:
                self.wait_timeouts.append(timeout)
                if self.returncode is None:
                    raise isolation.subprocess.TimeoutExpired("python3", timeout)
                return self.returncode

        child = ChildProcess()
        group_alive = [True]
        sent_signals: list[int] = []
        signals = isolation.SignalState()
        clock = FakeClock()

        def start_child(*_args: object, **_kwargs: object) -> ChildProcess:
            signals.request(signal.SIGTERM)
            return child

        def signal_group(process_group: int, signum: int) -> None:
            self.assertEqual(process_group, child.pid)
            if signum == 0:
                if not group_alive[0]:
                    raise ProcessLookupError
                return
            sent_signals.append(signum)
            if signum == signal.SIGTERM:
                child.returncode = -signal.SIGTERM
            elif signum == signal.SIGKILL:
                group_alive[0] = False

        with (
            patch.object(isolation.os, "killpg", side_effect=signal_group),
            patch.object(isolation.time, "monotonic", clock.monotonic),
            patch.object(isolation.time, "sleep", clock.sleep),
        ):
            with self.assertRaises(isolation._SignalRequested):
                isolation._execute_suite(
                    ["python3", "-B"],
                    {},
                    None,
                    signals,
                    poll_interval=0.01,
                    termination_timeout=0.05,
                    process_factory=start_child,
                )

        self.assertEqual(sent_signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertFalse(group_alive[0])
        self.assertLessEqual(clock.now, 0.1)

    def test_malformed_status_aborts_before_shutdown_or_suite(self) -> None:
        git_ai = FakeGitAI(running=True)
        git_ai.status_output = b'{"ok":true,"git_repo":false,"daemon_running":"yes"}'
        diagnostics: list[str] = []

        result, calls = self.invoke(git_ai, diagnostics=diagnostics)

        self.assertNotEqual(result, 0)
        self.assertEqual(calls, [])
        self.assertEqual(git_ai.commands, [("bg", "status")])
        self.assertTrue(any("status" in message.lower() for message in diagnostics))

    def test_incomplete_status_json_aborts_before_shutdown_or_suite(self) -> None:
        git_ai = FakeGitAI(running=True)
        git_ai.status_output = (
            b'{"ok":true,"git_repo":false,"daemon_running":true'
        )

        result, calls = self.invoke(git_ai)

        self.assertNotEqual(result, 0)
        self.assertEqual(calls, [])
        self.assertEqual(git_ai.commands, [("bg", "status")])

    def test_approximately_414_kib_status_parses_through_bounded_reader(self) -> None:
        byte_count = 413_816
        result = self.run_synthetic_status(byte_count)

        self.assertFalse(result.timed_out)
        self.assertFalse(result.output_limit_exceeded)
        self.assertEqual(len(result.stdout), byte_count)
        self.assertTrue(isolation._parse_status(result))

    def test_status_at_two_mib_limit_is_accepted(self) -> None:
        byte_limit = 2 * 1024 * 1024
        result = self.run_synthetic_status(byte_limit)

        self.assertEqual(isolation.MAX_STATUS_OUTPUT_BYTES, byte_limit)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.output_limit_exceeded)
        self.assertEqual(len(result.stdout), byte_limit)
        self.assertTrue(isolation._parse_status(result))

    def test_status_one_byte_over_two_mib_is_rejected_with_bounded_read(self) -> None:
        byte_limit = 2 * 1024 * 1024
        reads: list[tuple[int, int]] = []
        result = self.run_synthetic_status(byte_limit + 1, reads)

        self.assertEqual(isolation.MAX_STATUS_OUTPUT_BYTES, byte_limit)
        self.assertTrue(result.output_limit_exceeded)
        self.assertTrue(result.child_exit_confirmed)
        self.assertEqual(sum(read for _, read in reads), byte_limit + 1)
        self.assertTrue(
            all(requested <= isolation.MAX_STATUS_OUTPUT_BYTES + 1 for requested, _ in reads)
        )
        with self.assertRaisesRegex(isolation.IsolationError, "safety limit"):
            isolation._parse_status(result)

    def test_oversized_status_aborts_before_shutdown_or_suite(self) -> None:
        git_ai = FakeGitAI(running=True)
        command_calls: list[tuple[str, ...]] = []

        def run_status_with_real_reader(
            command: list[str],
            *,
            cwd: str,
            timeout: float,
            capture_stdout: bool,
        ) -> isolation.CommandResult:
            command_calls.append(tuple(command[1:]))
            if command[1:] == ["bg", "status"]:
                return self.run_synthetic_status(2 * 1024 * 1024 + 1)
            return git_ai(
                command,
                cwd=cwd,
                timeout=timeout,
                capture_stdout=capture_stdout,
            )

        result, suite_calls = self.invoke(
            git_ai, command_runner=run_status_with_real_reader
        )

        self.assertNotEqual(result, 0)
        self.assertEqual(command_calls, [("bg", "status")])
        self.assertEqual(git_ai.commands, [])
        self.assertEqual(suite_calls, [])

    def test_status_timeout_is_bounded_and_aborts_before_suite(self) -> None:
        git_ai = FakeGitAI(running=True)
        git_ai.status_timed_out = True
        diagnostics: list[str] = []

        result, calls = self.invoke(git_ai, diagnostics=diagnostics)

        self.assertNotEqual(result, 0)
        self.assertEqual(calls, [])
        self.assertEqual(git_ai.commands, [("bg", "status")])
        self.assertTrue(all(timeout == isolation.GIT_AI_COMMAND_TIMEOUT for timeout in git_ai.timeouts))

    def test_running_daemon_is_not_restored_while_suite_group_survives_termination(self) -> None:
        class SurvivingSuiteProcess:
            def __init__(self) -> None:
                self.pid = 4321
                self.returncode: int | None = None
                self.wait_calls = 0

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float) -> int:
                self.wait_calls += 1
                if self.wait_calls == 1:
                    fail_suite_status[0] = True
                clock.sleep(max(0.0, timeout))
                raise TimeoutExpired("python3", timeout)

        git_ai = FakeGitAI(running=True)
        diagnostics: list[str] = []
        clock = FakeClock()
        child = SurvivingSuiteProcess()
        group_alive = True
        sent_signals: list[int] = []
        fail_suite_status = [False]
        run_status = isolation._run_status

        def fail_suite_verification_once(
            executable: str,
            command_runner: Callable[..., isolation.CommandResult],
        ) -> bool:
            if fail_suite_status[0]:
                fail_suite_status[0] = False
                raise isolation.IsolationError("injected suite verification failure")
            return run_status(executable, command_runner)

        def signal_group(process_group: int, signum: int) -> None:
            nonlocal group_alive
            self.assertEqual(process_group, child.pid)
            if signum == 0:
                if not group_alive:
                    raise ProcessLookupError
                return
            sent_signals.append(signum)

        with (
            patch.object(isolation.subprocess, "Popen", return_value=child),
            patch.object(isolation.os, "killpg", side_effect=signal_group),
            patch.object(isolation, "_run_status", side_effect=fail_suite_verification_once),
            patch.object(isolation.time, "monotonic", clock.monotonic),
            patch.object(isolation, "PROCESS_TERMINATION_TIMEOUT", 0.05),
        ):
            result = isolation.run_isolated_suite(
                lock_path=self.lock_path,
                executable_lookup=lambda _name: "/fake/git-ai",
                command_runner=git_ai,
                status_poll_interval=0.01,
                clock=clock.monotonic,
                sleep=clock.sleep,
                diagnostic=diagnostics.append,
            )

        self.assertNotEqual(result, 0)
        self.assertTrue(group_alive)
        self.assertEqual(sent_signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(git_ai.commands.count(("bg", "start")), 0)
        self.assertFalse(git_ai.running)
        self.assertTrue(
            any(message.startswith("SUITE TERMINATION FAILED") for message in diagnostics),
            diagnostics,
        )

    def test_suite_process_is_terminated_with_bounded_wait_on_isolation_breach(self) -> None:
        class ChildProcess:
            def __init__(self) -> None:
                self.pid = 1234
                self.returncode: int | None = None
                self.wait_timeouts: list[float] = []
                self.signals: list[int] = []

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float) -> int:
                self.wait_timeouts.append(timeout)
                if self.signals and self.signals[-1] == signal.SIGKILL:
                    self.returncode = -signal.SIGKILL
                    return self.returncode
                raise TimeoutExpired("python3", timeout)

            def terminate(self) -> None:
                self.signals.append(signal.SIGTERM)

        child = ChildProcess()
        checks = 0

        def verify() -> None:
            nonlocal checks
            checks += 1
            if checks == 2:
                raise isolation.IsolationError("daemon restarted")

        group_alive = [True]

        def signal_group(process_group: int, signum: int) -> None:
            self.assertEqual(process_group, child.pid)
            if signum == 0:
                if not group_alive[0]:
                    raise ProcessLookupError
                return
            child.signals.append(signum)
            if signum == signal.SIGKILL:
                group_alive[0] = False

        with (
            patch.object(isolation.os, "killpg", side_effect=signal_group) as killpg,
            patch.object(isolation.subprocess, "Popen", return_value=child) as popen,
        ):
            with self.assertRaises(isolation.IsolationError):
                isolation._execute_suite(
                    ["python3", "-B"],
                    {},
                    verify,
                    isolation.SignalState(),
                    poll_interval=0.01,
                    termination_timeout=0.2,
                )

        self.assertEqual(child.signals, [signal.SIGTERM, signal.SIGKILL])
        killpg.assert_any_call(child.pid, signal.SIGTERM)
        killpg.assert_any_call(child.pid, signal.SIGKILL)
        self.assertLessEqual(max(child.wait_timeouts), 0.2)
        self.assertEqual(popen.call_args.args[0], ["python3", "-B"])
        self.assertIs(popen.call_args.kwargs["start_new_session"], True)
        self.assertNotIn("shell", popen.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
