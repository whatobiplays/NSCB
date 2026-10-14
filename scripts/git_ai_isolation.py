"""Run the content-policy test suite with verified Git AI daemon isolation.

This opt-in command serializes callers, records the daemon's initial state,
stops it only when it was running, and restores that state after the Python
suite. It never uses a shell to launch Git AI or the test process.
"""

from __future__ import annotations

import json
import os
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Sequence

try:
    import fcntl
except ImportError:  # Module imports are also used by the portable policy tests.
    fcntl = None  # type: ignore[assignment]


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUITE_COMMAND = (
    "python3",
    "-B",
    "-m",
    "unittest",
    "discover",
    "-s",
    "tests",
    "-p",
    "test_content_policy.py",
)
NON_REPOSITORY_CWD = os.path.abspath(os.sep)
ISOLATION_ENVIRONMENT_VARIABLE = "_NSCB_GIT_AI_ISOLATION_VERIFIED"
ISOLATION_ENVIRONMENT_VALUE = "stopped"

GIT_AI_COMMAND_TIMEOUT = 5.0
SUITE_POLL_INTERVAL = 0.5
STATUS_POLL_INTERVAL = 0.2
SHUTDOWN_TIMEOUT = 10.0
RESTORE_TIMEOUT = 15.0
PROCESS_TERMINATION_TIMEOUT = 2.0
LOCK_TIMEOUT = 30.0
MAX_STATUS_OUTPUT_BYTES = 2 * 1024 * 1024
_READ_CHUNK_BYTES = 4096


class IsolationError(RuntimeError):
    """Describe a safely detected failure to establish or maintain isolation."""


def _unsupported_platform_reason() -> str | None:
    """Explain why daemon isolation cannot run without POSIX locking and signals."""
    if (
        os.name != "posix"
        or fcntl is None
        or not callable(getattr(fcntl, "flock", None))
        or not callable(getattr(os, "killpg", None))
        or not hasattr(signal, "SIGTERM")
        or not hasattr(signal, "SIGKILL")
    ):
        return (
            "the Git AI isolation target requires POSIX fcntl.flock and "
            "process-group signaling support"
        )
    return None


class _SignalRequested(Exception):
    """Carry a handled SIGINT or SIGTERM out of the suite process loop."""

    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


@dataclass(frozen=True)
class CommandResult:
    """Hold bounded command output and the result of one child process."""

    returncode: int | None
    stdout: bytes = b""
    timed_out: bool = False
    output_limit_exceeded: bool = False
    child_exit_confirmed: bool = True


class SignalState:
    """Record the first termination signal for orderly suite cleanup."""

    def __init__(self) -> None:
        self.requested_signal: int | None = None

    def request(self, signum: int) -> None:
        """Remember the first requested signal without interrupting restoration."""
        if self.requested_signal is None:
            self.requested_signal = signum

    def handle(self, signum: int, _frame: object) -> None:
        """Use as a Python signal handler while the wrapper owns the lifecycle."""
        self.request(signum)


def _default_lock_path() -> Path:
    """Return a per-user lock path in the local temporary directory."""
    user_id = os.getuid() if hasattr(os, "getuid") else os.getpid()
    return Path(tempfile.gettempdir()) / f"nscb-git-ai-isolation-{user_id}.lock"


@contextmanager
def _exclusive_lock(
    path: Path,
    *,
    timeout: float,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
) -> Iterator[None]:
    """Hold a bounded, mode-restricted advisory lock for one wrapper run."""
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise IsolationError("Could not open the local Git AI isolation lock") from error

    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise IsolationError("The local Git AI isolation lock is not a regular file")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise IsolationError("The local Git AI isolation lock has a different owner")
        os.fchmod(descriptor, 0o600)

        deadline = clock() + timeout
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                remaining = deadline - clock()
                if remaining <= 0:
                    raise IsolationError(
                        "Another Git AI isolation run holds the lock; retry after it finishes"
                    )
                sleep(min(0.05, remaining))
            except OSError as error:
                raise IsolationError("Could not acquire the Git AI isolation lock") from error
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


@contextmanager
def _handle_termination_signals(state: SignalState) -> Iterator[None]:
    """Record SIGINT/SIGTERM on the main thread and restore prior handlers."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    previous: dict[int, object] = {}
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, state.handle)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _stop_child_process(process: subprocess.Popen[bytes], timeout: float) -> bool:
    """Send SIGTERM to one owned child and wait for a bounded interval."""
    if process.poll() is not None:
        return True
    try:
        process.terminate()
    except ProcessLookupError:
        return True
    except OSError:
        return process.poll() is not None
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    return True


def _stop_suite_process(process: subprocess.Popen[bytes], timeout: float) -> bool:
    """Stop and reap the isolated suite process group within bounded waits."""
    process_group = process.pid
    if not _suite_process_group_exists(process_group):
        return process.poll() is not None
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        return False

    if _wait_for_suite_process_group(process, timeout):
        return True

    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        return False
    return _wait_for_suite_process_group(process, timeout)


def _suite_process_group_exists(process_group: int) -> bool:
    """Check whether any process remains in the wrapper-owned process group."""
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except OSError:
        # An inability to inspect the group is not proof that it has exited.
        return True
    return True


def _wait_for_suite_process_group(
    process: subprocess.Popen[bytes], timeout: float
) -> bool:
    """Wait a bounded interval for the group and its direct child to exit."""
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        if not _suite_process_group_exists(process.pid):
            if process.poll() is None:
                remaining = max(0.0, deadline - time.monotonic())
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    return False
            return process.poll() is not None

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        wait_interval = min(SUITE_POLL_INTERVAL, remaining)
        if process.poll() is None:
            try:
                process.wait(timeout=wait_interval)
            except subprocess.TimeoutExpired:
                pass
        else:
            time.sleep(wait_interval)


def _run_git_ai_command(
    command: list[str],
    *,
    cwd: str,
    timeout: float,
    capture_stdout: bool,
) -> CommandResult:
    """Run one Git AI CLI command with bounded time and optional bounded output."""
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    output = bytearray()
    child_exit_confirmed = True
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        deadline = time.monotonic() + timeout

        if capture_stdout:
            assert process.stdout is not None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    child_exit_confirmed = _stop_child_process(
                        process, PROCESS_TERMINATION_TIMEOUT
                    )
                    return CommandResult(
                        returncode=None,
                        timed_out=True,
                        child_exit_confirmed=child_exit_confirmed,
                    )
                if not selector.select(remaining):
                    child_exit_confirmed = _stop_child_process(
                        process, PROCESS_TERMINATION_TIMEOUT
                    )
                    return CommandResult(
                        returncode=None,
                        timed_out=True,
                        child_exit_confirmed=child_exit_confirmed,
                    )
                chunk = os.read(
                    process.stdout.fileno(),
                    min(_READ_CHUNK_BYTES, MAX_STATUS_OUTPUT_BYTES + 1 - len(output)),
                )
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_STATUS_OUTPUT_BYTES:
                    child_exit_confirmed = _stop_child_process(
                        process, PROCESS_TERMINATION_TIMEOUT
                    )
                    return CommandResult(
                        returncode=None,
                        output_limit_exceeded=True,
                        child_exit_confirmed=child_exit_confirmed,
                    )

        remaining = max(0.0, deadline - time.monotonic())
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            child_exit_confirmed = _stop_child_process(
                process, PROCESS_TERMINATION_TIMEOUT
            )
            return CommandResult(
                returncode=None,
                timed_out=True,
                child_exit_confirmed=child_exit_confirmed,
            )
        return CommandResult(returncode=returncode, stdout=bytes(output))
    except OSError:
        if process is not None:
            child_exit_confirmed = _stop_child_process(
                process, PROCESS_TERMINATION_TIMEOUT
            )
        return CommandResult(
            returncode=None, child_exit_confirmed=child_exit_confirmed
        )
    finally:
        if selector is not None:
            selector.close()
        if process is not None and process.stdout is not None:
            process.stdout.close()


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate status fields instead of accepting ambiguous JSON."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parse_status(result: CommandResult) -> bool:
    """Return daemon state from a complete, successful non-repository status."""
    if result.timed_out:
        raise IsolationError("Git AI status command timed out")
    if result.output_limit_exceeded:
        raise IsolationError("Git AI status output exceeded its safety limit")
    if result.returncode != 0:
        raise IsolationError("Git AI status command failed; daemon state is unknown")
    try:
        document = json.loads(
            result.stdout.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise IsolationError("Git AI returned malformed status JSON") from error
    if (
        not isinstance(document, dict)
        or document.get("ok") is not True
        or document.get("git_repo") is not False
        or type(document.get("daemon_running")) is not bool
    ):
        raise IsolationError("Git AI status did not confirm a non-repository daemon state")
    return document["daemon_running"]


def _run_status(
    executable: str,
    command_runner: Callable[..., CommandResult],
) -> bool:
    """Query status from the filesystem root without capturing daemon logs."""
    result = command_runner(
        [executable, "bg", "status"],
        cwd=NON_REPOSITORY_CWD,
        timeout=GIT_AI_COMMAND_TIMEOUT,
        capture_stdout=True,
    )
    return _parse_status(result)


def _run_lifecycle_command(
    executable: str,
    action: str,
    command_runner: Callable[..., CommandResult],
) -> CommandResult:
    """Run a bounded shutdown or start request without retaining its output."""
    return command_runner(
        [executable, "bg", action],
        cwd=NON_REPOSITORY_CWD,
        timeout=GIT_AI_COMMAND_TIMEOUT,
        capture_stdout=False,
    )


def _wait_for_state(
    executable: str,
    expected_running: bool,
    command_runner: Callable[..., CommandResult],
    *,
    timeout: float,
    poll_interval: float,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    signal_state: SignalState,
    raise_on_signal: bool = True,
    timeout_message: str,
) -> None:
    """Poll a verified status until the requested state or deadline."""
    deadline = clock() + timeout
    while True:
        if raise_on_signal and signal_state.requested_signal is not None:
            raise _SignalRequested(signal_state.requested_signal)
        running = _run_status(executable, command_runner)
        if running is expected_running:
            return
        remaining = deadline - clock()
        if remaining <= 0:
            raise IsolationError(timeout_message)
        sleep(min(poll_interval, remaining))


def _suite_environment(isolated: bool) -> dict[str, str]:
    """Build the child environment and emit the private signal only if verified."""
    environment = os.environ.copy()
    environment.pop(ISOLATION_ENVIRONMENT_VARIABLE, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if isolated:
        environment[ISOLATION_ENVIRONMENT_VARIABLE] = ISOLATION_ENVIRONMENT_VALUE
    return environment


class _SuiteProcessGroupTerminationError(IsolationError):
    """Raised when the wrapper cannot confirm the suite process group exited."""


def _require_suite_process_group_stopped(
    process: subprocess.Popen[bytes], timeout: float
) -> None:
    """Fail distinctly when bounded cleanup cannot confirm the group is gone."""
    message = (
        f"Could not stop the Python test process group led by PID {process.pid} "
        "within the termination deadline"
    )
    try:
        stopped = _stop_suite_process(process, timeout)
    except BaseException as error:
        raise _SuiteProcessGroupTerminationError(message) from error
    if not stopped:
        raise _SuiteProcessGroupTerminationError(message)


def _execute_suite(
    command: Sequence[str],
    environment: dict[str, str],
    verify_isolation: Callable[[], None] | None,
    signal_state: SignalState,
    *,
    poll_interval: float = SUITE_POLL_INTERVAL,
    termination_timeout: float = PROCESS_TERMINATION_TIMEOUT,
    process_factory: Callable[..., subprocess.Popen[bytes]] | None = None,
) -> int:
    """Run the suite, checking daemon state while it runs and terminating on breach."""
    if verify_isolation is not None:
        verify_isolation()
    start_process = process_factory or subprocess.Popen
    try:
        process = start_process(
            list(command),
            cwd=REPOSITORY_ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as error:
        raise IsolationError("Could not start the Python content-policy suite") from error

    try:
        while True:
            if signal_state.requested_signal is not None:
                raise _SignalRequested(signal_state.requested_signal)
            returncode = process.poll()
            if returncode is not None:
                _require_suite_process_group_stopped(process, termination_timeout)
                if verify_isolation is not None:
                    verify_isolation()
                if signal_state.requested_signal is not None:
                    raise _SignalRequested(signal_state.requested_signal)
                return returncode
            try:
                process.wait(timeout=poll_interval)
            except subprocess.TimeoutExpired:
                pass
            if signal_state.requested_signal is not None:
                raise _SignalRequested(signal_state.requested_signal)
            if verify_isolation is not None:
                verify_isolation()
    except BaseException:
        _require_suite_process_group_stopped(process, termination_timeout)
        raise


def _restore_running_daemon(
    executable: str,
    command_runner: Callable[..., CommandResult],
    *,
    restore_timeout: float,
    poll_interval: float,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    signal_state: SignalState,
) -> str | None:
    """Restore the daemon and preserve any failure from the start command.

    A healthy status after `bg start` does not erase a nonzero start result.
    """
    try:
        if _run_status(executable, command_runner):
            return None
    except IsolationError as error:
        return f"Could not verify daemon state before restoration: {error}"

    start_result = _run_lifecycle_command(executable, "start", command_runner)
    try:
        _wait_for_state(
            executable,
            True,
            command_runner,
            timeout=restore_timeout,
            poll_interval=poll_interval,
            clock=clock,
            sleep=sleep,
            signal_state=signal_state,
            raise_on_signal=False,
            timeout_message="Git AI daemon did not return to a healthy running state",
        )
    except IsolationError as error:
        if start_result.timed_out:
            detail = "start command timed out"
        elif start_result.returncode != 0:
            detail = "start command failed"
        else:
            detail = "daemon did not become healthy"
        return f"{detail}: {error}"
    if start_result.returncode != 0:
        return (
            f"start command failed with exit status {start_result.returncode}; "
            "observed daemon status: running"
        )
    return None


def run_isolated_suite(
    suite_command: Sequence[str] | None = None,
    *,
    lock_path: Path | None = None,
    executable_lookup: Callable[[str], str | None] | None = None,
    command_runner: Callable[..., CommandResult] | None = None,
    suite_runner: Callable[..., int] | None = None,
    lock_timeout: float = LOCK_TIMEOUT,
    shutdown_timeout: float = SHUTDOWN_TIMEOUT,
    restore_timeout: float = RESTORE_TIMEOUT,
    status_poll_interval: float = STATUS_POLL_INTERVAL,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    diagnostic: Callable[[str], None] = print,
) -> int:
    """Run the content-policy suite with bounded, state-preserving isolation."""
    unsupported_reason = _unsupported_platform_reason()
    if unsupported_reason is not None:
        diagnostic(f"Git AI isolation unavailable: {unsupported_reason}")
        return 2

    command = list(suite_command or DEFAULT_SUITE_COMMAND)
    lock = lock_path or _default_lock_path()
    find_executable = executable_lookup or shutil.which
    execute_command = command_runner or _run_git_ai_command
    lifecycle_child_unresolved = False
    unresolved_lifecycle_command: str | None = None

    def run_command(
        command: list[str],
        *,
        cwd: str,
        timeout: float,
        capture_stdout: bool,
    ) -> CommandResult:
        nonlocal lifecycle_child_unresolved, unresolved_lifecycle_command
        if lifecycle_child_unresolved:
            raise IsolationError(
                "A previous Git AI CLI child has not been confirmed exited"
            )
        result = execute_command(
            command,
            cwd=cwd,
            timeout=timeout,
            capture_stdout=capture_stdout,
        )
        if not result.child_exit_confirmed:
            lifecycle_child_unresolved = True
            unresolved_lifecycle_command = " ".join(command[1:])
        return result

    run_suite = suite_runner or _execute_suite
    signal_state = SignalState()
    initial_running: bool | None = None
    shutdown_attempted = False
    suite_exit_code: int | None = None
    result_code = 2
    restore_failure: str | None = None
    suite_group_termination_confirmed = True

    try:
        with _exclusive_lock(
            lock, timeout=lock_timeout, clock=clock, sleep=sleep
        ):
            with _handle_termination_signals(signal_state):
                try:
                    executable = find_executable("git-ai")
                    if executable is None:
                        suite_exit_code = run_suite(
                            command,
                            _suite_environment(isolated=False),
                            None,
                            signal_state,
                        )
                    else:
                        initial_running = _run_status(executable, run_command)
                        if signal_state.requested_signal is not None:
                            raise _SignalRequested(signal_state.requested_signal)

                        if initial_running:
                            shutdown_attempted = True
                            shutdown_result = _run_lifecycle_command(
                                executable, "shutdown", run_command
                            )
                            if shutdown_result.timed_out:
                                raise IsolationError("Git AI shutdown command timed out")
                            if shutdown_result.returncode != 0:
                                raise IsolationError(
                                    "Git AI shutdown command failed; isolated tests were not started"
                                )
                            _wait_for_state(
                                executable,
                                False,
                                run_command,
                                timeout=shutdown_timeout,
                                poll_interval=status_poll_interval,
                                clock=clock,
                                sleep=sleep,
                                signal_state=signal_state,
                                timeout_message=(
                                    "Git AI shutdown timed out before the daemon stopped"
                                ),
                            )

                        def verify_stopped() -> None:
                            """Abort if the daemon restarts or its state becomes unknown."""
                            if signal_state.requested_signal is not None:
                                raise _SignalRequested(signal_state.requested_signal)
                            if _run_status(executable, run_command):
                                raise IsolationError(
                                    "Git AI daemon restarted during the isolated test suite"
                                )

                        verify_stopped()
                        suite_exit_code = run_suite(
                            command,
                            _suite_environment(isolated=True),
                            verify_stopped,
                            signal_state,
                        )

                    if signal_state.requested_signal is not None:
                        raise _SignalRequested(signal_state.requested_signal)
                    if initial_running is not None:
                        verify_stopped()
                    result_code = suite_exit_code
                except _SignalRequested as interrupted:
                    suite_exit_code = 128 + interrupted.signum
                    result_code = suite_exit_code
                    diagnostic(
                        f"Validation interrupted by signal {interrupted.signum}; restoring daemon state"
                    )
                except _SuiteProcessGroupTerminationError as error:
                    suite_group_termination_confirmed = False
                    result_code = 2
                    diagnostic(
                        f"SUITE TERMINATION FAILED: {error}. Daemon restoration was "
                        "skipped; verify that the suite group is gone and check "
                        "Git AI state before restarting it."
                    )
                except IsolationError as error:
                    result_code = 2
                    diagnostic(f"Git AI isolation aborted: {error}")
                except Exception as error:
                    result_code = 2
                    diagnostic(
                        "Git AI isolation aborted after an unexpected wrapper error "
                        f"({type(error).__name__})"
                    )
                finally:
                    if (
                        initial_running
                        and shutdown_attempted
                        and suite_group_termination_confirmed
                        and not lifecycle_child_unresolved
                    ):
                        restore_failure = _restore_running_daemon(
                            executable,
                            run_command,
                            restore_timeout=restore_timeout,
                            poll_interval=status_poll_interval,
                            clock=clock,
                            sleep=sleep,
                            signal_state=signal_state,
                        )
    except IsolationError as error:
        diagnostic(f"Git AI isolation aborted: {error}")
        return 2

    if suite_exit_code not in (None, 0) and result_code == 2:
        # Keep an observed test failure when a later wrapper check also failed.
        result_code = suite_exit_code
    if signal_state.requested_signal is not None:
        result_code = 128 + signal_state.requested_signal
    if lifecycle_child_unresolved:
        command = unresolved_lifecycle_command or "Git AI lifecycle command"
        diagnostic(
            f"GIT AI CLI CHILD UNRESOLVED: `{command}` did not exit within its "
            "bounded graceful termination period. Daemon restoration was skipped; "
            "inspect the child and daemon state before proceeding."
        )
    if restore_failure is not None:
        diagnostic(
            "RESTORATION FAILED: Git AI was initially running but could not be "
            f"verified healthy afterward ({restore_failure}). Run `git-ai bg status` "
            "from a non-repository directory, then `git-ai bg start` if it is stopped."
        )
        if result_code == 0:
            result_code = 1
    return result_code


def main() -> int:
    """Run the opt-in content-policy suite and return its process status."""
    return run_isolated_suite()


if __name__ == "__main__":
    raise SystemExit(main())
