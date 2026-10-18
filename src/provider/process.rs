//! Bounded direct process execution for a digest-qualified helper.
//!
//! The helper is started without a shell in its own process group (or Windows
//! job object). Stdout and stderr are drained concurrently with hard caps. A
//! deadline or cancellation terminates the whole group and waits for pipe
//! closure before the call returns.
use crate::inspection::CancellationHandle;
use command_group::{CommandGroup, GroupChild};
#[cfg(windows)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::{self, Read};
#[cfg(target_os = "macos")]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) const DEFAULT_STDOUT_LIMIT: usize = 32 * 1024 * 1024;
pub(crate) const DEFAULT_STDERR_LIMIT: usize = 1024 * 1024;
pub(crate) const DEFAULT_DEADLINE: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const READ_CHUNK: usize = 8 * 1024;
const READER_JOIN_GRACE: Duration = Duration::from_secs(2);
const TERMINATE_GRACE: Duration = Duration::from_millis(250);
#[cfg(target_os = "macos")]
const DEFAULT_CPU_SECONDS: u64 = 60;
#[cfg(target_os = "macos")]
const DEFAULT_OPEN_FILES: u64 = 64;
#[cfg(target_os = "macos")]
const DEFAULT_FILE_SIZE_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(test)]
struct ActiveReader(Arc<std::sync::atomic::AtomicUsize>);

#[cfg(test)]
impl ActiveReader {
    fn new(readers: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        readers.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(readers)
    }
}

#[cfg(test)]
impl Drop for ActiveReader {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessLimits {
    pub(crate) deadline: Duration,
    pub(crate) stdout: usize,
    pub(crate) stderr: usize,
    #[cfg(target_os = "macos")]
    cpu_seconds: u64,
    #[cfg(target_os = "macos")]
    open_files: u64,
    #[cfg(target_os = "macos")]
    file_size_bytes: u64,
    #[cfg(test)]
    allow_uncontained_for_test: bool,
    #[cfg(test)]
    active_readers: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    force_termination_failure: bool,
    #[cfg(test)]
    force_stderr_reader_start_failure: bool,
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            deadline: DEFAULT_DEADLINE,
            stdout: DEFAULT_STDOUT_LIMIT,
            stderr: DEFAULT_STDERR_LIMIT,
            #[cfg(target_os = "macos")]
            cpu_seconds: DEFAULT_CPU_SECONDS,
            #[cfg(target_os = "macos")]
            open_files: DEFAULT_OPEN_FILES,
            #[cfg(target_os = "macos")]
            file_size_bytes: DEFAULT_FILE_SIZE_BYTES,
            #[cfg(test)]
            allow_uncontained_for_test: false,
            #[cfg(test)]
            active_readers: None,
            #[cfg(test)]
            force_termination_failure: false,
            #[cfg(test)]
            force_stderr_reader_start_failure: false,
        }
    }
}

impl ProcessLimits {
    #[cfg(test)]
    pub(crate) fn uncontained_test_limits(
        deadline: Duration,
        stdout: usize,
        stderr: usize,
    ) -> Self {
        Self {
            deadline,
            stdout,
            stderr,
            allow_uncontained_for_test: true,
            ..Self::default()
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProcessOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessFailure {
    Launch,
    TimedOut,
    Cancelled,
    OutputExceeded,
    ContainmentUnsupported,
    Io,
    TerminationFailed,
}

struct Capture {
    bytes: Vec<u8>,
    exceeded: bool,
    failed: bool,
}

pub(crate) fn run(
    program: &Path,
    arguments: &[OsString],
    working_directory: &Path,
    limits: ProcessLimits,
    cancellation: Option<&CancellationHandle>,
) -> Result<ProcessOutput, ProcessFailure> {
    if cancellation.is_some_and(CancellationHandle::is_cancelled) {
        return Err(ProcessFailure::Cancelled);
    }

    let mut command = std::process::Command::new(program);
    command
        .args(arguments)
        .current_dir(working_directory)
        .env_clear()
        .env("HOME", working_directory)
        .env("USERPROFILE", working_directory)
        .env("TMPDIR", working_directory)
        .env("TMP", working_directory)
        .env("TEMP", working_directory)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "")
        .env("TZ", "UTC")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    copy_required_windows_environment(&mut command);
    configure_resource_controls(&mut command, &limits)?;

    let mut child = command.group().spawn().map_err(|error| {
        #[cfg(target_os = "macos")]
        if error.raw_os_error() == Some(libc::EOPNOTSUPP) {
            return ProcessFailure::ContainmentUnsupported;
        }
        let _ = error;
        ProcessFailure::Launch
    })?;
    #[cfg(test)]
    let force_termination_failure = limits.force_termination_failure;
    #[cfg(not(test))]
    let force_termination_failure = false;
    #[cfg(test)]
    let force_stderr_reader_start_failure = limits.force_stderr_reader_start_failure;
    #[cfg(not(test))]
    let force_stderr_reader_start_failure = false;
    let stdout = child.inner().stdout.take().ok_or(ProcessFailure::Io)?;
    let stderr = child.inner().stderr.take().ok_or(ProcessFailure::Io)?;
    let stop_readers = Arc::new(AtomicBool::new(false));

    let stdout_reader = match spawn_reader(
        stdout,
        limits.stdout,
        Arc::clone(&stop_readers),
        #[cfg(test)]
        limits.active_readers.clone(),
    ) {
        Ok(reader) => reader,
        Err(()) => {
            return if terminate(&mut child, force_termination_failure).is_err() {
                Err(ProcessFailure::TerminationFailed)
            } else {
                Err(ProcessFailure::Io)
            };
        }
    };
    let stderr_start = if force_stderr_reader_start_failure {
        Err(())
    } else {
        spawn_reader(
            stderr,
            limits.stderr,
            Arc::clone(&stop_readers),
            #[cfg(test)]
            limits.active_readers.clone(),
        )
    };
    let stderr_reader = match stderr_start {
        Ok(reader) => reader,
        Err(()) => {
            let termination = terminate(&mut child, force_termination_failure);
            stop_and_join_reader(stdout_reader, &stop_readers);
            return if termination.is_err() {
                Err(ProcessFailure::TerminationFailed)
            } else {
                Err(ProcessFailure::Io)
            };
        }
    };

    let started = Instant::now();
    let status = loop {
        if cancellation.is_some_and(CancellationHandle::is_cancelled) {
            let termination = terminate(&mut child, force_termination_failure);
            stop_and_join_readers(stdout_reader, stderr_reader, &stop_readers);
            if termination.is_err() {
                return Err(ProcessFailure::TerminationFailed);
            }
            return Err(ProcessFailure::Cancelled);
        }
        if started.elapsed() >= limits.deadline {
            let termination = terminate(&mut child, force_termination_failure);
            stop_and_join_readers(stdout_reader, stderr_reader, &stop_readers);
            if termination.is_err() {
                return Err(ProcessFailure::TerminationFailed);
            }
            return Err(ProcessFailure::TimedOut);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(_) => {
                let termination = terminate(&mut child, force_termination_failure);
                stop_and_join_readers(stdout_reader, stderr_reader, &stop_readers);
                if termination.is_err() {
                    return Err(ProcessFailure::TerminationFailed);
                }
                return Err(ProcessFailure::Io);
            }
        }
    };

    // On Windows the leader can exit while a descendant still owns an
    // inherited pipe. Terminating the job closes those handles. On Unix this
    // is a harmless attempt once the process group is empty.
    if terminate(&mut child, force_termination_failure).is_err() {
        stop_and_join_readers(stdout_reader, stderr_reader, &stop_readers);
        return Err(ProcessFailure::TerminationFailed);
    }
    let reader_deadline = Instant::now() + READER_JOIN_GRACE;
    let (stdout, stderr) =
        finish_readers(stdout_reader, stderr_reader, reader_deadline, &stop_readers)?;
    if stdout.exceeded || stderr.exceeded {
        return Err(ProcessFailure::OutputExceeded);
    }
    if stdout.failed || stderr.failed {
        return Err(ProcessFailure::Io);
    }
    Ok(ProcessOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

/// Verifies the supported hard process controls before provider execution.
pub(crate) fn probe_hard_controls() -> Result<(), ProcessFailure> {
    #[cfg(target_os = "macos")]
    {
        let working_directory = tempfile::tempdir().map_err(|_| ProcessFailure::Io)?;
        let output = run(
            Path::new("/usr/bin/true"),
            &[],
            working_directory.path(),
            ProcessLimits::default(),
            None,
        )?;
        if output.status.success() {
            Ok(())
        } else {
            Err(ProcessFailure::ContainmentUnsupported)
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(ProcessFailure::ContainmentUnsupported)
    }
}

fn configure_resource_controls(
    command: &mut std::process::Command,
    limits: &ProcessLimits,
) -> Result<(), ProcessFailure> {
    #[cfg(test)]
    if limits.allow_uncontained_for_test {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let cpu_seconds = limits.cpu_seconds as libc::rlim_t;
        let open_files = limits.open_files as libc::rlim_t;
        let file_size = limits.file_size_bytes as libc::rlim_t;
        unsafe {
            command.pre_exec(move || {
                for (resource, value) in [
                    (libc::RLIMIT_CPU, cpu_seconds),
                    (libc::RLIMIT_NOFILE, open_files),
                    (libc::RLIMIT_FSIZE, file_size),
                    (libc::RLIMIT_CORE, 0),
                ] {
                    let limit = libc::rlimit {
                        rlim_cur: value,
                        rlim_max: value,
                    };
                    if libc::setrlimit(resource, &limit) != 0 {
                        return Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP));
                    }
                }
                Ok(())
            });
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (command, limits);
        Err(ProcessFailure::ContainmentUnsupported)
    }
}

trait NonblockingPipe: Read + Send {
    fn prepare_nonblocking(&self) -> io::Result<()>;
    fn read_available(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>>;
}

#[cfg(unix)]
impl<T: Read + std::os::fd::AsRawFd + Send> NonblockingPipe for T {
    fn prepare_nonblocking(&self) -> io::Result<()> {
        let fd = self.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_available(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        match self.read(buffer) {
            Ok(read) => Ok(Some(read)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[cfg(windows)]
impl<T: Read + std::os::windows::io::AsRawHandle + Send> NonblockingPipe for T {
    fn prepare_nonblocking(&self) -> io::Result<()> {
        Ok(())
    }

    fn read_available(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        let mut available = 0_u32;
        let result = unsafe {
            windows_sys::Win32::System::Pipes::PeekNamedPipe(
                self.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if error == 109 {
                return Ok(Some(0));
            }
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        if available == 0 {
            return Ok(None);
        }
        let count = buffer.len().min(available as usize);
        self.read(&mut buffer[..count]).map(Some)
    }
}

#[cfg(not(any(unix, windows)))]
impl<T: Read + Send> NonblockingPipe for T {
    fn prepare_nonblocking(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "nonblocking process pipes are unavailable on this platform",
        ))
    }

    fn read_available(&mut self, _buffer: &mut [u8]) -> io::Result<Option<usize>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "nonblocking process pipes are unavailable on this platform",
        ))
    }
}

fn spawn_reader(
    mut stream: impl NonblockingPipe + 'static,
    limit: usize,
    stop: Arc<AtomicBool>,
    #[cfg(test)] active_readers: Option<Arc<std::sync::atomic::AtomicUsize>>,
) -> Result<JoinHandle<Capture>, ()> {
    stream.prepare_nonblocking().map_err(|_| ())?;
    thread::Builder::new()
        .name("nscb-provider-output".to_owned())
        .spawn(move || {
            #[cfg(test)]
            let _active_reader = active_readers.map(ActiveReader::new);
            let mut bytes = Vec::new();
            let mut exceeded = false;
            let mut failed = false;
            let mut buffer = [0_u8; READ_CHUNK];
            loop {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                match stream.read_available(&mut buffer) {
                    Ok(Some(0)) => break,
                    Ok(Some(read)) => {
                        if !exceeded {
                            if bytes.len().saturating_add(read) > limit {
                                exceeded = true;
                                bytes.clear();
                            } else if bytes.try_reserve(read).is_err() {
                                failed = true;
                                bytes.clear();
                            } else {
                                bytes.extend_from_slice(&buffer[..read]);
                            }
                        }
                    }
                    Ok(None) => thread::sleep(POLL_INTERVAL),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            Capture {
                bytes,
                exceeded,
                failed,
            }
        })
        .map_err(|_| ())
}

fn finish_readers(
    stdout: JoinHandle<Capture>,
    stderr: JoinHandle<Capture>,
    deadline: Instant,
    stop: &AtomicBool,
) -> Result<(Capture, Capture), ProcessFailure> {
    while !stdout.is_finished() || !stderr.is_finished() {
        if Instant::now() >= deadline {
            stop.store(true, Ordering::Release);
            let _ = stdout.join();
            let _ = stderr.join();
            return Err(ProcessFailure::Io);
        }
        thread::sleep(POLL_INTERVAL);
    }
    let stdout = stdout.join().map_err(|_| ProcessFailure::Io)?;
    let stderr = stderr.join().map_err(|_| ProcessFailure::Io)?;
    Ok((stdout, stderr))
}

fn stop_and_join_readers(
    stdout: JoinHandle<Capture>,
    stderr: JoinHandle<Capture>,
    stop: &AtomicBool,
) {
    stop.store(true, Ordering::Release);
    let _ = stdout.join();
    let _ = stderr.join();
}

fn stop_and_join_reader(reader: JoinHandle<Capture>, stop: &AtomicBool) {
    stop.store(true, Ordering::Release);
    let _ = reader.join();
}

fn terminate(child: &mut GroupChild, force_failure: bool) -> Result<(), ProcessFailure> {
    let kill_result = child.kill();
    if force_failure {
        return Err(ProcessFailure::TerminationFailed);
    }
    let deadline = Instant::now() + TERMINATE_GRACE;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Err(_) => return Err(ProcessFailure::TerminationFailed),
            Ok(None) => thread::sleep(POLL_INTERVAL),
        }
    }
    let _ = child.inner().try_wait();
    if kill_result.is_err() {
        return Err(ProcessFailure::TerminationFailed);
    }
    Err(ProcessFailure::TerminationFailed)
}

#[cfg(windows)]
fn copy_required_windows_environment(command: &mut std::process::Command) {
    for name in [OsStr::new("SystemRoot"), OsStr::new("WINDIR")] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}

#[cfg(not(windows))]
fn copy_required_windows_environment(_command: &mut std::process::Command) {}

impl ProcessOutput {
    pub(crate) fn succeeded(&self) -> bool {
        self.status.success()
    }
}

#[cfg(test)]
mod tests {
    use super::{ProcessFailure, ProcessLimits, run};
    use crate::inspection::CancellationHandle;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    static NEXT_SCRIPT: AtomicU64 = AtomicU64::new(1);

    #[cfg(unix)]
    struct EscapedDescendant(PathBuf);

    #[cfg(unix)]
    impl Drop for EscapedDescendant {
        fn drop(&mut self) {
            if let Ok(pid) = fs::read_to_string(&self.0)
                .and_then(|pid| pid.trim().parse::<i32>().map_err(std::io::Error::other))
            {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn escaped_descendant_handshake_proves_pipe_reader_cleanup_is_bounded() {
        let directory = workdir();
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("helper");
        let pid_file = directory.join("descendant.pid");
        let _descendant = EscapedDescendant(pid_file.clone());
        let body = format!(
            "/usr/bin/perl -MPOSIX -e 'my $sid = POSIX::setsid(); die unless defined($sid) && $sid >= 0; open my $f, \">\", $ARGV[0] or die; print $f \"$$\\n\"; close $f or die; exec \"/bin/sleep\", \"30\";' '{}' &\n\
             i=0\n\
             while [ ! -s '{}' ]; do i=$((i + 1)); [ $i -lt 500 ] || exit 70; /bin/sleep 0.01; done\n\
             pid=$(/bin/cat '{}')\n\
             /bin/kill -0 \"$pid\" || exit 71\n\
             exit 0",
            pid_file.display(),
            pid_file.display(),
            pid_file.display(),
        );
        write_script(&path, &body);

        let active_readers = Arc::new(AtomicUsize::new(0));
        let mut limits = test_limits(Duration::from_secs(30), 1024, 1024);
        limits.active_readers = Some(Arc::clone(&active_readers));
        let started = Instant::now();
        let result = run(&path, &[], &directory, limits, None);

        assert!(
            pid_file.exists(),
            "descendant published its PID after setsid"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(active_readers.load(Ordering::SeqCst), 0);
        assert_eq!(result.unwrap_err(), ProcessFailure::Io);
        let _ = fs::remove_dir_all(directory);
    }

    fn workdir() -> PathBuf {
        let id = NEXT_SCRIPT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("nscb-process-test-{}-{id}", std::process::id()))
    }

    fn test_limits(deadline: Duration, stdout: usize, stderr: usize) -> ProcessLimits {
        ProcessLimits::uncontained_test_limits(deadline, stdout, stderr)
    }

    #[cfg(unix)]
    fn script(body: &str) -> (PathBuf, PathBuf) {
        let directory = workdir();
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("helper");
        write_script(&path, body);
        (path, directory)
    }

    #[cfg(unix)]
    fn write_script(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn captures_bounded_output_and_sanitizes_the_environment() {
        let (path, directory) = script("printf '%s' \"$HOME|$PATH|$UNEXPECTED\"");
        let output = run(
            &path,
            &[],
            &directory,
            test_limits(Duration::from_secs(2), 1024, 1024),
            None,
        )
        .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout, format!("{}||", directory.display()));
        assert!(output.stderr.is_empty());
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn launches_the_exact_executable_with_one_typed_argument_and_no_path_lookup() {
        let (path, directory) = script("printf '%s|%s' \"$1\" \"$PATH\"");
        let argument = OsString::from("value; touch PWNED");
        let output = run(
            &path,
            &[argument],
            &directory,
            test_limits(Duration::from_secs(2), 1024, 1024),
            None,
        )
        .unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout, b"value; touch PWNED|");
        assert!(!directory.join("PWNED").exists());
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn signal_termination_is_preserved_as_a_signal_status() {
        use std::os::unix::process::ExitStatusExt;

        let (path, directory) = script("kill -TERM $$");
        let output = run(
            &path,
            &[],
            &directory,
            test_limits(Duration::from_secs(2), 1024, 1024),
            None,
        )
        .unwrap();
        assert_eq!(output.status.code(), None);
        assert_eq!(output.status.signal(), Some(libc::SIGTERM));
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn successful_child_is_reaped_before_run_returns() {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("pid");
        let (path, script_directory) =
            script(&format!("printf '%s' \"$$\" > '{}'", pid_path.display()));
        let output = run(
            &path,
            &[],
            &script_directory,
            test_limits(Duration::from_secs(2), 1024, 1024),
            None,
        )
        .unwrap();
        assert!(output.status.success());
        let pid = fs::read_to_string(&pid_path)
            .unwrap()
            .parse::<libc::pid_t>()
            .unwrap();
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(waited, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        let _ = fs::remove_dir_all(script_directory);
    }

    #[cfg(unix)]
    #[test]
    fn timeout_terminates_a_descendant_that_holds_an_inherited_pipe() {
        let (path, directory) = script("/bin/sleep 30 & wait");
        let started = Instant::now();
        let failure = run(
            &path,
            &[],
            &directory,
            test_limits(Duration::from_millis(150), 1024, 1024),
            None,
        )
        .unwrap_err();
        assert_eq!(failure, ProcessFailure::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_is_bounded_even_when_a_helper_ignores_signals() {
        let (path, directory) = script("trap '' TERM INT; /bin/sleep 30 & wait");
        let cancellation = CancellationHandle::new();
        let worker = cancellation.clone();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            worker.cancel();
        });
        let started = Instant::now();
        let failure = run(
            &path,
            &[],
            &directory,
            test_limits(Duration::from_secs(30), 1024, 1024),
            Some(&cancellation),
        )
        .unwrap_err();
        assert_eq!(failure, ProcessFailure::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(3));
        thread.join().unwrap();
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn termination_failure_is_reported_and_readers_still_stop_after_cancellation() {
        let (path, directory) = script("/bin/sleep 30 & wait");
        let cancellation = CancellationHandle::new();
        let worker = cancellation.clone();
        let cancel_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            worker.cancel();
        });
        let active_readers = Arc::new(AtomicUsize::new(0));
        let mut limits = test_limits(Duration::from_secs(30), 1024, 1024);
        limits.active_readers = Some(Arc::clone(&active_readers));
        limits.force_termination_failure = true;
        let started = Instant::now();
        let failure = run(&path, &[], &directory, limits, Some(&cancellation)).unwrap_err();

        assert_eq!(failure, ProcessFailure::TerminationFailed);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(active_readers.load(Ordering::SeqCst), 0);
        cancel_thread.join().unwrap();
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn stderr_reader_start_and_termination_failure_join_started_reader() {
        let (path, directory) = script("/bin/sleep 30 & wait");
        let active_readers = Arc::new(AtomicUsize::new(0));
        let mut limits = test_limits(Duration::from_secs(2), 1024, 1024);
        limits.active_readers = Some(Arc::clone(&active_readers));
        limits.force_termination_failure = true;
        limits.force_stderr_reader_start_failure = true;
        let started = Instant::now();

        let failure = run(&path, &[], &directory, limits, None).unwrap_err();

        assert_eq!(failure, ProcessFailure::TerminationFailed);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(active_readers.load(Ordering::SeqCst), 0);
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn stdout_and_stderr_caps_are_independent() {
        let (path, directory) = script("printf '0123456789'; printf 'abcdefghij' >&2");
        let failure = run(
            &path,
            &[],
            &directory,
            test_limits(Duration::from_secs(2), 5, 1024),
            None,
        )
        .unwrap_err();
        assert_eq!(failure, ProcessFailure::OutputExceeded);
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn a_nonzero_exit_is_reported_to_the_caller_without_exposing_output() {
        let (path, directory) = script("printf secret >&2; exit 9");
        let output = run(
            &path,
            &[OsString::from("ignored")],
            &directory,
            test_limits(Duration::from_secs(2), 1024, 1024),
            None,
        )
        .unwrap();
        assert!(!output.succeeded());
        assert_eq!(output.stderr, b"secret");
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn an_absent_executable_is_a_launch_failure() {
        let directory = workdir();
        fs::create_dir_all(&directory).unwrap();
        let failure = run(
            Path::new("/definitely/not/a/provider"),
            &[],
            &directory,
            test_limits(Duration::from_secs(2), 1024, 1024),
            None,
        )
        .unwrap_err();
        assert_eq!(failure, ProcessFailure::Launch);
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_before_spawn_does_not_start_the_helper() {
        let (path, directory) = script("printf ran");
        let cancellation = CancellationHandle::new();
        cancellation.cancel();
        let failure = run(
            &path,
            &[],
            &directory,
            ProcessLimits::default(),
            Some(&cancellation),
        )
        .unwrap_err();
        assert_eq!(failure, ProcessFailure::Cancelled);
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn production_launch_enforces_supported_darwin_hard_limits() {
        let directory = workdir();
        fs::create_dir_all(&directory).unwrap();
        let source = directory.join("resource_probe.c");
        let executable = directory.join("resource_probe");
        let source_text = r#"
#include <sys/resource.h>
static int has_limit(int resource, rlim_t expected) {
    struct rlimit limit;
    return getrlimit(resource, &limit) == 0 &&
        limit.rlim_cur == expected && limit.rlim_max == expected;
}

int main(void) {
    if (!has_limit(RLIMIT_CPU, (rlim_t)@CPU@)) return 12;
    if (!has_limit(RLIMIT_NOFILE, (rlim_t)@FILES@)) return 13;
    if (!has_limit(RLIMIT_FSIZE, (rlim_t)@FSIZE@)) return 14;
    if (!has_limit(RLIMIT_CORE, (rlim_t)0)) return 15;
    return 0;
}
"#;
        let source_text = source_text
            .replace("@CPU@", &super::DEFAULT_CPU_SECONDS.to_string())
            .replace("@FILES@", &super::DEFAULT_OPEN_FILES.to_string())
            .replace("@FSIZE@", &super::DEFAULT_FILE_SIZE_BYTES.to_string());
        fs::write(&source, source_text).unwrap();
        let compile = std::process::Command::new("/usr/bin/clang")
            .arg("-O0")
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()
            .expect("the native containment probe requires the macOS compiler");
        assert!(
            compile.success(),
            "the native containment probe did not compile"
        );

        let output = run(&executable, &[], &directory, ProcessLimits::default(), None)
            .expect("supported Darwin hard limits allow launch without a memory cap");
        assert_eq!(output.status.code(), Some(0));
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(not(target_os = "macos"))]
    #[cfg(unix)]
    #[test]
    fn unsupported_platform_fails_closed_before_starting_a_child() {
        let directory = workdir();
        fs::create_dir_all(&directory).unwrap();
        let marker = directory.join("started");
        let (path, _) = script(&format!("touch '{}'", marker.display()));
        let failure = run(&path, &[], &directory, ProcessLimits::default(), None).unwrap_err();
        assert_eq!(failure, ProcessFailure::ContainmentUnsupported);
        assert!(!marker.exists());
        let _ = fs::remove_dir_all(directory);
    }
}
