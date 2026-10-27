//! Bounded output transport used only by the macOS `copy` executable path.
//!
//! The filesystem operation remains synchronous and host-owned. Two private
//! workers write complete records to duplicated standard-stream descriptors;
//! the command thread queues records without waiting on pipe capacity. Once
//! execution returns, the command waits for acknowledgments only through one
//! five-second monotonic deadline. Dropping a worker handle never joins it.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const REPORTING_BUDGET: Duration = Duration::from_secs(5);
const SEMANTIC_QUEUE_CAPACITY: usize = 16;
const DIAGNOSTIC_QUEUE_CAPACITY: usize = 4;

#[derive(Default)]
struct TimingState {
    filesystem_execution_active: bool,
    deadline_origin: Option<Instant>,
}

/// Per-invocation completion and failure signals shared with the output workers.
#[derive(Clone, Default)]
pub(crate) struct ReportingControl {
    timing: Arc<Mutex<TimingState>>,
    failed: Arc<AtomicBool>,
    outstanding: Arc<AtomicUsize>,
}

impl ReportingControl {
    /// Starts planning without starting the post-execution reporting budget.
    pub(crate) fn begin_planning(&self) {
        if let Ok(mut timing) = self.timing.lock() {
            timing.filesystem_execution_active = true;
            timing.deadline_origin = None;
        }
    }

    /// Starts the budget when a pre-admission error becomes reportable.
    pub(crate) fn pre_admission_complete(&self) {
        self.finish_at(Instant::now());
    }

    /// Starts the budget after execution and operation-owned cleanup return.
    pub(crate) fn job_complete(&self) {
        self.finish_at(Instant::now());
    }

    fn finish_at(&self, terminalized_at: Instant) {
        if let Ok(mut timing) = self.timing.lock() {
            timing.filesystem_execution_active = false;
            timing.deadline_origin = Some(terminalized_at);
        }
    }

    fn record_pre_admission_output(&self) {
        if let Ok(mut timing) = self.timing.lock()
            && !timing.filesystem_execution_active
            && timing.deadline_origin.is_none()
        {
            timing.deadline_origin = Some(Instant::now());
        }
    }

    fn deadline(&self) -> Instant {
        self.timing
            .lock()
            .ok()
            .and_then(|timing| timing.deadline_origin)
            .unwrap_or_else(Instant::now)
            + REPORTING_BUDGET
    }

    pub(crate) fn fail(&self) {
        self.failed.store(true, Ordering::Release);
    }

    fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn has_outstanding_records(&self) -> bool {
        self.outstanding.load(Ordering::Acquire) != 0
    }

    fn acknowledge_record(&self, acknowledged_at: Instant) {
        let late = self.timing.lock().ok().is_some_and(|timing| {
            !timing.filesystem_execution_active
                && timing
                    .deadline_origin
                    .is_some_and(|origin| acknowledged_at >= origin + REPORTING_BUDGET)
        });
        if late {
            self.fail();
        }
        self.outstanding.fetch_sub(1, Ordering::AcqRel);
    }

    #[cfg(test)]
    fn job_complete_at(&self, terminalized_at: Instant) {
        self.finish_at(terminalized_at);
    }
}

struct ReportWriter {
    sender: mpsc::SyncSender<Vec<u8>>,
    control: ReportingControl,
}

impl Write for ReportWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.control.record_pre_admission_output();
        self.control.outstanding.fetch_add(1, Ordering::AcqRel);
        match self.sender.try_send(bytes.to_vec()) {
            Ok(()) => Ok(bytes.len()),
            Err(mpsc::TrySendError::Full(_)) => {
                self.control.outstanding.fetch_sub(1, Ordering::AcqRel);
                self.control.fail();
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "bounded reporting queue is full",
                ))
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.control.outstanding.fetch_sub(1, Ordering::AcqRel);
                self.control.fail();
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "reporting worker stopped",
                ))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // Each queue item is one complete record; the worker flushes after it.
        Ok(())
    }
}

fn duplicate_file(descriptor: std::os::fd::RawFd) -> io::Result<File> {
    let duplicate = unsafe { libc::dup(descriptor) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // `dup` leaves the caller's descriptor flags unchanged. The duplicate is
    // private to this worker and is closed by `File` when the worker exits.
    Ok(unsafe { File::from_raw_fd(duplicate) })
}

fn spawn_writer<W>(
    mut file: W,
    receiver: mpsc::Receiver<Vec<u8>>,
    control: ReportingControl,
) -> io::Result<JoinHandle<()>>
where
    W: Write + Send + 'static,
{
    thread::Builder::new().spawn(move || {
        while let Ok(record) = receiver.recv() {
            let result = file.write_all(&record).and_then(|()| file.flush());
            let acknowledged_at = Instant::now();
            if result.is_err() {
                control.fail();
            }
            // This decrement is the acknowledgment that the complete record
            // was written and flushed, or that its write failed.
            control.acknowledge_record(acknowledged_at);
        }
    })
}

/// Owns the executable's bounded stdout and stderr reporting workers.
pub(crate) struct ReportingSession {
    stdout: ReportWriter,
    stderr: ReportWriter,
    control: ReportingControl,
    // Dropping JoinHandle detaches a worker. The process may then terminate
    // even when an OS pipe has left that worker blocked in `write`.
    _workers: Vec<JoinHandle<()>>,
}

impl ReportingSession {
    /// Duplicates both standard descriptors and starts their bounded workers.
    pub(crate) fn new() -> io::Result<Self> {
        let stdout_file = duplicate_file(std::io::stdout().as_raw_fd())?;
        let stderr_file = duplicate_file(std::io::stderr().as_raw_fd())?;
        let control = ReportingControl::default();
        let (stdout_sender, stdout_receiver) = mpsc::sync_channel(SEMANTIC_QUEUE_CAPACITY);
        let (stderr_sender, stderr_receiver) = mpsc::sync_channel(DIAGNOSTIC_QUEUE_CAPACITY);
        let stdout_worker = spawn_writer(stdout_file, stdout_receiver, control.clone())?;
        let stderr_worker = spawn_writer(stderr_file, stderr_receiver, control.clone())?;
        Ok(Self {
            stdout: ReportWriter {
                sender: stdout_sender,
                control: control.clone(),
            },
            stderr: ReportWriter {
                sender: stderr_sender,
                control: control.clone(),
            },
            control,
            _workers: vec![stdout_worker, stderr_worker],
        })
    }

    /// Creates an already-failed transport when descriptor duplication or
    /// worker startup fails. Copy execution can still finish authoritatively.
    pub(crate) fn unavailable() -> Self {
        let control = ReportingControl::default();
        control.fail();
        let (stdout_sender, stdout_receiver) = mpsc::sync_channel(SEMANTIC_QUEUE_CAPACITY);
        let (stderr_sender, stderr_receiver) = mpsc::sync_channel(DIAGNOSTIC_QUEUE_CAPACITY);
        drop(stdout_receiver);
        drop(stderr_receiver);
        Self {
            stdout: ReportWriter {
                sender: stdout_sender,
                control: control.clone(),
            },
            stderr: ReportWriter {
                sender: stderr_sender,
                control: control.clone(),
            },
            control,
            _workers: Vec::new(),
        }
    }

    pub(crate) fn control(&self) -> ReportingControl {
        self.control.clone()
    }

    pub(crate) fn writers(&mut self) -> (&mut dyn Write, &mut dyn Write) {
        (&mut self.stdout, &mut self.stderr)
    }

    /// Waits for complete-record acknowledgments through the one shared budget.
    /// A report error changes the process code, never the completed Job result.
    pub(crate) fn finish(&mut self, operation_exit: i32) -> i32 {
        self.finish_with_wait_hook(operation_exit, || {})
    }

    fn finish_with_wait_hook(&mut self, operation_exit: i32, wait_started: impl FnOnce()) -> i32 {
        let deadline = self.control.deadline();
        let mut diagnostic_attempted = false;
        self.attempt_failure_diagnostic(deadline, &mut diagnostic_attempted);
        wait_started();

        loop {
            self.attempt_failure_diagnostic(deadline, &mut diagnostic_attempted);
            if !self.control.has_outstanding_records() {
                // A worker can publish failure immediately before its final
                // acknowledgment. Check again before leaving so a just-observed
                // write or flush error gets its one diagnostic.
                self.attempt_failure_diagnostic(deadline, &mut diagnostic_attempted);
                if !self.control.has_outstanding_records() {
                    break;
                }
            }
            let now = Instant::now();
            if now >= deadline {
                self.control.fail();
                break;
            }
            thread::sleep((deadline - now).min(Duration::from_millis(5)));
        }

        if self.control.is_failed() {
            7
        } else {
            operation_exit
        }
    }

    fn attempt_failure_diagnostic(&mut self, deadline: Instant, attempted: &mut bool) {
        if *attempted || !self.control.is_failed() || Instant::now() >= deadline {
            return;
        }
        *attempted = true;
        let mut diagnostic = crate::localization::english::output_failure()
            .as_bytes()
            .to_vec();
        diagnostic.push(b'\n');
        let _ = self.stderr.write_all(&diagnostic);
    }
}

#[cfg(test)]
mod tests {
    use super::{REPORTING_BUDGET, ReportWriter, ReportingControl, ReportingSession, spawn_writer};
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::{Duration, Instant};

    struct WriteFailure;

    impl Write for WriteFailure {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken sink"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FlushFailure;

    impl Write for FlushFailure {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }

    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct GatedWriter {
        started: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        finished: mpsc::Sender<()>,
        fail_write: bool,
    }

    impl Write for GatedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let _ = self.started.send(());
            let _ = self.release.recv();
            let _ = self.finished.send(());
            if self.fail_write {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "released failure",
                ))
            } else {
                Ok(bytes.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn assert_worker_failure_is_reported(writer: impl Write + Send + 'static) {
        let control = ReportingControl::default();
        let (stdout_sender, stdout_receiver) = mpsc::sync_channel(1);
        let (stderr_sender, stderr_receiver) = mpsc::sync_channel(1);
        let stdout_worker = spawn_writer(writer, stdout_receiver, control.clone()).unwrap();
        let stderr_bytes = Arc::new(Mutex::new(Vec::new()));
        let stderr_worker = spawn_writer(
            CaptureWriter(Arc::clone(&stderr_bytes)),
            stderr_receiver,
            control.clone(),
        )
        .unwrap();
        let mut session = ReportingSession {
            stdout: ReportWriter {
                sender: stdout_sender,
                control: control.clone(),
            },
            stderr: ReportWriter {
                sender: stderr_sender,
                control: control.clone(),
            },
            control: control.clone(),
            _workers: vec![stdout_worker, stderr_worker],
        };
        session.stdout.write_all(b"result record").unwrap();

        let failure_deadline = Instant::now() + Duration::from_secs(2);
        while !control.is_failed() {
            assert!(
                Instant::now() < failure_deadline,
                "writer failure was not observed"
            );
            std::thread::yield_now();
        }
        control.job_complete();

        assert_eq!(session.finish(0), 7);
        assert_eq!(
            *stderr_bytes.lock().unwrap(),
            format!("{}\n", crate::localization::english::output_failure()).as_bytes()
        );
    }

    #[test]
    fn reporting_deadline_starts_at_the_terminal_completion_receipt() {
        let control = ReportingControl::default();
        control.begin_planning();
        let completion = Instant::now();
        control.job_complete_at(completion);
        assert_eq!(control.deadline(), completion + REPORTING_BUDGET);
        assert!(control.deadline() >= Instant::now());
        assert_eq!(REPORTING_BUDGET, Duration::from_secs(5));
    }

    #[test]
    fn acknowledgment_after_the_shared_deadline_takes_exit_code_seven_precedence() {
        let control = ReportingControl::default();
        let (stdout_sender, stdout_receiver) = mpsc::sync_channel(1);
        let (stderr_sender, stderr_receiver) = mpsc::sync_channel(1);
        let (write_started_sender, write_started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (finished_sender, _finished_receiver) = mpsc::channel();
        let stdout_worker = spawn_writer(
            GatedWriter {
                started: write_started_sender,
                release: release_receiver,
                finished: finished_sender,
                fail_write: false,
            },
            stdout_receiver,
            control.clone(),
        )
        .unwrap();
        let stderr_worker = spawn_writer(io::sink(), stderr_receiver, control.clone()).unwrap();
        let mut session = ReportingSession {
            stdout: ReportWriter {
                sender: stdout_sender,
                control: control.clone(),
            },
            stderr: ReportWriter {
                sender: stderr_sender,
                control: control.clone(),
            },
            control: control.clone(),
            _workers: vec![stdout_worker, stderr_worker],
        };
        session.stdout.write_all(b"terminal result").unwrap();
        write_started_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("stdout worker reached the controlled write");

        control.job_complete_at(Instant::now() - REPORTING_BUDGET - Duration::from_millis(1));
        release_sender.send(()).unwrap();
        let acknowledgment_deadline = Instant::now() + Duration::from_secs(2);
        while control.has_outstanding_records() {
            assert!(
                Instant::now() < acknowledgment_deadline,
                "writer did not acknowledge the released record"
            );
            std::thread::yield_now();
        }

        assert!(Instant::now() >= control.deadline());
        assert_eq!(session.finish(3), 7);
    }

    #[test]
    fn reporting_failure_takes_precedence_over_every_operation_exit_class() {
        // A succeeded result with a cleanup warning retains operation exit 0;
        // reporting failure still takes process-exit precedence.
        for operation_exit in [0, 2, 3, 4, 6, 7] {
            let mut session = ReportingSession::unavailable();
            assert_eq!(session.finish(operation_exit), 7);
        }
    }

    #[test]
    fn report_records_are_admitted_without_blocking_and_the_queue_is_bounded() {
        let control = ReportingControl::default();
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut writer = ReportWriter {
            sender,
            control: control.clone(),
        };
        let record = b"{\"kind\":\"job.result\"}\n";
        assert_eq!(writer.write(record).unwrap(), record.len());
        assert_eq!(receiver.try_recv().unwrap(), record);
        assert_eq!(
            writer.write(record).unwrap(),
            record.len(),
            "the first complete record is queued without waiting for its writer"
        );
        assert_eq!(
            writer.write(record).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(control.is_failed());
        assert!(control.has_outstanding_records());
    }

    #[test]
    fn worker_write_and_flush_failures_attempt_one_bounded_stderr_diagnostic() {
        assert_worker_failure_is_reported(WriteFailure);
        assert_worker_failure_is_reported(FlushFailure);
    }

    #[test]
    fn worker_failure_during_reporting_wait_still_attempts_diagnostic() {
        let control = ReportingControl::default();
        let (stdout_sender, stdout_receiver) = mpsc::sync_channel(1);
        let (stderr_sender, stderr_receiver) = mpsc::sync_channel(1);
        let (write_started_sender, write_started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (write_finished_sender, _write_finished_receiver) = mpsc::channel();
        let stdout_worker = spawn_writer(
            GatedWriter {
                started: write_started_sender,
                release: release_receiver,
                finished: write_finished_sender,
                fail_write: true,
            },
            stdout_receiver,
            control.clone(),
        )
        .unwrap();
        let stderr_bytes = Arc::new(Mutex::new(Vec::new()));
        let stderr_worker = spawn_writer(
            CaptureWriter(Arc::clone(&stderr_bytes)),
            stderr_receiver,
            control.clone(),
        )
        .unwrap();
        let mut session = ReportingSession {
            stdout: ReportWriter {
                sender: stdout_sender,
                control: control.clone(),
            },
            stderr: ReportWriter {
                sender: stderr_sender,
                control: control.clone(),
            },
            control: control.clone(),
            _workers: vec![stdout_worker, stderr_worker],
        };
        session.stdout.write_all(b"pending result").unwrap();
        write_started_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("stdout worker reached the controlled write");
        control.job_complete();

        let (waiting_sender, waiting_receiver) = mpsc::channel();
        let (exit_sender, exit_receiver) = mpsc::channel();
        let finish_thread = std::thread::spawn(move || {
            let exit = session.finish_with_wait_hook(0, || {
                waiting_sender.send(()).unwrap();
            });
            exit_sender.send(exit).unwrap();
        });
        waiting_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("report coordinator entered its acknowledgment wait");
        release_sender.send(()).unwrap();

        assert_eq!(
            exit_receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
            7
        );
        assert_eq!(
            *stderr_bytes.lock().unwrap(),
            format!("{}\n", crate::localization::english::output_failure()).as_bytes()
        );
        finish_thread.join().unwrap();
    }

    #[test]
    fn dropping_session_does_not_join_a_blocked_writer() {
        let control = ReportingControl::default();
        let (stdout_sender, stdout_receiver) = mpsc::sync_channel(1);
        let (stderr_sender, stderr_receiver) = mpsc::sync_channel(1);
        let (write_started_sender, write_started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (write_finished_sender, write_finished_receiver) = mpsc::channel();
        let stdout_worker = spawn_writer(
            GatedWriter {
                started: write_started_sender,
                release: release_receiver,
                finished: write_finished_sender,
                fail_write: false,
            },
            stdout_receiver,
            control.clone(),
        );
        let stderr_worker = spawn_writer(io::sink(), stderr_receiver, control.clone()).unwrap();
        let mut session = ReportingSession {
            stdout: ReportWriter {
                sender: stdout_sender,
                control: control.clone(),
            },
            stderr: ReportWriter {
                sender: stderr_sender,
                control: control.clone(),
            },
            control,
            _workers: vec![stdout_worker.unwrap(), stderr_worker],
        };
        session.stdout.write_all(b"blocked record").unwrap();
        write_started_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("writer reached the controlled blocked checkpoint");

        let (drop_sender, drop_receiver) = mpsc::channel();
        let drop_thread = std::thread::spawn(move || {
            drop(session);
            drop_sender.send(()).unwrap();
        });
        let dropped_without_join = drop_receiver
            .recv_timeout(Duration::from_millis(500))
            .is_ok();
        let _ = release_sender.send(());
        assert!(
            dropped_without_join,
            "dropping reporting handles must not wait for blocked output"
        );
        write_finished_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("detached worker can finish after the blocked write is released");
        drop_thread.join().unwrap();
    }
}
