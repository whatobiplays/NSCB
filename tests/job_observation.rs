#![cfg(target_os = "macos")]

//! Public observation, cancellation, and authoritative-completion contracts for
//! host-owned copy-through executions.

use nscb::{
    CancellationHandle, CopyThroughRequest, DestinationBaseline, Engine, JobState,
    OperationArtifactRole, OperationEvent, OperationEventConsumer, OperationEventKind,
    OperationFailureCode, OperationOutcome, OperationPlan, OperationSession,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

fn fixture() -> (TempDir, PathBuf, PathBuf, PathBuf) {
    let root = tempfile::tempdir().expect("create observation fixture");
    let source = root.path().join("source.bin");
    let destination = root.path().join("destination.bin");
    let workspace = root.path().join("workspace");
    fs::write(&source, b"observation fixture source bytes").expect("write source");
    fs::create_dir(&workspace).expect("create workspace");
    (root, source, destination, workspace)
}

fn make_plan(source: &Path, destination: &Path, workspace: &Path) -> OperationPlan {
    Engine::new()
        .plan_copy_through(CopyThroughRequest::new(source, destination, workspace))
        .expect("create copy-through plan")
}

fn drain(consumer: &OperationEventConsumer) -> Vec<OperationEvent> {
    let mut events = Vec::new();
    while let Ok(event) = consumer.recv_timeout(Duration::from_millis(250)) {
        events.push(event);
    }
    events
}

fn terminal_count(events: &[OperationEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event.event(), OperationEventKind::Completed { .. }))
        .count()
}

#[test]
fn terminal_result_is_recoverable_after_the_consumer_is_dropped() {
    let (_root, source, destination, workspace) = fixture();
    let plan = make_plan(&source, &destination, &workspace);
    let session = OperationSession::new();
    let consumer = session.subscribe_events().expect("claim event consumer");
    drop(consumer);

    let result = Engine::new().execute_operation(plan, &session);

    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(result.outcome(), Some(OperationOutcome::Copied));
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
    assert_eq!(
        session.last_result().expect("read terminal result"),
        Some(result.clone())
    );
    let completion = session
        .last_completion()
        .expect("read terminal completion")
        .expect("completion survives a dropped consumer");
    assert_eq!(completion.result().state(), JobState::Succeeded);
    assert_eq!(
        completion.result().outcome(),
        Some(OperationOutcome::Copied)
    );
    assert_eq!(
        completion.snapshot().status(),
        nscb::OperationSessionStatus::Succeeded
    );
    assert_eq!(
        completion.snapshot().phase(),
        nscb::OperationSessionPhase::Idle
    );
    assert_eq!(
        completion.snapshot().completed_bytes(),
        fs::metadata(&source).unwrap().len()
    );
    assert_eq!(completion.sequence(), result.milestones().len() as u64 + 1);
}

#[test]
fn second_consumer_is_refused_until_the_first_is_dropped() {
    let session = OperationSession::new();
    let first = session.subscribe_events().expect("first consumer");
    assert_eq!(
        session.subscribe_events().unwrap_err(),
        OperationFailureCode::EventConsumerUnavailable
    );
    drop(first);
    let _second = session
        .subscribe_events()
        .expect("released consumer can be reclaimed");
}

#[test]
fn events_are_ordered_bounded_and_have_one_terminal_completion() {
    let (root, source, destination, workspace) = fixture();
    let plan = make_plan(&source, &destination, &workspace);
    let session = OperationSession::new();
    let consumer = session.subscribe_events().expect("claim event consumer");

    let result = Engine::new().execute_operation(plan, &session);
    let events = drain(&consumer);

    assert_eq!(result.state(), JobState::Succeeded);
    assert!(events.len() <= 16, "bounded event cardinality: {events:?}");
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.sequence(), index as u64);
    }
    assert!(matches!(
        events.first().map(OperationEvent::event),
        Some(OperationEventKind::Started { total_bytes }) if *total_bytes == fs::metadata(&source).unwrap().len()
    ));
    assert_eq!(terminal_count(&events), 1);
    assert!(matches!(
        events.last().map(OperationEvent::event),
        Some(OperationEventKind::Completed { result: terminal }) if terminal == &result
    ));
    for event in &events {
        assert_eq!(
            event.snapshot().completed_bytes(),
            serde_json::to_value(event).unwrap()["snapshot"]["completed_bytes"]
                .as_u64()
                .expect("serialized event has the same progress snapshot")
        );
    }
    let terminal = events.last().unwrap();
    assert_eq!(
        terminal.snapshot().phase(),
        nscb::OperationSessionPhase::Idle
    );
    assert_eq!(
        terminal.snapshot().status(),
        nscb::OperationSessionStatus::Succeeded
    );
    assert_eq!(
        terminal.snapshot().outcome(),
        Some(OperationOutcome::Copied)
    );
    assert_eq!(
        terminal.snapshot().completed_bytes(),
        fs::metadata(&source).unwrap().len()
    );
    let completion = session.last_completion().unwrap().unwrap();
    assert_eq!(completion.sequence(), terminal.sequence());
    assert_eq!(completion.snapshot(), terminal.snapshot());
    assert_eq!(completion.result(), &result);

    // Nonterminal semantic events never carry artifact, source, destination, or
    // workspace paths. Reconciliation data lives only in the terminal result.
    for event in &events[..events.len() - 1] {
        let serialized = serde_json::to_string(event).expect("serialize event");
        for path in [
            root.path(),
            source.as_path(),
            destination.as_path(),
            workspace.as_path(),
        ] {
            assert!(
                !serialized.contains(&path.display().to_string()),
                "nonterminal event leaked a path: {serialized}"
            );
        }
    }
}

#[test]
fn repeated_admissions_replace_the_terminal_result_and_reset_sequences() {
    let (_root, source, destination, workspace) = fixture();
    let second_destination = workspace.join("second-destination.bin");
    let session = OperationSession::new();

    let first_plan = make_plan(&source, &destination, &workspace);
    let first = Engine::new().execute_operation(first_plan, &session);
    assert_eq!(
        session.last_result().expect("first terminal"),
        Some(first.clone())
    );

    let consumer = session.subscribe_events().expect("second consumer");
    let second_plan = make_plan(&source, &second_destination, &workspace);
    let second = Engine::new().execute_operation(second_plan, &session);
    let events = drain(&consumer);

    assert_eq!(second.state(), JobState::Succeeded);
    assert_ne!(first, second);
    assert_eq!(events.first().map(OperationEvent::sequence), Some(0));
    assert_eq!(terminal_count(&events), 1);
    assert_eq!(
        session.last_result().expect("second terminal"),
        Some(second)
    );
}

#[test]
fn pre_admission_cancellation_binds_to_the_invocation() {
    let (_root, source, destination, workspace) = fixture();
    let plan = make_plan(&source, &destination, &workspace);
    let session = OperationSession::new();
    let cancellation = CancellationHandle::new();
    cancellation.cancel();

    let result = Engine::new().execute_operation_with_cancellation(plan, &session, cancellation);

    assert_eq!(result.state(), JobState::Cancelled);
    assert_eq!(
        result.failure().map(|failure| failure.code()),
        Some(OperationFailureCode::Cancelled)
    );
    assert!(
        !destination.exists(),
        "cancelled execution publishes nothing"
    );
    assert_eq!(
        fs::read(&source).unwrap(),
        b"observation fixture source bytes"
    );
    assert!(matches!(
        session.current_operation().expect("snapshot"),
        snapshot if snapshot.completed_bytes() == 0 && snapshot.total_bytes() == Some(fs::metadata(&source).unwrap().len())
    ));
    assert_eq!(
        session.last_result().expect("terminal cancelled result"),
        Some(result)
    );

    // A later unrelated execution on the same session is not cancelled by the
    // earlier request because cancellation is bound to its invocation.
    let later_plan = make_plan(&source, &destination, &workspace);
    let later = Engine::new().execute_operation_with_cancellation(
        later_plan,
        &session,
        CancellationHandle::new(),
    );
    assert_eq!(later.state(), JobState::Succeeded);
    assert_eq!(fs::read(&destination).unwrap(), fs::read(&source).unwrap());
}

#[test]
fn failed_planning_cannot_cancel_a_later_execution() {
    let (_root, source, destination, workspace) = fixture();
    let missing = workspace.join("missing-source.bin");
    let cancelled = CancellationHandle::new();
    cancelled.cancel();

    let planning_error = Engine::new()
        .plan_copy_through(CopyThroughRequest::new(&missing, &destination, &workspace))
        .err()
        .expect("missing source must fail planning");
    assert_eq!(
        planning_error.code(),
        OperationFailureCode::SourceUnavailable
    );

    let session = OperationSession::new();
    drop(cancelled);
    assert_eq!(
        session.current_operation().expect("idle snapshot").phase(),
        nscb::OperationSessionPhase::Idle
    );
    assert_eq!(session.last_result().expect("no terminal result"), None);
    assert!(!destination.exists());

    let plan = make_plan(&source, &destination, &workspace);
    let result = Engine::new().execute_operation_with_cancellation(
        plan,
        &session,
        CancellationHandle::new(),
    );
    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(session.last_result().expect("terminal"), Some(result));
}

#[test]
fn already_up_to_date_reports_zero_completed_bytes_and_the_planned_total() {
    let (_root, source, destination, workspace) = fixture();
    fs::copy(&source, &destination).expect("seed identical destination");
    let plan = make_plan(&source, &destination, &workspace);
    let session = OperationSession::new();

    let result = Engine::new().execute_operation(plan, &session);

    assert_eq!(result.state(), JobState::Succeeded);
    assert_eq!(result.outcome(), Some(OperationOutcome::AlreadyUpToDate));
    let snapshot = session.current_operation().expect("snapshot");
    assert_eq!(snapshot.completed_bytes(), 0);
    assert_eq!(
        snapshot.total_bytes(),
        Some(fs::metadata(&source).unwrap().len())
    );
}

#[test]
fn terminal_result_carries_actionable_artifact_identity() {
    let (_root, source, destination, workspace) = fixture();
    let plan = make_plan(&source, &destination, &workspace);
    let baseline = plan.snapshot().destination_baseline().clone();
    let session = OperationSession::new();

    let result = Engine::new().execute_operation(plan, &session);

    assert_eq!(result.state(), JobState::Succeeded);
    let published = result
        .artifacts()
        .iter()
        .find(|artifact| artifact.role() == OperationArtifactRole::PublishedDestination)
        .expect("published destination artifact");
    assert_eq!(
        published.path(),
        fs::canonicalize(&destination).unwrap().as_path()
    );
    assert_eq!(published.path_identity_matches(), Some(true));
    assert_eq!(
        published.length(),
        Some(fs::metadata(&source).unwrap().len())
    );

    let document = serde_json::to_value(&result).expect("serialize terminal result");
    let path = destination.display().to_string();
    assert!(
        document.to_string().contains(&path),
        "terminal result must carry reconciliation paths"
    );
    assert!(matches!(baseline, DestinationBaseline::Absent));
}
