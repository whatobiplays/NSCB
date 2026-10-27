mod cli;
#[cfg(target_os = "macos")]
mod cli_reporting;
mod localization;

use nscb::Engine;
use std::process::ExitCode;

fn main() -> ExitCode {
    let engine = Engine::new();
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    #[cfg(target_os = "macos")]
    if cli::is_copy_command(&args) {
        let mut reporting = cli_reporting::ReportingSession::new()
            .unwrap_or_else(|_| cli_reporting::ReportingSession::unavailable());
        let operation_exit = cli::run_with_reporting(&args, &engine, &mut reporting);
        return ExitCode::from(reporting.finish(operation_exit) as u8);
    }
    let code = cli::run(
        &args,
        &engine,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    ExitCode::from(code as u8)
}
