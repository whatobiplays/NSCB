mod cli;
#[cfg(target_os = "macos")]
mod cli_reporting;
#[path = "key_file.rs"]
mod key_file;
mod localization;
mod standalone;

use nscb::Engine;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(code) = standalone::run_global_information(&args) {
        return ExitCode::from(code as u8);
    }
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    if let Some(code) = standalone::run_pre_engine_command(&args, &mut stdout, &mut stderr) {
        return ExitCode::from(code as u8);
    }
    let standalone_config = match standalone::StandaloneConfig::load_or_initialize() {
        Ok(config) => config,
        Err(error) => {
            return ExitCode::from(standalone::emit_startup_error(
                &args,
                error,
                &mut stdout,
                &mut stderr,
            ) as u8);
        }
    };
    drop(stdout);
    drop(stderr);
    let engine = Engine::new();
    #[cfg(target_os = "macos")]
    if cli::requires_reporting_session(&args) {
        let mut reporting = cli_reporting::ReportingSession::new()
            .unwrap_or_else(|_| cli_reporting::ReportingSession::unavailable());
        let operation_exit = cli::run_with_reporting_and_standalone_config(
            &args,
            &engine,
            &standalone_config,
            &mut reporting,
        );
        return ExitCode::from(reporting.finish(operation_exit) as u8);
    }
    let code = cli::run_with_standalone_config(
        &args,
        &engine,
        &standalone_config,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    ExitCode::from(code as u8)
}
