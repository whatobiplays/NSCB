mod cli;
mod localization;

use nscb::Engine;
use std::process::ExitCode;

fn main() -> ExitCode {
    let engine = Engine::new();
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let code = cli::run(
        &args,
        &engine,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    ExitCode::from(code as u8)
}
