#![cfg_attr(feature = "ci", deny(warnings))]

#[cfg(not(windows))]
include!("main_unix.inc.rs");

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use clap::Parser;

    let _control = ph::main_args::Control::parse();
    eprintln!("This Windows build is compile-only; PH adapter and node startup are unsupported.");
    std::process::ExitCode::FAILURE
}
