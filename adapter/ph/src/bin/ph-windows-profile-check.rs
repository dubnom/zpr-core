use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os();
    let program = args
        .next()
        .unwrap_or_else(|| "ph-windows-profile-check".into());
    let Some(path) = args.next() else {
        return Err(format!(
            "usage: {} <profile.toml>",
            program.to_string_lossy()
        ));
    };
    if args.next().is_some() {
        return Err(format!(
            "usage: {} <profile.toml>",
            program.to_string_lossy()
        ));
    }

    let input = fs::read_to_string(&path)
        .map_err(|error| format!("unable to read profile file: {error}"))?;
    ph::windows_profile::parse_windows_profile(&input)
        .map_err(|error| format!("profile validation failed: {error}"))?;

    println!(
        "Profile schema is valid (version {}). This does not verify credentials, files, Wintun, host state, or runtime readiness.",
        ph::windows_profile::WINDOWS_PROFILE_VERSION
    );
    Ok(())
}
