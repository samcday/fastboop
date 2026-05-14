use std::ffi::OsStr;
use std::process::{Command, ExitStatus};

pub fn run(program: impl AsRef<OsStr>, args: &[&str]) {
    let program = program.as_ref();
    let status = Command::new(program)
        .args(args)
        .status()
        .unwrap_or_else(|err| panic!("failed to run {program:?}: {err}"));
    exit_on_failure(status);
}

pub fn exit_on_failure(status: ExitStatus) {
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}
