use std::process::{Command, ExitStatus};

pub fn fixtures() {
    run("tools/channels/generate-fixtures.sh", &[]);
}

fn run(program: &str, args: &[&str]) {
    let status = Command::new(program)
        .args(args)
        .status()
        .unwrap_or_else(|err| panic!("failed to run {program}: {err}"));
    exit_on_failure(status);
}

fn exit_on_failure(status: ExitStatus) {
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}
