use crate::util;
use std::ffi::OsStr;
use std::process::Command;

pub fn run() {
    let cargo = OsStr::new("cargo");

    step("rustfmt", cargo, &["fmt", "--all", "--check"]);
    step(
        "root workspace (host target)",
        cargo,
        &["check", "--workspace", "--exclude", "fastboop-web"],
    );
    step(
        "root wasm targets",
        cargo,
        &[
            "check",
            "-p",
            "fastboop-fastboot-webusb",
            "--target",
            "wasm32-unknown-unknown",
        ],
    );
    step(
        "fastboop-web wasm target",
        cargo,
        &[
            "check",
            "-p",
            "fastboop-web",
            "--target",
            "wasm32-unknown-unknown",
        ],
    );
}

fn step(label: &str, program: &OsStr, args: &[&str]) {
    eprintln!("==> {label}");
    let mut command = Command::new(program);
    command.args(args);
    let status = command
        .status()
        .unwrap_or_else(|err| panic!("failed to run {program:?}: {err}"));
    util::exit_on_failure(status);
}
