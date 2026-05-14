use crate::util;
use std::ffi::OsStr;
use std::process::Command;

pub fn run(local: bool) {
    let cargo = if local {
        let local_cargo = std::env::current_dir()
            .expect("failed to read current directory")
            .join("tools/cargo-local.sh");
        local_cargo.into_os_string()
    } else {
        "cargo".into()
    };
    let stage0_cargo = local.then_some(cargo.as_os_str());

    step(
        "rustfmt",
        &cargo,
        stage0_cargo,
        &["fmt", "--all", "--check"],
    );
    step(
        if local {
            "root workspace (host target, local overlay)"
        } else {
            "root workspace (host target)"
        },
        &cargo,
        stage0_cargo,
        &["check", "--workspace", "--exclude", "fastboop-web"],
    );
    step(
        if local {
            "root wasm targets (local overlay)"
        } else {
            "root wasm targets"
        },
        &cargo,
        stage0_cargo,
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
        &cargo,
        stage0_cargo,
        &[
            "check",
            "-p",
            "fastboop-web",
            "--target",
            "wasm32-unknown-unknown",
        ],
    );
}

fn step(label: &str, program: &OsStr, stage0_cargo: Option<&OsStr>, args: &[&str]) {
    eprintln!("==> {label}");
    let mut command = Command::new(program);
    command.args(args);
    if let Some(stage0_cargo) = stage0_cargo {
        command.env("FASTBOOP_STAGE0_CARGO", stage0_cargo);
    }
    let status = command
        .status()
        .unwrap_or_else(|err| panic!("failed to run {program:?}: {err}"));
    util::exit_on_failure(status);
}
