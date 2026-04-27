use std::process::{Command, ExitStatus};

pub fn run(local: bool) {
    let cargo = if local {
        let local_cargo = std::env::current_dir()
            .expect("failed to read current directory")
            .join("tools/cargo-local.sh");
        std::env::set_var("FASTBOOP_STAGE0_CARGO", &local_cargo);
        local_cargo.into_os_string()
    } else {
        "cargo".into()
    };

    step("rustfmt", &cargo, &["fmt", "--all", "--check"]);
    step(
        if local {
            "root workspace (host target, local overlay)"
        } else {
            "root workspace (host target)"
        },
        &cargo,
        &["check", "--workspace", "--exclude", "fastboop-web"],
    );
    step(
        if local {
            "root wasm targets (local overlay)"
        } else {
            "root wasm targets"
        },
        &cargo,
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
        &[
            "check",
            "-p",
            "fastboop-web",
            "--target",
            "wasm32-unknown-unknown",
        ],
    );
}

fn step(label: &str, program: &std::ffi::OsStr, args: &[&str]) {
    eprintln!("==> {label}");
    let status = Command::new(program)
        .args(args)
        .status()
        .unwrap_or_else(|err| panic!("failed to run {program:?}: {err}"));
    exit_on_failure(status);
}

fn exit_on_failure(status: ExitStatus) {
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}
