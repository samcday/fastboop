use notify::{RecursiveMode, Watcher};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const DEFAULT_ADDR: &str = "127.0.0.1:38080";

pub fn run() {
    let live_version = fs::read_to_string("infra/k8s/live-version.txt")
        .expect("failed to read infra/k8s/live-version.txt")
        .trim()
        .to_string();
    eprintln!("live version: {live_version}");

    let cache_dir = std::env::temp_dir().join("edge-cache");
    fs::create_dir_all(&cache_dir).expect("failed to create cache dir");

    let wasm_path = "infra/frontdoor/target/wasm32-wasip2/debug/frontdoor_edge.wasm";

    if !build() {
        eprintln!("initial build failed");
        std::process::exit(1);
    }

    let mut child = serve(
        &live_version,
        &cache_dir.to_string_lossy(),
        wasm_path,
        DEFAULT_ADDR,
    );

    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove() {
                let _ = tx.send(());
            }
        }
    })
    .expect("failed to create file watcher");

    watcher
        .watch(
            Path::new("infra/frontdoor/crates"),
            RecursiveMode::Recursive,
        )
        .expect("failed to watch infra/frontdoor/crates");

    eprintln!("watching infra/frontdoor/crates/ for changes...");

    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }

        let debounce = Duration::from_millis(300);
        let mut last_event = Instant::now();
        loop {
            match rx.recv_timeout(debounce) {
                Ok(()) => last_event = Instant::now(),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if last_event.elapsed() >= debounce {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        eprintln!("\n--- change detected, rebuilding... ---\n");

        if build() {
            eprintln!("build succeeded, restarting wasmtime...");
            let _ = child.kill();
            let _ = child.wait();
            child = serve(
                &live_version,
                &cache_dir.to_string_lossy(),
                wasm_path,
                DEFAULT_ADDR,
            );
        } else {
            eprintln!("build failed, keeping previous version running");
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

fn build() -> bool {
    eprintln!("building frontdoor-edge for wasm32-wasip2...");
    // Run from infra/frontdoor/ so rustup picks up rust-toolchain.toml
    // (which pins the channel and has the wasm32-wasip2 target).
    // When xtask itself is started via `cargo +...`, the child inherits
    // RUSTUP_TOOLCHAIN and that would bypass rust-toolchain.toml unless removed.
    let status = Command::new("cargo")
        .current_dir("infra/frontdoor")
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(["build", "--target", "wasm32-wasip2", "-p", "frontdoor-edge"])
        .status()
        .expect("failed to run cargo build");
    status.success()
}

fn serve(live_version: &str, cache_dir: &str, wasm_path: &str, addr: &str) -> Child {
    let dir_arg = format!("{cache_dir}::/cache");
    eprintln!("starting wasmtime serve on http://{addr}/");
    let mut child = Command::new("wasmtime")
        .args([
            "serve",
            "--wasi",
            "cli",
            "--wasi",
            "http",
            "--addr",
            addr,
            "--env",
            &format!("RUST_LOG={}", std::env::var("RUST_LOG").as_deref().unwrap_or("info")),
            "--env",
            &format!("LIVE_VERSION={live_version}"),
            "--env",
            "GITHUB_OWNER=samcday",
            "--env",
            "GITHUB_REPO=fastboop",
            "--env",
            "ASSET_NAME_TEMPLATE=fastboop-web-{version}.tar.gz",
            "--env",
            "MATRIX_SERVER_NAME=matrix.fastboop.win:443",
            "--env",
            "MATRIX_CLIENT_BASE_URL=https://matrix.fastboop.win",
            "--dir",
            &dir_arg,
            wasm_path,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start wasmtime serve");

    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    eprintln!("{line}");
                }
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    eprintln!("{line}");
                }
            }
        });
    }

    child
}
