mod channels;
mod check;
mod frontdoor_dev;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("channels-fixtures") => channels::fixtures(),
        Some("check") => check::run(false),
        Some("check-local") => check::run(true),
        Some("frontdoor-dev") => frontdoor_dev::run(),
        Some(cmd) => {
            eprintln!("unknown command: {cmd}");
            std::process::exit(1);
        }
        None => {
            eprintln!("usage: cargo xtask <command>");
            eprintln!("commands: channels-fixtures, check, check-local, frontdoor-dev");
            std::process::exit(1);
        }
    }
}
