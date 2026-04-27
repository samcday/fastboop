mod channels;
mod check;
mod frontdoor_dev;
mod release;

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("bump") => release::bump(args.get(1).map(String::as_str)),
        Some("channels-fixtures") => channels::fixtures(),
        Some("channels-test") => channels::test(),
        Some("check") => check::run(false),
        Some("check-local") => check::run(true),
        Some("frontdoor-dev") => frontdoor_dev::run(),
        Some("publish-dry-run") => release::publish(false),
        Some(cmd) => {
            eprintln!("unknown command: {cmd}");
            std::process::exit(1);
        }
        None => {
            eprintln!("usage: cargo xtask <command>");
            eprintln!(
                "commands: bump, channels-fixtures, channels-test, check, check-local, frontdoor-dev, publish-dry-run"
            );
            std::process::exit(1);
        }
    }
}
