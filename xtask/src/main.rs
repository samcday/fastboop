mod frontdoor_dev;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("frontdoor-dev") => frontdoor_dev::run(),
        Some(cmd) => {
            eprintln!("unknown command: {cmd}");
            std::process::exit(1);
        }
        None => {
            eprintln!("usage: cargo xtask <command>");
            eprintln!("commands: frontdoor-dev");
            std::process::exit(1);
        }
    }
}
