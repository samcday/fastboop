use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const DESKTOP_ID: &str = "win.fastboop.fastboop.desktop";
const ICON_ID: &str = "win.fastboop.fastboop";
const HANDLER_MIME: &str = "x-scheme-handler/fastboop";

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn install() {
    if let Err(err) = install_inner() {
        eprintln!("desktop-dev-install: {err}");
        std::process::exit(1);
    }
}

pub fn uninstall() {
    if let Err(err) = uninstall_inner() {
        eprintln!("desktop-dev-uninstall: {err}");
        std::process::exit(1);
    }
}

fn install_inner() -> Result<()> {
    let paths = DesktopDevPaths::new()?;

    build_desktop_binary(&paths.repo_root)?;

    fs::create_dir_all(&paths.apps_dir)?;
    fs::create_dir_all(&paths.icons_dir)?;
    fs::create_dir_all(&paths.fastboop_data_dir)?;

    fs::write(&paths.launcher_path, launcher_script(&paths.repo_root))?;
    make_executable(&paths.launcher_path)?;

    fs::write(
        &paths.desktop_path,
        desktop_file(&paths.launcher_path.to_string_lossy()),
    )?;
    fs::copy(
        paths.repo_root.join("assets/win.fastboop.fastboop.svg"),
        &paths.icon_path,
    )?;

    run_best_effort(
        "update-desktop-database",
        [paths.apps_dir.as_os_str()],
        "refresh desktop entry cache",
    );
    run_best_effort(
        "gtk-update-icon-cache",
        [paths.icon_theme_dir.as_os_str()],
        "refresh icon cache",
    );

    run_required(
        "xdg-mime",
        [
            OsStr::new("default"),
            OsStr::new(DESKTOP_ID),
            OsStr::new(HANDLER_MIME),
        ],
        "register fastboop:// handler",
    )?;

    eprintln!("installed desktop entry: {}", paths.desktop_path.display());
    eprintln!("installed dev launcher: {}", paths.launcher_path.display());
    eprintln!("installed icon: {}", paths.icon_path.display());

    match query_default_handler() {
        Ok(handler) if handler == DESKTOP_ID => {
            eprintln!("registered {HANDLER_MIME} -> {DESKTOP_ID}");
        }
        Ok(handler) if handler.is_empty() => {
            eprintln!("warning: no default handler reported for {HANDLER_MIME}");
        }
        Ok(handler) => {
            eprintln!("warning: {HANDLER_MIME} currently reports {handler}");
        }
        Err(err) => {
            eprintln!("warning: failed to verify handler registration: {err}");
        }
    }

    Ok(())
}

fn uninstall_inner() -> Result<()> {
    let paths = DesktopDevPaths::new()?;
    let current_handler = query_default_handler().ok();

    remove_file_if_exists(&paths.desktop_path)?;
    remove_file_if_exists(&paths.icon_path)?;
    remove_file_if_exists(&paths.launcher_path)?;
    remove_empty_dir_if_exists(&paths.fastboop_data_dir)?;

    if current_handler.as_deref() == Some(DESKTOP_ID) {
        clear_user_mimeapps_handler(&paths)?;
    }

    run_best_effort(
        "update-desktop-database",
        [paths.apps_dir.as_os_str()],
        "refresh desktop entry cache",
    );
    run_best_effort(
        "gtk-update-icon-cache",
        [paths.icon_theme_dir.as_os_str()],
        "refresh icon cache",
    );

    eprintln!("removed desktop entry: {}", paths.desktop_path.display());
    eprintln!("removed dev launcher: {}", paths.launcher_path.display());
    eprintln!("removed icon: {}", paths.icon_path.display());

    match query_default_handler() {
        Ok(handler) if handler == DESKTOP_ID => {
            eprintln!("warning: {HANDLER_MIME} still points at {DESKTOP_ID}");
        }
        Ok(handler) if handler.is_empty() => {
            eprintln!("cleared {HANDLER_MIME} default handler");
        }
        Ok(handler) => {
            eprintln!("{HANDLER_MIME} now points at {handler}");
        }
        Err(err) => {
            eprintln!("warning: failed to verify handler removal: {err}");
        }
    }

    Ok(())
}

struct DesktopDevPaths {
    repo_root: PathBuf,
    apps_dir: PathBuf,
    icon_theme_dir: PathBuf,
    icons_dir: PathBuf,
    fastboop_data_dir: PathBuf,
    desktop_path: PathBuf,
    icon_path: PathBuf,
    launcher_path: PathBuf,
    mimeapps_paths: Vec<PathBuf>,
}

impl DesktopDevPaths {
    fn new() -> Result<Self> {
        let xtask_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = xtask_dir
            .parent()
            .ok_or_else(|| error("failed to resolve repository root from xtask manifest dir"))?
            .to_path_buf();
        let home = home_dir()?;
        let data_home = env_path("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share"));
        let config_home = env_path("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
        let apps_dir = data_home.join("applications");
        let icon_theme_dir = data_home.join("icons/hicolor");
        let icons_dir = icon_theme_dir.join("scalable/apps");
        let fastboop_data_dir = data_home.join("fastboop");
        let desktop_path = apps_dir.join(DESKTOP_ID);
        let icon_path = icons_dir.join(format!("{ICON_ID}.svg"));
        let launcher_path = fastboop_data_dir.join("desktop-dev-launcher");
        let mimeapps_paths = vec![
            config_home.join("mimeapps.list"),
            data_home.join("applications/mimeapps.list"),
            data_home.join("mimeapps.list"),
        ];

        Ok(Self {
            repo_root,
            apps_dir,
            icon_theme_dir,
            icons_dir,
            fastboop_data_dir,
            desktop_path,
            icon_path,
            launcher_path,
            mimeapps_paths,
        })
    }
}

fn home_dir() -> Result<PathBuf> {
    env_path("HOME").ok_or_else(|| error("HOME is not set"))
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn build_desktop_binary(repo_root: &Path) -> Result<()> {
    eprintln!("building fastboop-desktop...");
    let status = Command::new("cargo")
        .current_dir(repo_root)
        .args(["build", "-p", "fastboop-desktop"])
        .status()
        .map_err(|err| {
            error(format!(
                "failed to run cargo build -p fastboop-desktop: {err}"
            ))
        })?;

    if !status.success() {
        return Err(error(format!(
            "cargo build -p fastboop-desktop failed with status {status}"
        )));
    }

    Ok(())
}

fn launcher_script(repo_root: &Path) -> String {
    format!(
        "#!/bin/sh\nset -eu\ncd {}\nexec cargo run -p fastboop-desktop -- \"$@\"\n",
        sh_quote(&repo_root.to_string_lossy())
    )
}

fn desktop_file(launcher_path: &str) -> String {
    format!(
        "[Desktop Entry]\n\
Type=Application\n\
Name=fastboop\n\
Comment=Ephemeral Linux boot over USB bootloaders\n\
Exec={} %u\n\
Icon={ICON_ID}\n\
Terminal=false\n\
Categories=Utility;System;\n\
Keywords=fastboot;usb;boot;linux;\n\
MimeType={HANDLER_MIME};\n",
        desktop_exec_quote(launcher_path)
    )
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn desktop_exec_quote(value: &str) -> String {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return value.to_string();
    }

    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

fn run_required<I, S>(program: &str, args: I, action: &str) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|err| error(format!("failed to run {program} to {action}: {err}")))?;

    if !status.success() {
        return Err(error(format!(
            "{program} failed to {action} with status {status}"
        )));
    }

    Ok(())
}

fn run_best_effort<I, S>(program: &str, args: I, action: &str)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    match Command::new(program).args(args).status() {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!("warning: {program} failed to {action} with status {status}"),
        Err(err) => eprintln!("warning: failed to run {program} to {action}: {err}"),
    }
}

fn query_default_handler() -> Result<String> {
    let output = Command::new("xdg-mime")
        .args(["query", "default", HANDLER_MIME])
        .output()
        .map_err(|err| {
            error(format!(
                "failed to run xdg-mime query default {HANDLER_MIME}: {err}"
            ))
        })?;

    if !output.status.success() {
        return Err(error(format!(
            "xdg-mime query default {HANDLER_MIME} failed with status {}",
            output.status
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn clear_user_mimeapps_handler(paths: &DesktopDevPaths) -> Result<()> {
    for path in &paths.mimeapps_paths {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(Box::new(err)),
        };

        let rewritten = remove_desktop_id_from_mimeapps(&contents, DESKTOP_ID, HANDLER_MIME);
        if rewritten != contents {
            fs::write(path, rewritten)?;
        }
    }

    Ok(())
}

fn remove_desktop_id_from_mimeapps(contents: &str, desktop_id: &str, mime: &str) -> String {
    let mut section = None;
    let mut output = Vec::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = Some(&trimmed[1..trimmed.len() - 1]);
            output.push(line.to_string());
            continue;
        }

        let should_rewrite = matches!(section, Some("Default Applications" | "Added Associations"))
            && line
                .split_once('=')
                .map(|(key, _)| key.trim() == mime)
                .unwrap_or(false);

        if !should_rewrite {
            output.push(line.to_string());
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            output.push(line.to_string());
            continue;
        };
        let entries = value
            .split(';')
            .filter(|entry| !entry.is_empty() && *entry != desktop_id)
            .collect::<Vec<_>>();

        if !entries.is_empty() {
            output.push(format!("{}={};", key.trim(), entries.join(";")));
        }
    }

    if contents.ends_with('\n') {
        output.join("\n") + "\n"
    } else {
        output.join("\n")
    }
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(Box::new(err)),
    }
}

fn remove_empty_dir_if_exists(path: &Path) -> Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(err) => Err(Box::new(err)),
    }
}

fn error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_file_registers_fastboop_handler_with_launcher() {
        let file = desktop_file("/home/dev/.local/share/fastboop/desktop-dev-launcher");

        assert!(file.contains("Exec=/home/dev/.local/share/fastboop/desktop-dev-launcher %u\n"));
        assert!(file.contains("Icon=win.fastboop.fastboop\n"));
        assert!(file.contains("MimeType=x-scheme-handler/fastboop;\n"));
    }

    #[test]
    fn desktop_file_quotes_launcher_paths_with_spaces() {
        let file = desktop_file("/home/dev/with space/desktop-dev-launcher");

        assert!(file.contains("Exec=\"/home/dev/with space/desktop-dev-launcher\" %u\n"));
    }

    #[test]
    fn launcher_runs_desktop_from_repo_root() {
        let script = launcher_script(Path::new("/tmp/fastboop checkout"));

        assert!(script.contains("cd '/tmp/fastboop checkout'\n"));
        assert!(script.contains("exec cargo run -p fastboop-desktop -- \"$@\"\n"));
    }

    #[test]
    fn remove_desktop_id_clears_our_only_default() {
        let contents =
            "[Default Applications]\nx-scheme-handler/fastboop=win.fastboop.fastboop.desktop;\n";

        let rewritten = remove_desktop_id_from_mimeapps(contents, DESKTOP_ID, HANDLER_MIME);

        assert_eq!(rewritten, "[Default Applications]\n");
    }

    #[test]
    fn remove_desktop_id_preserves_other_handler() {
        let contents = "[Default Applications]\nx-scheme-handler/fastboop=win.fastboop.fastboop.desktop;other.desktop;\n";

        let rewritten = remove_desktop_id_from_mimeapps(contents, DESKTOP_ID, HANDLER_MIME);

        assert_eq!(
            rewritten,
            "[Default Applications]\nx-scheme-handler/fastboop=other.desktop;\n"
        );
    }

    #[test]
    fn remove_desktop_id_preserves_unrelated_entries() {
        let contents = "[Added Associations]\ntext/plain=editor.desktop;\nx-scheme-handler/fastboop=other.desktop;win.fastboop.fastboop.desktop;\n";

        let rewritten = remove_desktop_id_from_mimeapps(contents, DESKTOP_ID, HANDLER_MIME);

        assert_eq!(
            rewritten,
            "[Added Associations]\ntext/plain=editor.desktop;\nx-scheme-handler/fastboop=other.desktop;\n"
        );
    }
}
