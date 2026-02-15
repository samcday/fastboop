#[cfg(feature = "native-serial")]
use std::sync::Arc;

use vt100::{Cell, Color, Parser};

pub const DEFAULT_TERMINAL_ROWS: u16 = 240;
pub const DEFAULT_TERMINAL_COLS: u16 = 160;
pub const DEFAULT_SCROLLBACK: usize = 8_192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TerminalColor {
    #[default]
    Default,
    Rgb(u8, u8, u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TerminalStyle {
    pub fg: TerminalColor,
    pub bg: TerminalColor,
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    pub inverse: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalSpan {
    pub text: String,
    pub style: TerminalStyle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalRow {
    pub spans: Vec<TerminalSpan>,
}

pub struct SerialTerminal {
    parser: Parser,
    scrollback: usize,
}

impl Default for SerialTerminal {
    fn default() -> Self {
        Self::new(
            DEFAULT_TERMINAL_ROWS,
            DEFAULT_TERMINAL_COLS,
            DEFAULT_SCROLLBACK,
        )
    }
}

impl SerialTerminal {
    #[must_use]
    pub fn new(rows: u16, cols: u16, scrollback: usize) -> Self {
        Self {
            parser: Parser::new(rows.max(1), cols.max(1), scrollback),
            scrollback,
        }
    }

    pub fn clear(&mut self) {
        let (rows, cols) = self.parser.screen().size();
        self.parser = Parser::new(rows.max(1), cols.max(1), self.scrollback);
    }

    pub fn process(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    pub fn process_text(&mut self, text: &str) {
        self.process(text.as_bytes());
    }

    pub fn set_size(&mut self, rows: u16, cols: u16) {
        self.parser.screen_mut().set_size(rows.max(1), cols.max(1));
    }

    #[must_use]
    pub fn plain_text(&self) -> String {
        self.parser.screen().contents()
    }

    #[must_use]
    pub fn styled_rows(&self, max_rows: usize) -> Vec<TerminalRow> {
        let screen = self.parser.screen();
        let (rows, cols) = screen.size();
        let rows_to_take = max_rows.min(rows as usize) as u16;
        let start_row = rows.saturating_sub(rows_to_take);

        let mut rendered = Vec::with_capacity(rows_to_take as usize);
        for row in start_row..rows {
            let mut spans: Vec<TerminalSpan> = Vec::new();

            for col in 0..cols {
                let Some(cell) = screen.cell(row, col) else {
                    continue;
                };
                if cell.is_wide_continuation() {
                    continue;
                }

                let style = cell_style(cell);
                let text = if cell.has_contents() {
                    cell.contents().to_string()
                } else {
                    " ".to_string()
                };

                if let Some(last) = spans.last_mut()
                    && last.style == style
                {
                    last.text.push_str(&text);
                } else {
                    spans.push(TerminalSpan { text, style });
                }
            }

            trim_trailing_blank_cells(&mut spans);
            rendered.push(TerminalRow { spans });
        }

        rendered
    }
}

#[derive(Default)]
pub struct SerialLineAccumulator {
    pending: String,
}

impl SerialLineAccumulator {
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Vec<String> {
        let text = String::from_utf8_lossy(bytes);
        self.push_text(&text)
    }

    pub fn push_text(&mut self, text: &str) -> Vec<String> {
        let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
        self.pending.push_str(&normalized);

        let mut lines = Vec::new();
        while let Some(newline) = self.pending.find('\n') {
            let mut line = self.pending.drain(..=newline).collect::<String>();
            if line.ends_with('\n') {
                line.pop();
            }
            lines.push(line);
        }
        lines
    }

    #[must_use]
    pub fn take_pending(&mut self) -> Option<String> {
        if self.pending.is_empty() {
            return None;
        }
        Some(std::mem::take(&mut self.pending))
    }
}

#[must_use]
pub fn strip_ansi(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut out = String::with_capacity(input.len());

    while i < bytes.len() {
        if bytes[i] == 0x1B {
            i += 1;
            if i >= bytes.len() {
                break;
            }
            match bytes[i] {
                b'[' => {
                    i += 1;
                    while i < bytes.len() {
                        let b = bytes[i];
                        i += 1;
                        if (0x40..=0x7E).contains(&b) {
                            break;
                        }
                    }
                }
                b']' => {
                    i += 1;
                    while i < bytes.len() {
                        let b = bytes[i];
                        if b == 0x07 {
                            i += 1;
                            break;
                        }
                        if b == 0x1B && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                }
                _ => {
                    i += 1;
                }
            }
            continue;
        }

        let ch = input[i..]
            .chars()
            .next()
            .expect("index is always at a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn trim_trailing_blank_cells(spans: &mut Vec<TerminalSpan>) {
    while let Some(last) = spans.last_mut() {
        let trimmed_len = last.text.trim_end_matches(' ').len();
        if trimmed_len == last.text.len() {
            break;
        }
        if trimmed_len == 0 {
            let _ = spans.pop();
        } else {
            last.text.truncate(trimmed_len);
            break;
        }
    }
}

fn cell_style(cell: &Cell) -> TerminalStyle {
    TerminalStyle {
        fg: color_to_terminal(cell.fgcolor()),
        bg: color_to_terminal(cell.bgcolor()),
        bold: cell.bold(),
        dim: cell.dim(),
        italic: cell.italic(),
        underline: cell.underline(),
        inverse: cell.inverse(),
    }
}

fn color_to_terminal(color: Color) -> TerminalColor {
    match color {
        Color::Default => TerminalColor::Default,
        Color::Idx(index) => {
            let (r, g, b) = ansi_index_to_rgb(index);
            TerminalColor::Rgb(r, g, b)
        }
        Color::Rgb(r, g, b) => TerminalColor::Rgb(r, g, b),
    }
}

fn ansi_index_to_rgb(index: u8) -> (u8, u8, u8) {
    match index {
        0 => (0x00, 0x00, 0x00),
        1 => (0xCD, 0x00, 0x00),
        2 => (0x00, 0xCD, 0x00),
        3 => (0xCD, 0xCD, 0x00),
        4 => (0x00, 0x00, 0xEE),
        5 => (0xCD, 0x00, 0xCD),
        6 => (0x00, 0xCD, 0xCD),
        7 => (0xE5, 0xE5, 0xE5),
        8 => (0x7F, 0x7F, 0x7F),
        9 => (0xFF, 0x00, 0x00),
        10 => (0x00, 0xFF, 0x00),
        11 => (0xFF, 0xFF, 0x00),
        12 => (0x5C, 0x5C, 0xFF),
        13 => (0xFF, 0x00, 0xFF),
        14 => (0x00, 0xFF, 0xFF),
        15 => (0xFF, 0xFF, 0xFF),
        16..=231 => {
            let idx = index - 16;
            let r = idx / 36;
            let g = (idx % 36) / 6;
            let b = idx % 6;
            (cube_component(r), cube_component(g), cube_component(b))
        }
        232..=255 => {
            let shade = 8 + (index - 232) * 10;
            (shade, shade, shade)
        }
    }
}

fn cube_component(component: u8) -> u8 {
    match component {
        0 => 0,
        1 => 95,
        2 => 135,
        3 => 175,
        4 => 215,
        _ => 255,
    }
}

#[cfg(feature = "native-serial")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSerialSelector {
    pub vid: u16,
    pub pid: u16,
    pub serial: Option<String>,
    pub baud_rate: u32,
    pub poll_interval: std::time::Duration,
    pub read_timeout: std::time::Duration,
}

#[cfg(feature = "native-serial")]
impl NativeSerialSelector {
    #[must_use]
    pub fn new(vid: u16, pid: u16, serial: Option<String>) -> Self {
        Self {
            vid,
            pid,
            serial,
            baud_rate: 115_200,
            poll_interval: std::time::Duration::from_millis(500),
            read_timeout: std::time::Duration::from_millis(200),
        }
    }
}

#[cfg(feature = "native-serial")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeSerialEvent {
    Status(String),
    Connected { port: String },
    Disconnected { port: String },
    Error(String),
    Bytes(Vec<u8>),
}

#[cfg(feature = "native-serial")]
pub fn spawn_native_serial_reader<F>(
    selector: NativeSerialSelector,
    mut on_event: F,
) -> Arc<std::sync::atomic::AtomicBool>
where
    F: FnMut(NativeSerialEvent) + Send + 'static,
{
    use std::io::{ErrorKind, Read as _};
    use std::sync::atomic::{AtomicBool, Ordering};

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);

    let thread = std::thread::Builder::new()
        .name(format!(
            "fastboop-serial-{:04x}:{:04x}",
            selector.vid, selector.pid
        ))
        .spawn(move || {
            on_event(NativeSerialEvent::Status(format!(
                "waiting for CDC-ACM gadget {:04x}:{:04x}",
                selector.vid, selector.pid
            )));

            while !stop_thread.load(Ordering::Relaxed) {
                let port_path = match matching_port_path(&selector) {
                    Ok(Some(port_path)) => port_path,
                    Ok(None) => {
                        std::thread::sleep(selector.poll_interval);
                        continue;
                    }
                    Err(err) => {
                        on_event(NativeSerialEvent::Error(err));
                        std::thread::sleep(selector.poll_interval);
                        continue;
                    }
                };

                let mut port = match open_tty_nonblocking(&port_path) {
                    Ok(port) => port,
                    Err(err) => {
                        on_event(NativeSerialEvent::Error(format!(
                            "failed to open serial port {port_path}: {err}"
                        )));
                        std::thread::sleep(selector.poll_interval);
                        continue;
                    }
                };

                on_event(NativeSerialEvent::Connected {
                    port: port_path.clone(),
                });

                let mut buffer = [0u8; 4096];
                loop {
                    if stop_thread.load(Ordering::Relaxed) {
                        break;
                    }

                    match port.read(&mut buffer) {
                        Ok(0) => {
                            std::thread::sleep(selector.read_timeout);
                        }
                        Ok(n) => {
                            on_event(NativeSerialEvent::Bytes(buffer[..n].to_vec()));
                        }
                        Err(err)
                            if matches!(
                                err.kind(),
                                ErrorKind::WouldBlock | ErrorKind::Interrupted
                            ) =>
                        {
                            std::thread::sleep(selector.read_timeout);
                        }
                        Err(err) => {
                            on_event(NativeSerialEvent::Error(format!(
                                "serial read failed on {port_path}: {err}"
                            )));
                            break;
                        }
                    }
                }

                on_event(NativeSerialEvent::Disconnected { port: port_path });
                std::thread::sleep(selector.poll_interval);
            }
        });

    if let Err(err) = thread {
        stop.store(true, Ordering::Relaxed);
        let _ = err;
    }

    stop
}

#[cfg(feature = "native-serial")]
fn matching_port_path(selector: &NativeSerialSelector) -> Result<Option<String>, String> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        use std::path::Path;

        let mut matches = Vec::new();
        let entries = fs::read_dir("/sys/class/tty")
            .map_err(|err| format!("read /sys/class/tty failed: {err}"))?;

        for entry in entries {
            let entry = entry.map_err(|err| format!("read tty entry failed: {err}"))?;
            let tty_name = entry.file_name().to_string_lossy().to_string();
            if !tty_name.starts_with("ttyACM") {
                continue;
            }

            let tty_path = fs::canonicalize(entry.path())
                .map_err(|err| format!("canonicalize tty path failed: {err}"))?;
            let Some(identity) = usb_identity_for_tty_path(&tty_path) else {
                continue;
            };

            if identity.0 != selector.vid || identity.1 != selector.pid {
                continue;
            }

            if let Some(expected_serial) = selector.serial.as_deref()
                && identity.2.as_deref().map(str::trim) != Some(expected_serial.trim())
            {
                continue;
            }

            matches.push(Path::new("/dev").join(tty_name));
        }

        matches.sort();
        Ok(matches
            .into_iter()
            .next()
            .map(|path| path.to_string_lossy().to_string()))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = selector;
        Err("native serial reader is only implemented for Linux hosts".to_string())
    }
}

#[cfg(all(feature = "native-serial", target_os = "linux"))]
fn usb_identity_for_tty_path(path: &std::path::Path) -> Option<(u16, u16, Option<String>)> {
    for ancestor in path.ancestors() {
        let vendor_path = ancestor.join("idVendor");
        let product_path = ancestor.join("idProduct");
        if !vendor_path.exists() || !product_path.exists() {
            continue;
        }

        let vid = read_hex_u16(&vendor_path)?;
        let pid = read_hex_u16(&product_path)?;
        let serial = std::fs::read_to_string(ancestor.join("serial"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        return Some((vid, pid, serial));
    }
    None
}

#[cfg(all(feature = "native-serial", target_os = "linux"))]
fn read_hex_u16(path: &std::path::Path) -> Option<u16> {
    let text = std::fs::read_to_string(path).ok()?;
    let trimmed = text.trim();
    let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    u16::from_str_radix(trimmed, 16).ok()
}

#[cfg(all(feature = "native-serial", target_family = "unix"))]
fn open_tty_nonblocking(path: &str) -> std::io::Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

#[cfg(all(feature = "native-serial", not(target_family = "unix")))]
fn open_tty_nonblocking(path: &str) -> std::io::Result<std::fs::File> {
    let _ = path;
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "native serial reader requires a Unix-like host",
    ))
}

#[cfg(test)]
mod tests {
    use super::{SerialLineAccumulator, strip_ansi};

    #[test]
    fn strip_ansi_handles_csi_sequences() {
        let input = "foo \u{1b}[31mred\u{1b}[0m bar";
        assert_eq!(strip_ansi(input), "foo red bar");
    }

    #[test]
    fn strip_ansi_handles_osc_sequences() {
        let input = "\u{1b}]0;title\u{7}hello";
        assert_eq!(strip_ansi(input), "hello");
    }

    #[test]
    fn line_accumulator_splits_newlines_and_carriage_returns() {
        let mut lines = SerialLineAccumulator::default();
        assert_eq!(lines.push_text("one\rtwo\nthree"), vec!["one", "two"]);
        assert_eq!(lines.take_pending(), Some("three".to_string()));
    }
}
