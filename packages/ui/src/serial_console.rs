use dioxus::prelude::*;
use fastboop_serial::{SerialTerminal, TerminalColor, TerminalRow, TerminalStyle};

pub const SERIAL_LOG_ROWS: u16 = 420;
pub const SERIAL_LOG_COLS: u16 = 180;
pub const SERIAL_LOG_SCROLLBACK: usize = 8_192;

pub struct SerialLogBuffer {
    terminal: SerialTerminal,
    render_rows: usize,
}

impl Default for SerialLogBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialLogBuffer {
    #[must_use]
    pub fn new() -> Self {
        Self::with_dimensions(SERIAL_LOG_ROWS, SERIAL_LOG_COLS, SERIAL_LOG_SCROLLBACK)
    }

    #[must_use]
    pub fn with_dimensions(rows: u16, cols: u16, scrollback: usize) -> Self {
        Self {
            terminal: SerialTerminal::new(rows, cols, scrollback),
            render_rows: rows as usize,
        }
    }

    pub fn clear(&mut self) {
        self.terminal.clear();
    }

    pub fn push_status(&mut self, message: impl AsRef<str>) {
        let status_line = format!("\x1b[38;5;245m[host]\x1b[0m {}\r\n", message.as_ref());
        self.push_bytes(status_line.as_bytes());
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.terminal.process(bytes);
    }

    #[must_use]
    pub fn render_rows(&self) -> Vec<TerminalRow> {
        self.terminal.styled_rows(self.render_rows)
    }
}

#[component]
pub fn SerialLogOutput(rows: Vec<TerminalRow>) -> Element {
    rsx! {
        div { class: "serial-logs__output",
            for (row_index, row) in rows.iter().enumerate() {
                div { class: "serial-logs__row", key: "row-{row_index}",
                    for (span_index, span) in row.spans.iter().enumerate() {
                        span {
                            key: "span-{row_index}-{span_index}",
                            style: "{terminal_span_style(&span.style)}",
                            "{span.text}"
                        }
                    }
                }
            }
        }
    }
}

#[must_use]
pub fn terminal_span_style(style: &TerminalStyle) -> String {
    let (fg, bg) = if style.inverse {
        (style.bg, style.fg)
    } else {
        (style.fg, style.bg)
    };
    let mut css = String::new();

    if let Some((r, g, b)) = terminal_color_rgb(fg) {
        css.push_str(format!("color: rgb({r} {g} {b});").as_str());
    }
    if let Some((r, g, b)) = terminal_color_rgb(bg) {
        css.push_str(format!("background-color: rgb({r} {g} {b});").as_str());
    }
    if style.bold {
        css.push_str("font-weight: 700;");
    }
    if style.dim {
        css.push_str("opacity: 0.8;");
    }
    if style.italic {
        css.push_str("font-style: italic;");
    }
    if style.underline {
        css.push_str("text-decoration: underline;");
    }
    css
}

fn terminal_color_rgb(color: TerminalColor) -> Option<(u8, u8, u8)> {
    match color {
        TerminalColor::Default => None,
        TerminalColor::Rgb(r, g, b) => Some((r, g, b)),
    }
}
