use std::collections::VecDeque;
use std::io;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use fastboop_serial::{SerialTerminal, TerminalColor, TerminalStyle};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline};
use ratatui::{Frame, Terminal};

use crate::boot_ui::{BootEvent, BootPhase, timestamp_hms};

const TICK: Duration = Duration::from_millis(100);
const HISTORY: usize = 120;
const LOG_LIMIT: usize = 5000;

pub enum TuiOutcome {
    Completed,
    Quit,
}

pub fn run_boot_tui(rx: &Receiver<BootEvent>) -> Result<TuiOutcome> {
    let mut stdout = io::stdout();
    enable_raw_mode().context("enable raw mode")?;
    execute!(stdout, EnterAlternateScreen).context("enter alternate screen")?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout)).context("create terminal")?;
    let guard = TerminalGuard::new();

    let mut state = TuiState::default();
    loop {
        let mut updated = false;
        loop {
            match rx.try_recv() {
                Ok(event) => {
                    state.handle_event(event);
                    updated = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    state.done = true;
                    break;
                }
            }
        }

        let size = terminal.size().context("read terminal size")?;
        let area = ratatui::layout::Rect::new(0, 0, size.width, size.height);
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(20),
                Constraint::Percentage(40),
                Constraint::Percentage(40),
            ])
            .split(area);
        let visible_logs = rows[2].height.saturating_sub(2) as usize;
        state.page_step = (visible_logs.max(1) / 2).max(1) as u16;
        state.clamp_scroll(visible_logs);

        terminal
            .draw(|f| draw(f, &state))
            .context("draw TUI frame")?;

        if state.done && !updated {
            drop(guard);
            return Ok(TuiOutcome::Completed);
        }

        if event::poll(TICK).context("poll terminal input")?
            && let Event::Key(key) = event::read().context("read terminal input")?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('p') => {
                    state.paused = !state.paused;
                    if !state.paused {
                        state.scroll = u16::MAX;
                    }
                }
                KeyCode::Up => {
                    state.paused = true;
                    state.scroll = state.scroll.saturating_sub(1);
                }
                KeyCode::Down => {
                    state.paused = true;
                    state.scroll = state.scroll.saturating_add(1);
                }
                KeyCode::PageUp => {
                    state.paused = true;
                    state.scroll = state.scroll.saturating_sub(state.page_step);
                }
                KeyCode::PageDown => {
                    state.paused = true;
                    state.scroll = state.scroll.saturating_add(state.page_step);
                }
                KeyCode::Char('q') => {
                    drop(guard);
                    return Ok(TuiOutcome::Quit);
                }
                _ => {}
            }
        }
    }
}

fn draw(frame: &mut Frame<'_>, state: &TuiState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(40),
            Constraint::Percentage(40),
        ])
        .split(frame.area());
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(rows[0]);
    let top_right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(top[1]);

    let boot_lines = vec![
        Line::from(vec![
            Span::styled(
                format!("phase: {}", state.phase.label()),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                state.phase_detail.as_str(),
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            Span::raw("keys: "),
            Span::styled("p", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" pause/resume  "),
            Span::styled(
                "up/down/pgup/pgdn",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(" scroll  "),
            Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" quit"),
        ]),
    ];
    let boot = Paragraph::new(boot_lines)
        .block(Block::default().title("Boot State").borders(Borders::ALL));
    frame.render_widget(boot, top[0]);

    draw_smoo_panel(frame, top_right[0], state);
    draw_gibblox_panel(frame, top_right[1], state);

    draw_serial_panel(frame, rows[1], state);

    let log_title = if state.paused {
        format!("Logs [paused, scroll={}]", state.scroll)
    } else {
        "Logs [live]".to_string()
    };
    let logs = Paragraph::new(state.logs.join("\n"))
        .block(Block::default().title(log_title).borders(Borders::ALL))
        .scroll((state.scroll, 0));
    frame.render_widget(logs, rows[2]);
}

fn draw_smoo_panel(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &TuiState) {
    let block = Block::default().title("Smoo").borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(inner);

    let trend = trend_symbol(&state.smoo_history);
    let status = if state.smoo_active { "UP" } else { "DOWN" };
    let color = if state.smoo_active {
        Color::Green
    } else {
        Color::Red
    };
    let header = Line::from(vec![
        Span::styled(format!("{status} {trend}"), Style::default().fg(color)),
        Span::raw("  "),
        Span::styled(
            format!(
                "exports={} sid={}",
                state.smoo_export_count, state.smoo_session_id
            ),
            Style::default().fg(Color::Gray),
        ),
    ]);
    let header_widget = Paragraph::new(header);
    frame.render_widget(header_widget, rows[0]);

    let data: Vec<u64> = state.smoo_history.iter().copied().collect();
    let sparkline = Sparkline::default()
        .data(&data)
        .max(100)
        .style(Style::default().fg(color));
    frame.render_widget(sparkline, rows[1]);
}

fn draw_gibblox_panel(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &TuiState) {
    let block = Block::default().title("Gibblox").borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(inner);

    let trend = trend_symbol(&state.gibblox_history);
    let status = if state.gibblox_available {
        format!(
            "hit={}%% fill={}%% {trend}",
            state.gibblox_hit_rate, state.gibblox_fill_rate
        )
    } else {
        "n/a".to_string()
    };
    let color = if state.gibblox_available {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let header = Line::from(vec![Span::styled(status, Style::default().fg(color))]);
    let header_widget = Paragraph::new(header);
    frame.render_widget(header_widget, rows[0]);

    let data: Vec<u64> = state.gibblox_history.iter().copied().collect();
    let sparkline = Sparkline::default()
        .data(&data)
        .max(100)
        .style(Style::default().fg(color));
    frame.render_widget(sparkline, rows[1]);
}

fn draw_serial_panel(frame: &mut Frame<'_>, area: ratatui::layout::Rect, state: &TuiState) {
    let inner_rows = area.height.saturating_sub(2) as usize;
    let terminal_rows = state.serial.styled_rows(inner_rows.max(1));
    let lines: Vec<Line<'_>> = terminal_rows
        .into_iter()
        .map(|row| {
            let spans = row
                .spans
                .into_iter()
                .map(|span| Span::styled(span.text, style_from_terminal(span.style)))
                .collect::<Vec<_>>();
            Line::from(spans)
        })
        .collect();

    let panel = Paragraph::new(lines).block(
        Block::default()
            .title("Serial Console")
            .borders(Borders::ALL),
    );
    frame.render_widget(panel, area);
}

fn style_from_terminal(style: TerminalStyle) -> Style {
    let (fg, bg) = if style.inverse {
        (style.bg, style.fg)
    } else {
        (style.fg, style.bg)
    };

    let mut out = Style::default();
    if let Some(color) = ratatui_color(fg) {
        out = out.fg(color);
    }
    if let Some(color) = ratatui_color(bg) {
        out = out.bg(color);
    }
    if style.bold {
        out = out.add_modifier(Modifier::BOLD);
    }
    if style.dim {
        out = out.add_modifier(Modifier::DIM);
    }
    if style.italic {
        out = out.add_modifier(Modifier::ITALIC);
    }
    if style.underline {
        out = out.add_modifier(Modifier::UNDERLINED);
    }
    out
}

fn ratatui_color(color: TerminalColor) -> Option<Color> {
    match color {
        TerminalColor::Default => None,
        TerminalColor::Rgb(r, g, b) => Some(Color::Rgb(r, g, b)),
    }
}

fn trend_symbol(history: &VecDeque<u64>) -> &'static str {
    if history.len() < 2 {
        return "-";
    }
    let prev = history[history.len() - 2];
    let cur = history[history.len() - 1];
    if cur > prev {
        "^"
    } else if cur < prev {
        "v"
    } else {
        "-"
    }
}

#[derive(Default)]
struct TuiState {
    phase: BootPhase,
    phase_detail: String,
    logs: Vec<String>,
    serial: SerialTerminal,
    paused: bool,
    scroll: u16,
    page_step: u16,
    smoo_active: bool,
    smoo_export_count: u32,
    smoo_session_id: u64,
    smoo_history: VecDeque<u64>,
    gibblox_available: bool,
    gibblox_hit_rate: u64,
    gibblox_fill_rate: u64,
    gibblox_history: VecDeque<u64>,
    done: bool,
}

impl TuiState {
    fn handle_event(&mut self, event: BootEvent) {
        match event {
            BootEvent::Phase { phase, detail } => {
                self.phase = phase;
                self.phase_detail = detail.clone();
                self.push_log(format!(
                    "[{}] phase={} {}",
                    timestamp_hms(),
                    phase.label(),
                    detail
                ));
            }
            BootEvent::Log(line) => self.push_log(format!("[{}] {line}", timestamp_hms())),
            BootEvent::SerialBytes(bytes) => {
                self.serial.process(bytes.as_slice());
            }
            BootEvent::SmooStatus {
                active,
                export_count,
                session_id,
            } => {
                self.smoo_active = active;
                self.smoo_export_count = export_count;
                self.smoo_session_id = session_id;
                Self::push_history(&mut self.smoo_history, if active { 100 } else { 0 });
            }
            BootEvent::GibbloxStats {
                hit_rate_pct,
                fill_rate_pct,
                cached_blocks,
                total_blocks,
            } => {
                self.gibblox_available = true;
                self.gibblox_hit_rate = hit_rate_pct;
                self.gibblox_fill_rate = fill_rate_pct;
                Self::push_history(&mut self.gibblox_history, hit_rate_pct);
                self.push_log(format!(
                    "[{}] gibblox cache hit={}%% fill={}%% blocks={}/{}",
                    timestamp_hms(),
                    hit_rate_pct,
                    fill_rate_pct,
                    cached_blocks,
                    total_blocks
                ));
            }
            BootEvent::Finished => {
                self.phase = BootPhase::Finished;
                self.phase_detail = "boot flow finished".to_string();
                self.done = true;
            }
            BootEvent::Failed(message) => {
                self.phase = BootPhase::Failed;
                self.phase_detail = message.clone();
                self.push_log(format!("[{}] error: {message}", timestamp_hms()));
                self.done = true;
            }
        }
    }

    fn clamp_scroll(&mut self, visible_logs: usize) {
        let max = self.logs.len().saturating_sub(visible_logs) as u16;
        if self.paused {
            self.scroll = self.scroll.min(max);
        } else {
            self.scroll = max;
        }
    }

    fn push_log(&mut self, line: String) {
        self.logs.push(line);
        if self.logs.len() > LOG_LIMIT {
            let to_drop = self.logs.len() - LOG_LIMIT;
            self.logs.drain(0..to_drop);
        }
    }

    fn push_history(history: &mut VecDeque<u64>, value: u64) {
        if history.len() >= HISTORY {
            let _ = history.pop_front();
        }
        history.push_back(value.min(100));
    }
}

struct TerminalGuard;

impl TerminalGuard {
    fn new() -> Self {
        Self
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
    }
}
