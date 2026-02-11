use std::io;
use std::time::{Duration, Instant};
use usb_gadget::function::custom::Event;

/// Current USB link state as observed from FunctionFS lifecycle events and liveness pings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    Offline,
    Ready,
    Online,
}

/// Commands emitted by the link controller for the runtime to act upon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkCommand {
    /// Link state became invalid and the runtime should terminate.
    Fatal,
}

/// Drives link state transitions based on ep0 lifecycle events, heartbeat pings,
/// endpoint I/O errors, and periodic liveness ticks.
///
/// This controller is intentionally small and side-effect-free: it only tracks state and
/// emits commands. The caller is responsible for actually opening/closing endpoints and
/// replaying or parking I/O.
pub struct LinkController {
    state: LinkState,
    last_status: Option<Instant>,
    liveness_timeout: Duration,
    reopen_backoff: Duration,
    reopen_backoff_max: Duration,
    reopen_not_before: Option<Instant>,
    pending_drop: bool,
}

impl LinkController {
    /// Construct a new controller with a configurable liveness timeout.
    pub fn new(liveness_timeout: Duration) -> Self {
        Self {
            state: LinkState::Offline,
            last_status: None,
            liveness_timeout,
            reopen_backoff: Duration::from_secs(1),
            reopen_backoff_max: Duration::from_secs(30),
            reopen_not_before: None,
            pending_drop: false,
        }
    }

    /// Current link state snapshot.
    pub fn state(&self) -> LinkState {
        self.state
    }

    /// Notify the controller of an ep0 lifecycle event.
    pub fn on_ep0_event(&mut self, event: Event) {
        match event {
            Event::Bind | Event::Enable | Event::Resume => {
                self.reset_reopen_backoff();
                self.enter_ready();
            }
            Event::Disable | Event::Unbind => {
                self.enter_offline();
            }
            Event::Suspend => {
                // The bus may briefly suspend while the host reconfigures; keep the data plane
                // around and let liveness/status pings drive us back to Online.
                self.state = LinkState::Ready;
                self.pending_drop = false;
            }
            Event::SetupDeviceToHost(_) | Event::SetupHostToDevice(_) => { /* ignored */ }
            Event::Unknown(_) => {}
            _ => {}
        }
    }

    /// Notify the controller that a SMOO_STATUS (or equivalent heartbeat) was seen.
    pub fn on_status_ping(&mut self) {
        let now = Instant::now();
        self.last_status = Some(now);
        if matches!(self.state, LinkState::Offline) {
            if let Some(not_before) = self.reopen_not_before {
                if now < not_before {
                    return;
                }
            }
            // Host is talking to ep0; ensure data plane is reopened.
            self.enter_ready();
        }
        if matches!(self.state, LinkState::Ready | LinkState::Online) {
            self.state = LinkState::Online;
            self.reset_reopen_backoff();
        }
    }

    /// Notify the controller that an endpoint I/O error occurred.
    pub fn on_io_error(&mut self, _err: &io::Error) {
        if matches!(self.state, LinkState::Offline) {
            return;
        }
        self.reopen_not_before = Some(Instant::now() + self.reopen_backoff);
        self.reopen_backoff = self
            .reopen_backoff
            .saturating_mul(2)
            .min(self.reopen_backoff_max);
        self.enter_offline();
    }

    /// Advance the controller based on the current time to detect liveness timeouts.
    pub fn tick(&mut self, now: Instant) {
        if let Some(last) = self.last_status {
            if now.saturating_duration_since(last) > self.liveness_timeout {
                self.enter_offline();
            }
        }
    }

    /// Drain the next pending command, if any.
    pub fn take_command(&mut self) -> Option<LinkCommand> {
        if self.pending_drop {
            self.pending_drop = false;
            return Some(LinkCommand::Fatal);
        }
        None
    }

    fn enter_ready(&mut self) {
        self.state = LinkState::Ready;
        self.reopen_not_before = None;
        self.pending_drop = false;
    }

    fn enter_offline(&mut self) {
        self.state = LinkState::Offline;
        self.last_status = None;
        self.pending_drop = true;
    }

    fn reset_reopen_backoff(&mut self) {
        self.reopen_backoff = Duration::from_secs(1);
        self.reopen_not_before = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_on_events_and_status() {
        let mut ctrl = LinkController::new(Duration::from_secs(5));
        assert_eq!(ctrl.state(), LinkState::Offline);

        ctrl.on_ep0_event(Event::Enable);
        assert_eq!(ctrl.state(), LinkState::Ready);
        assert_eq!(ctrl.take_command(), None);

        ctrl.on_status_ping();
        assert_eq!(ctrl.state(), LinkState::Online);

        let err = io::Error::from_raw_os_error(libc::EPIPE);
        ctrl.on_io_error(&err);
        assert_eq!(ctrl.state(), LinkState::Offline);
        assert_eq!(ctrl.take_command(), Some(LinkCommand::Fatal));
    }

    #[test]
    fn liveness_timeout_forces_offline() {
        let mut ctrl = LinkController::new(Duration::from_millis(100));
        ctrl.on_ep0_event(Event::Enable);
        ctrl.take_command();
        ctrl.on_status_ping();
        let now = Instant::now() + Duration::from_millis(250);
        ctrl.tick(now);
        assert_eq!(ctrl.state(), LinkState::Offline);
        assert_eq!(ctrl.take_command(), Some(LinkCommand::Fatal));
    }
}
