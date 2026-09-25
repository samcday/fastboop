use std::collections::HashMap;
use std::fmt;

use anyhow::{Context as _, Result, ensure};
use rusb::{Direction, TransferType, UsbContext};

/// Newly enumerated USB device nodes can stay root-only until udev applies its
/// rules (MODE/GROUP/uaccess), so a failed inspection right after hotplug is
/// expected. Warn once a device keeps failing for this many consecutive passes
/// (about two seconds at the 500 ms discovery poll).
const WARN_AFTER_FAILED_PASSES: u32 = 4;
const DEVICE_PERMISSIONS_URL: &str = "https://fastboop.win/device-permissions";

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeUsbDevice<H> {
    pub serial: String,
    pub handle: H,
}

pub(crate) fn validate_runtime_serial(serial: &str) -> Result<()> {
    ensure!(
        !serial.is_empty()
            && serial.is_ascii()
            && serial.trim() == serial
            && !serial.chars().any(char::is_control),
        "smoo runtime serial must be nonempty ASCII, without surrounding whitespace or control characters"
    );
    Ok(())
}

fn select_runtime_device<H>(
    serial: &str,
    candidates: impl IntoIterator<Item = RuntimeUsbDevice<H>>,
) -> Result<Option<H>> {
    validate_runtime_serial(serial)?;
    let mut matches = candidates
        .into_iter()
        .filter(|device| device.serial == serial);
    let selected = matches.next();
    ensure!(
        matches.next().is_none(),
        "multiple smoo gadgets have runtime serial '{serial}'; configure a unique gadget serial before serving a root"
    );
    Ok(selected.map(|device| device.handle))
}

/// Runtime gadget discovery state retained across polls.
#[derive(Debug, Default)]
pub(super) struct RuntimeDiscovery {
    /// Consecutive failed passes for each bus/address that failed inspection
    /// in the latest pass.
    failing: HashMap<(u8, u8), FailureStreak>,
}

#[derive(Clone, Copy, Debug, Default)]
struct FailureStreak {
    passes: u32,
    warned: bool,
}

impl RuntimeDiscovery {
    // Discovery only reads descriptors. libusb is blocking, so keep the complete
    // scan (including serial reads) off the async executor. Count all matches and
    // retain the inspected handle, so claiming it never rescans or selects another
    // device if the USB inventory changes in between.
    pub(super) async fn discover(
        &mut self,
        serial: &str,
        class: u8,
        subclass: u8,
        protocol: u8,
    ) -> Result<Option<rusb::DeviceHandle<rusb::Context>>> {
        let scan =
            tokio::task::spawn_blocking(move || scan_runtime_devices(class, subclass, protocol))
                .await
                .context("runtime USB discovery task")?;
        match finish_discovery_attempt(scan)? {
            Some(scan) => self.select(serial, scan),
            None => Ok(None),
        }
    }

    fn select<H>(&mut self, serial: &str, scan: RuntimeScan<H>) -> Result<Option<H>> {
        for device in &scan.uninspected {
            tracing::debug!(
                bus = device.bus,
                address = device.address,
                step = %device.failure.step,
                error = %device.failure.error,
                "skipping USB device that could not be inspected for the smoo runtime serial"
            );
        }
        for device in self.track_failures(&scan.uninspected) {
            warn_uninspected(&device);
        }
        // Visible duplicates are fatal even when other devices were skipped.
        let selected = select_runtime_device(serial, scan.candidates)?;
        let deferring = scan
            .uninspected
            .iter()
            .filter(|device| device.failure.defers_claim())
            .count();
        if selected.is_some() && deferring > 0 {
            // Fail closed: a smoo-class device whose serial could not be read
            // may be a second gadget with the requested serial. Drop the
            // handle and claim only after a pass that read every such serial.
            tracing::debug!(
                deferring,
                "found the runtime gadget; deferring its claim until every smoo-class USB device can be inspected"
            );
            return Ok(None);
        }
        Ok(selected)
    }

    /// Record this pass's inspection failures and return the devices whose
    /// failures just became persistent. Each device address warns once per
    /// failure streak; a device that recovers or disappears is forgotten.
    fn track_failures(&mut self, uninspected: &[UninspectedDevice]) -> Vec<UninspectedDevice> {
        let previous = std::mem::take(&mut self.failing);
        let mut persistent = Vec::new();
        for device in uninspected {
            let key = (device.bus, device.address);
            let mut streak = previous.get(&key).copied().unwrap_or_default();
            streak.passes = streak.passes.saturating_add(1);
            if !streak.warned && streak.passes >= WARN_AFTER_FAILED_PASSES {
                streak.warned = true;
                persistent.push(*device);
            }
            self.failing.insert(key, streak);
        }
        persistent
    }
}

fn warn_uninspected(device: &UninspectedDevice) {
    let UninspectedDevice {
        bus,
        address,
        failure,
    } = *device;
    let consequence = if failure.defers_claim() {
        "It exposes a smoo interface, so no smoo gadget is claimed until it can be inspected \
         or is removed"
    } else {
        "It is skipped until its descriptors can be read"
    };
    if failure.error == rusb::Error::Access {
        tracing::warn!(
            bus,
            address,
            step = %failure.step,
            "permission denied inspecting USB device {bus:03}:{address:03} for the smoo runtime \
             serial; install udev rules that grant this user access (for example \
             TAG+=\"uaccess\"), see {DEVICE_PERMISSIONS_URL}. {consequence}"
        );
    } else {
        tracing::warn!(
            bus,
            address,
            step = %failure.step,
            error = %failure.error,
            "cannot inspect USB device {bus:03}:{address:03} for the smoo runtime serial. \
             {consequence}"
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InspectStep {
    DeviceDescriptor,
    ActiveConfig,
    Open,
    Serial,
}

impl fmt::Display for InspectStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DeviceDescriptor => "read device descriptor",
            Self::ActiveConfig => "read active configuration",
            Self::Open => "open device",
            Self::Serial => "read serial number",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InspectError {
    step: InspectStep,
    error: rusb::Error,
}

impl InspectError {
    fn at(step: InspectStep) -> impl FnOnce(rusb::Error) -> Self {
        move |error| Self { step, error }
    }

    /// A disconnected device, or one without an active configuration, exposes
    /// no smoo interface and cannot be a gadget with the requested serial.
    fn device_absent(self) -> bool {
        matches!(
            (self.step, self.error),
            (_, rusb::Error::NoDevice) | (InspectStep::ActiveConfig, rusb::Error::NotFound)
        )
    }

    /// Open and serial failures come from a device that exposes a smoo
    /// interface and a serial, so it may be a second gadget with the requested
    /// serial. A device whose descriptors cannot be read may be any USB device
    /// on the host, and cannot be claimed either, so it does not hold back a
    /// visible target.
    fn defers_claim(self) -> bool {
        matches!(self.step, InspectStep::Open | InspectStep::Serial)
    }
}

type Inspection<H> = Result<Option<RuntimeUsbDevice<H>>, InspectError>;

/// A USB device that a discovery pass could not inspect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UninspectedDevice {
    bus: u8,
    address: u8,
    failure: InspectError,
}

/// Result of one pass over the USB inventory. A device that fails inspection
/// is skipped without aborting the pass, so every other device is inspected.
/// Only failures that [`InspectError::defers_claim`] hold back a found target.
#[derive(Debug)]
struct RuntimeScan<H> {
    candidates: Vec<RuntimeUsbDevice<H>>,
    uninspected: Vec<UninspectedDevice>,
}

impl<H> RuntimeScan<H> {
    fn collect(inspections: impl IntoIterator<Item = ((u8, u8), Inspection<H>)>) -> Self {
        let mut scan = Self {
            candidates: Vec::new(),
            uninspected: Vec::new(),
        };
        for ((bus, address), inspection) in inspections {
            match inspection {
                Ok(Some(device)) => scan.candidates.push(device),
                Ok(None) => {}
                Err(failure) if failure.device_absent() => {
                    tracing::trace!(
                        bus,
                        address,
                        step = %failure.step,
                        error = %failure.error,
                        "skipping disconnected or unconfigured USB device"
                    );
                }
                Err(failure) => scan.uninspected.push(UninspectedDevice {
                    bus,
                    address,
                    failure,
                }),
            }
        }
        scan
    }
}

fn scan_runtime_devices(
    class: u8,
    subclass: u8,
    protocol: u8,
) -> Result<RuntimeScan<rusb::DeviceHandle<rusb::Context>>> {
    let context = rusb::Context::new().context("create runtime USB context")?;
    let devices = context.devices().context("enumerate runtime USB devices")?;
    Ok(RuntimeScan::collect(devices.iter().map(|device| {
        (
            (device.bus_number(), device.address()),
            inspect_runtime_device(&device, class, subclass, protocol),
        )
    })))
}

fn inspect_runtime_device(
    device: &rusb::Device<rusb::Context>,
    class: u8,
    subclass: u8,
    protocol: u8,
) -> Inspection<rusb::DeviceHandle<rusb::Context>> {
    let descriptor = device
        .device_descriptor()
        .map_err(InspectError::at(InspectStep::DeviceDescriptor))?;
    let config = device
        .active_config_descriptor()
        .map_err(InspectError::at(InspectStep::ActiveConfig))?;
    let has_smoo = config.interfaces().any(|interface| {
        interface.descriptors().any(|descriptor| {
            descriptor.class_code() == class
                && descriptor.sub_class_code() == subclass
                && descriptor.protocol_code() == protocol
                && has_smoo_endpoints(
                    descriptor
                        .endpoint_descriptors()
                        .map(|ep| (ep.transfer_type(), ep.direction())),
                )
        })
    });
    if !has_smoo
        || descriptor
            .serial_number_string_index()
            .is_none_or(|i| i == 0)
    {
        return Ok(None);
    }
    let handle = device.open().map_err(InspectError::at(InspectStep::Open))?;
    let serial = handle
        .read_serial_number_string_ascii(&descriptor)
        .map_err(InspectError::at(InspectStep::Serial))?;
    Ok(Some(RuntimeUsbDevice { serial, handle }))
}

/// Classify failures that prevent any pass over the USB inventory.
fn finish_discovery_attempt<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(scan) => Ok(Some(scan)),
        Err(err)
            if matches!(
                err.downcast_ref::<rusb::Error>(),
                Some(
                    rusb::Error::Io
                        | rusb::Error::NoDevice
                        | rusb::Error::NotFound
                        | rusb::Error::Busy
                        | rusb::Error::Timeout
                        | rusb::Error::Overflow
                        | rusb::Error::Pipe
                        | rusb::Error::Interrupted
                        | rusb::Error::Other
                )
            ) =>
        {
            // The caller's cancellable delay precedes a fresh scan.
            tracing::warn!(error = ?err, "transient runtime USB discovery failure; retrying");
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn has_smoo_endpoints(endpoints: impl Iterator<Item = (TransferType, Direction)>) -> bool {
    let mut seen = [false; 4];
    for endpoint in endpoints {
        match endpoint {
            (TransferType::Bulk, Direction::In) => seen[0] = true,
            (TransferType::Bulk, Direction::Out) => seen[1] = true,
            (TransferType::Interrupt, Direction::In) => seen[2] = true,
            (TransferType::Interrupt, Direction::Out) => seen[3] = true,
            _ => {}
        }
    }
    seen.into_iter().all(|present| present)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSPECT_STEPS: [InspectStep; 4] = [
        InspectStep::DeviceDescriptor,
        InspectStep::ActiveConfig,
        InspectStep::Open,
        InspectStep::Serial,
    ];

    // Steps reached only by a device exposing a smoo interface with a serial.
    const SMOO_CLASS_STEPS: [InspectStep; 2] = [InspectStep::Open, InspectStep::Serial];

    // Every libusb error other than a disconnect.
    const INSPECT_ERRORS: [rusb::Error; 12] = [
        rusb::Error::Access,
        rusb::Error::Busy,
        rusb::Error::Io,
        rusb::Error::Timeout,
        rusb::Error::Pipe,
        rusb::Error::Overflow,
        rusb::Error::Interrupted,
        rusb::Error::Other,
        rusb::Error::InvalidParam,
        rusb::Error::BadDescriptor,
        rusb::Error::NoMem,
        rusb::Error::NotSupported,
    ];

    fn device(serial: &str) -> RuntimeUsbDevice<u8> {
        RuntimeUsbDevice {
            serial: serial.into(),
            handle: 1,
        }
    }

    fn found(address: u8, serial: &str) -> ((u8, u8), Inspection<u8>) {
        (
            (1, address),
            Ok(Some(RuntimeUsbDevice {
                serial: serial.into(),
                handle: address,
            })),
        )
    }

    fn failed(address: u8, step: InspectStep, error: rusb::Error) -> ((u8, u8), Inspection<u8>) {
        ((1, address), Err(InspectError { step, error }))
    }

    fn uninspected(address: u8, step: InspectStep, error: rusb::Error) -> UninspectedDevice {
        UninspectedDevice {
            bus: 1,
            address,
            failure: InspectError { step, error },
        }
    }

    #[test]
    fn selection_waits_for_requested_device_and_never_switches_on_reconnect() {
        let mut other = device("other");
        other.handle = 2;
        let target = device("target");
        // The unrelated gadget arrives first. The target disconnects and later
        // returns with the other gadget still present and first in enumeration.
        for (candidates, expected) in [
            (vec![other.clone()], None),
            (vec![other.clone(), target.clone()], Some(target.handle)),
            (vec![other.clone()], None),
            (vec![other, target.clone()], Some(target.handle)),
        ] {
            assert_eq!(
                select_runtime_device("target", candidates).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn duplicate_serial_is_rejected_across_distinct_devices() {
        let mut duplicate = device("target");
        duplicate.handle += 1;
        assert!(select_runtime_device("target", vec![device("target"), duplicate]).is_err());
    }

    #[test]
    fn selector_is_never_empty_or_silently_normalized() {
        for serial in [
            "", " target", "target ", "target\n", "tar\0get", "café", "📱",
        ] {
            assert!(select_runtime_device::<u8>(serial, Vec::new()).is_err());
        }
    }

    #[test]
    fn uninspectable_device_is_skipped_while_the_scan_continues() {
        for step in INSPECT_STEPS {
            for error in INSPECT_ERRORS {
                // The failing device enumerates first; the rest of the pass is
                // still inspected, and no error results.
                let scan = RuntimeScan::collect([
                    failed(2, step, error),
                    found(3, "other"),
                    found(4, "target"),
                ]);
                assert_eq!(scan.candidates.len(), 2, "{step} {error}");
                assert_eq!(scan.uninspected, [uninspected(2, step, error)]);
            }
        }
    }

    #[test]
    fn uninspectable_smoo_class_device_defers_the_claim() {
        for step in SMOO_CLASS_STEPS {
            for error in INSPECT_ERRORS {
                let mut discovery = RuntimeDiscovery::default();
                let scan = RuntimeScan::collect([
                    failed(2, step, error),
                    found(3, "other"),
                    found(4, "target"),
                ]);
                assert_eq!(discovery.select("target", scan).unwrap(), None, "{step}");

                // The next poll inspects every device and claims the target.
                let scan = RuntimeScan::collect([
                    found(2, "unrelated"),
                    found(3, "other"),
                    found(4, "target"),
                ]);
                assert_eq!(discovery.select("target", scan).unwrap(), Some(4));
            }
        }
    }

    #[test]
    fn unreadable_descriptors_do_not_defer_the_claim() {
        for step in INSPECT_STEPS
            .into_iter()
            .filter(|step| !SMOO_CLASS_STEPS.contains(step))
        {
            for error in INSPECT_ERRORS {
                // The class of a device whose descriptors cannot be read is
                // unknown; it must not hold back a visible target forever.
                let mut discovery = RuntimeDiscovery::default();
                for _ in 0..=WARN_AFTER_FAILED_PASSES {
                    let scan = RuntimeScan::collect([failed(2, step, error), found(4, "target")]);
                    assert_eq!(
                        discovery.select("target", scan).unwrap(),
                        Some(4),
                        "{step} {error}"
                    );
                }
                // A smoo-class failure in the same pass still defers.
                let scan = RuntimeScan::collect([
                    failed(2, step, error),
                    failed(3, InspectStep::Open, rusb::Error::Access),
                    found(4, "target"),
                ]);
                assert_eq!(discovery.select("target", scan).unwrap(), None);
            }
        }
    }

    #[test]
    fn inaccessible_target_is_retried_until_udev_grants_access() {
        let mut discovery = RuntimeDiscovery::default();
        for _ in 0..3 {
            let scan = RuntimeScan::collect([
                found(2, "other"),
                failed(4, InspectStep::Open, rusb::Error::Access),
            ]);
            assert_eq!(discovery.select("target", scan).unwrap(), None);
        }
        let scan = RuntimeScan::collect([found(2, "other"), found(4, "target")]);
        assert_eq!(discovery.select("target", scan).unwrap(), Some(4));
    }

    #[test]
    fn disconnected_and_unconfigured_devices_do_not_defer_a_claim() {
        let mut inspections = INSPECT_STEPS
            .into_iter()
            .zip(2..)
            .map(|(step, address)| failed(address, step, rusb::Error::NoDevice))
            .collect::<Vec<_>>();
        inspections.push(failed(10, InspectStep::ActiveConfig, rusb::Error::NotFound));
        inspections.push(found(11, "target"));
        let scan = RuntimeScan::collect(inspections);
        assert!(scan.uninspected.is_empty());
        assert_eq!(
            RuntimeDiscovery::default().select("target", scan).unwrap(),
            Some(11)
        );

        // Elsewhere, NotFound is an inspection failure rather than an absence.
        for step in [
            InspectStep::DeviceDescriptor,
            InspectStep::Open,
            InspectStep::Serial,
        ] {
            let scan =
                RuntimeScan::collect([failed(2, step, rusb::Error::NotFound), found(3, "target")]);
            assert_eq!(scan.uninspected.len(), 1);
        }
    }

    #[test]
    fn visible_duplicates_remain_fatal_when_other_devices_fail() {
        let scan = RuntimeScan::collect([
            failed(2, InspectStep::Open, rusb::Error::Access),
            found(3, "target"),
            found(4, "target"),
        ]);
        assert!(RuntimeDiscovery::default().select("target", scan).is_err());
        let scan = RuntimeScan::collect([failed(2, InspectStep::Open, rusb::Error::Access)]);
        assert!(RuntimeDiscovery::default().select("", scan).is_err());
    }

    #[test]
    fn persistent_failures_warn_once_per_device_address() {
        let mut discovery = RuntimeDiscovery::default();
        let denied = uninspected(2, InspectStep::Open, rusb::Error::Access);
        let flapping = uninspected(3, InspectStep::Serial, rusb::Error::Pipe);
        let recovered = uninspected(4, InspectStep::Open, rusb::Error::Access);
        let mut warned = Vec::new();
        for pass in 1..=20 {
            let mut failures = vec![denied];
            // Short failure streaks (the udev hotplug window) never warn.
            if pass % WARN_AFTER_FAILED_PASSES != 0 {
                failures.push(flapping);
            }
            if pass < WARN_AFTER_FAILED_PASSES {
                failures.push(recovered);
            }
            warned.extend(
                discovery
                    .track_failures(&failures)
                    .into_iter()
                    .map(|device| (pass, device)),
            );
        }
        assert_eq!(warned, [(WARN_AFTER_FAILED_PASSES, denied)]);

        // A re-enumerated device has a new address and a fresh streak.
        let reenumerated = uninspected(5, InspectStep::Open, rusb::Error::Access);
        let warned = (1..=WARN_AFTER_FAILED_PASSES)
            .flat_map(|_| discovery.track_failures(&[denied, reenumerated]))
            .collect::<Vec<_>>();
        assert_eq!(warned, [reenumerated]);
    }

    #[test]
    fn enumeration_failures_keep_their_retry_classification() {
        assert_eq!(finish_discovery_attempt(Ok(7)).unwrap(), Some(7));
        for error in [
            rusb::Error::Io,
            rusb::Error::Timeout,
            rusb::Error::Interrupted,
            rusb::Error::Pipe,
            rusb::Error::Busy,
            rusb::Error::Other,
        ] {
            let failed: Result<u8> = Err(error).context("enumerate runtime USB devices");
            assert_eq!(finish_discovery_attempt(failed).unwrap(), None);
        }
        for error in [
            rusb::Error::Access,
            rusb::Error::InvalidParam,
            rusb::Error::BadDescriptor,
            rusb::Error::NoMem,
            rusb::Error::NotSupported,
        ] {
            let failed: Result<u8> = Err(error).context("create runtime USB context");
            assert!(finish_discovery_attempt(failed).is_err());
        }
    }

    #[test]
    fn fastboot_interface_is_not_a_runtime_candidate() {
        let bulk = [
            (TransferType::Bulk, Direction::In),
            (TransferType::Bulk, Direction::Out),
        ];
        assert!(!has_smoo_endpoints(bulk.into_iter()));
        assert!(has_smoo_endpoints(bulk.into_iter().chain([
            (TransferType::Interrupt, Direction::In),
            (TransferType::Interrupt, Direction::Out),
        ])));
    }
}
