use anyhow::{Context as _, Result, ensure};
use rusb::{Direction, TransferType, UsbContext};

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

// Discovery only reads descriptors. libusb is blocking, so keep the complete
// scan (including serial reads) off the async executor. Count all matches and
// retain the inspected handle, so claiming it never rescans or selects another
// device if the USB inventory changes in between.
pub(super) async fn discover_runtime_device(
    serial: String,
    class: u8,
    subclass: u8,
    protocol: u8,
) -> Result<Option<rusb::DeviceHandle<rusb::Context>>> {
    let result = tokio::task::spawn_blocking(move || {
        let context = rusb::Context::new().context("create runtime USB context")?;
        let devices = context.devices().context("enumerate runtime USB devices")?;
        let mut candidates = Vec::new();
        for device in devices.iter() {
            let descriptor = match device.device_descriptor() {
                Ok(descriptor) => descriptor,
                Err(rusb::Error::NoDevice) => continue,
                Err(err) => return Err(err).context("read runtime USB descriptor"),
            };
            let config = match device.active_config_descriptor() {
                Ok(config) => config,
                Err(rusb::Error::NotFound | rusb::Error::NoDevice) => continue, // unconfigured/disconnected device
                Err(err) => return Err(err).context("read runtime USB configuration"),
            };
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
                continue;
            }
            // Fail closed if a matching interface cannot be inspected: it
            // could be a second gadget with the requested serial.
            let handle = match device.open() {
                Ok(handle) => handle,
                Err(rusb::Error::NoDevice) => continue,
                Err(err) => {
                    return Err(err).context("open runtime USB device for serial inspection");
                }
            };
            let actual = match handle.read_serial_number_string_ascii(&descriptor) {
                Ok(serial) => serial,
                Err(rusb::Error::NoDevice) => continue,
                Err(err) => return Err(err).context("read runtime USB serial"),
            };
            candidates.push(RuntimeUsbDevice {
                serial: actual,
                handle,
            });
        }
        select_runtime_device(&serial, candidates)
    })
    .await
    .context("runtime USB discovery task")?;
    finish_discovery_attempt(result)
}

fn finish_discovery_attempt<H>(result: Result<Option<H>>) -> Result<Option<H>> {
    match result {
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
            // Discard the whole incomplete scan, even if it found a target
            // before failing. The caller's cancellable delay precedes a fresh
            // scan and duplicate check; no partial result can claim a device.
            tracing::warn!(error = ?err, "transient runtime USB discovery failure; retrying");
            Ok(None)
        }
        result => result,
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

    fn device(serial: &str) -> RuntimeUsbDevice<u8> {
        RuntimeUsbDevice {
            serial: serial.into(),
            handle: 1,
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
    fn transient_scan_failure_retries_without_claiming_a_partial_target() {
        for error in [
            rusb::Error::Io,
            rusb::Error::Timeout,
            rusb::Error::Interrupted,
            rusb::Error::Pipe,
            rusb::Error::Busy,
            rusb::Error::Other,
        ] {
            // A scan error carries context and must discard any partial result.
            let failed_scan: Result<Option<u8>> = Err(error).context("read runtime USB serial");
            assert_eq!(finish_discovery_attempt(failed_scan).unwrap(), None);
            assert_eq!(
                finish_discovery_attempt(select_runtime_device("target", vec![device("other")]))
                    .unwrap(),
                None
            );
            assert_eq!(
                finish_discovery_attempt(select_runtime_device("target", vec![device("target")]))
                    .unwrap(),
                Some(1)
            );
        }
    }

    #[test]
    fn invalid_ambiguous_and_permanent_discovery_errors_remain_fatal() {
        assert!(finish_discovery_attempt(select_runtime_device::<u8>("", Vec::new())).is_err());
        assert!(
            finish_discovery_attempt(select_runtime_device(
                "target",
                vec![device("target"), device("target")]
            ))
            .is_err()
        );
        for error in [
            rusb::Error::Access,
            rusb::Error::InvalidParam,
            rusb::Error::BadDescriptor,
            rusb::Error::NoMem,
            rusb::Error::NotSupported,
        ] {
            assert!(finish_discovery_attempt::<u8>(Err(error).context("read descriptor")).is_err());
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
