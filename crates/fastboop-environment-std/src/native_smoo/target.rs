use anyhow::{Context as _, Result, ensure};
use rusb::{Direction, TransferType, UsbContext};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RuntimeUsbIdentity {
    pub vendor: u16,
    pub product: u16,
    pub serial: String,
}

pub(crate) fn validate_runtime_serial(serial: &str) -> Result<()> {
    ensure!(
        !serial.is_empty() && serial.trim() == serial && !serial.chars().any(char::is_control),
        "smoo runtime serial must be nonempty, without surrounding whitespace or control characters"
    );
    Ok(())
}

fn select_runtime_device(
    serial: &str,
    candidates: impl IntoIterator<Item = RuntimeUsbIdentity>,
) -> Result<Option<RuntimeUsbIdentity>> {
    validate_runtime_serial(serial)?;
    let mut matches = candidates
        .into_iter()
        .filter(|device| device.serial == serial);
    let selected = matches.next();
    ensure!(
        matches.next().is_none(),
        "multiple smoo gadgets have runtime serial '{serial}'; configure a unique gadget serial before serving a root"
    );
    Ok(selected)
}

// Discovery only reads descriptors. libusb is blocking, so keep the complete
// scan (including serial reads) off the async executor. Count all matches before
// allowing smoo's first-match opener to claim an interface.
pub(super) async fn discover_runtime_device(
    serial: String,
    class: u8,
    subclass: u8,
    protocol: u8,
) -> Result<Option<RuntimeUsbIdentity>> {
    tokio::task::spawn_blocking(move || {
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
            candidates.push(RuntimeUsbIdentity {
                vendor: descriptor.vendor_id(),
                product: descriptor.product_id(),
                serial: actual,
            });
        }
        select_runtime_device(&serial, candidates)
    })
    .await
    .context("runtime USB discovery task")?
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

    fn device(serial: &str) -> RuntimeUsbIdentity {
        RuntimeUsbIdentity {
            vendor: 0x1209,
            product: 0xbeef,
            serial: serial.into(),
        }
    }

    #[test]
    fn selection_waits_for_requested_device_and_never_switches_on_reconnect() {
        let other = device("other");
        let target = device("target");
        // The unrelated gadget arrives first. The target disconnects and later
        // returns with the other gadget still present and first in enumeration.
        for (candidates, expected) in [
            (vec![other.clone()], None),
            (vec![other.clone(), target.clone()], Some(target.clone())),
            (vec![other.clone()], None),
            (vec![other, target.clone()], Some(target)),
        ] {
            assert_eq!(
                select_runtime_device("target", candidates).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn duplicate_serial_is_rejected_even_across_different_vid_pids() {
        let mut duplicate = device("target");
        duplicate.product += 1;
        assert!(select_runtime_device("target", vec![device("target"), duplicate]).is_err());
    }

    #[test]
    fn selector_is_never_empty_or_silently_normalized() {
        for serial in ["", " target", "target ", "target\n", "tar\0get"] {
            assert!(select_runtime_device(serial, Vec::new()).is_err());
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
