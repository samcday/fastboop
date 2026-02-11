use crate::{ControlTransport, TransportError, TransportErrorKind, TransportResult};
use alloc::{format, string::String};
use smoo_proto::{
    CONFIG_EXPORTS_REQ_TYPE, CONFIG_EXPORTS_REQUEST, IDENT_LEN, IDENT_REQUEST, Ident,
    SMOO_STATUS_LEN, SMOO_STATUS_REQ_TYPE, SMOO_STATUS_REQUEST, SmooStatusV0,
};

pub use smoo_proto::ConfigExportsV0;

const IDENT_REQ_TYPE: u8 = 0xC1;

/// Execute the IDENT control transfer and decode the gadget's response.
pub async fn fetch_ident<T: ControlTransport>(transport: &T) -> TransportResult<Ident> {
    let mut buf = [0u8; IDENT_LEN];
    let len = transport
        .control_in(IDENT_REQ_TYPE, IDENT_REQUEST, &mut buf)
        .await?;
    if len != IDENT_LEN {
        return Err(protocol_error(format!(
            "ident control transfer truncated (expected {IDENT_LEN}, got {len})"
        )));
    }
    Ident::decode(buf).map_err(|err| protocol_error(format!("decode ident response: {err}")))
}

/// Send a v0 CONFIG_EXPORTS payload to the gadget.
pub async fn send_config_exports_v0<T: ControlTransport>(
    transport: &T,
    payload: &ConfigExportsV0,
) -> TransportResult<()> {
    let data = payload.encode();
    let written = transport
        .control_out(CONFIG_EXPORTS_REQ_TYPE, CONFIG_EXPORTS_REQUEST, &data)
        .await?;
    if written != data.len() {
        return Err(protocol_error(format!(
            "CONFIG_EXPORTS transfer truncated (expected {}, got {written})",
            data.len()
        )));
    }
    Ok(())
}

/// Issue a SMOO_STATUS request and decode the response payload.
pub async fn read_status<T: ControlTransport>(transport: &T) -> TransportResult<SmooStatusV0> {
    let mut buf = [0u8; SMOO_STATUS_LEN];
    let len = transport
        .control_in(SMOO_STATUS_REQ_TYPE, SMOO_STATUS_REQUEST, &mut buf)
        .await?;
    if len != SMOO_STATUS_LEN {
        return Err(protocol_error(format!(
            "SMOO_STATUS transfer truncated (expected {SMOO_STATUS_LEN}, got {len})"
        )));
    }
    SmooStatusV0::try_from_slice(&buf[..len])
        .map_err(|err| protocol_error(format!("decode SMOO_STATUS payload: {err}")))
}

fn protocol_error(message: impl Into<String>) -> TransportError {
    TransportError::with_message(TransportErrorKind::Protocol, message)
}

#[cfg(test)]
mod tests {
    use super::ConfigExportsV0;
    use alloc::vec;

    #[test]
    fn config_exports_single_encodes_fields() {
        let entries = vec![smoo_proto::ConfigExport {
            export_id: 5,
            block_size: 4096,
            size_bytes: 8192,
        }];
        let payload = ConfigExportsV0::from_slice(&entries).unwrap();
        let encoded = payload.encode();
        assert_eq!(
            encoded.len(),
            ConfigExportsV0::HEADER_LEN + ConfigExportsV0::ENTRY_LEN
        );
        assert_eq!(&encoded[2..4], &[1, 0]);
        assert_eq!(&encoded[8..12], &5u32.to_le_bytes());
        assert_eq!(&encoded[12..16], &4096u32.to_le_bytes());
        assert_eq!(&encoded[16..24], &8192u64.to_le_bytes());
    }
}
