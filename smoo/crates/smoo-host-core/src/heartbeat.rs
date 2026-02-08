use crate::{ControlTransport, TransportError, control::read_status};
use smoo_proto::SmooStatusV0;

/// Issue a SMOO_STATUS request and return the decoded payload.
pub async fn heartbeat_once<C: ControlTransport>(
    control: &C,
) -> Result<SmooStatusV0, TransportError> {
    read_status(control).await
}
