#![no_std]

use core::{convert::TryFrom, fmt};

/// ASCII magic prefix for Ident handshake messages.
pub const IDENT_MAGIC: [u8; 4] = *b"SMOO";
/// Number of bytes in an encoded [`Ident`] message.
pub const IDENT_LEN: usize = 8;
/// Vendor control request opcode used to fetch [`Ident`].
pub const IDENT_REQUEST: u8 = 0x01;
/// Number of bytes in an encoded [`Request`] control message.
pub const REQUEST_LEN: usize = 28;
/// Number of bytes in an encoded [`Response`] control message.
pub const RESPONSE_LEN: usize = 28;
/// bmRequestType for CONFIG_EXPORTS (host → gadget, vendor, interface, OUT).
pub const CONFIG_EXPORTS_REQ_TYPE: u8 = 0x41;
/// Vendor control bRequest used to apply CONFIG_EXPORTS.
pub const CONFIG_EXPORTS_REQUEST: u8 = 0x02;
/// Vendor control bRequest used to fetch [`SmooStatusV0`].
pub const SMOO_STATUS_REQUEST: u8 = 0x03;
/// bmRequestType for SMOO status/heartbeat (device → host, vendor, interface).
pub const SMOO_STATUS_REQ_TYPE: u8 = 0xA1;
/// Number of bytes returned by [`SmooStatusV0`].
pub const SMOO_STATUS_LEN: usize = 16;
/// Supported status payload version.
pub const SMOO_STATUS_VERSION: u16 = 0;
/// Status flag indicating an active export.
pub const SMOO_STATUS_FLAG_EXPORT_ACTIVE: u16 = 1 << 0;

/// Errors surfaced while decoding protocol messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// Buffer length did not match the protocol expectation.
    InvalidLength { expected: usize, actual: usize },
    /// Incoming opcode is unsupported.
    InvalidOpcode(u8),
    /// Ident magic prefix did not match `SMOO`.
    InvalidMagic,
    /// Payload or struct version mismatch.
    InvalidVersion { expected: u16, actual: u16 },
    /// Field value failed validation.
    InvalidValue(&'static str),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::InvalidLength { expected, actual } => {
                write!(f, "invalid message length {actual}, expected {expected}")
            }
            ProtoError::InvalidOpcode(op) => write!(f, "invalid opcode {op}"),
            ProtoError::InvalidMagic => write!(f, "invalid ident magic"),
            ProtoError::InvalidVersion { expected, actual } => write!(
                f,
                "unsupported payload version {actual}, expected {expected}"
            ),
            ProtoError::InvalidValue(field) => write!(f, "invalid field value: {field}"),
        }
    }
}

/// Result alias for protocol parsing operations.
pub type Result<T> = core::result::Result<T, ProtoError>;

/// Control-plane operations issued by ublk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    Read = 0,
    Write = 1,
    Flush = 2,
    Discard = 3,
}

impl TryFrom<u8> for OpCode {
    type Error = ProtoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            2 => Ok(Self::Flush),
            3 => Ok(Self::Discard),
            other => Err(ProtoError::InvalidOpcode(other)),
        }
    }
}

impl From<OpCode> for u8 {
    fn from(op: OpCode) -> Self {
        op as u8
    }
}

/// Ident handshake sent from the gadget to the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ident {
    pub major: u16,
    pub minor: u16,
}

impl Ident {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub fn encode(self) -> [u8; IDENT_LEN] {
        let mut buf = [0u8; IDENT_LEN];
        buf[0..4].copy_from_slice(&IDENT_MAGIC);
        buf[4..6].copy_from_slice(&self.major.to_le_bytes());
        buf[6..8].copy_from_slice(&self.minor.to_le_bytes());
        buf
    }

    pub fn decode(bytes: [u8; IDENT_LEN]) -> Result<Self> {
        if bytes[0..4] != IDENT_MAGIC {
            return Err(ProtoError::InvalidMagic);
        }
        let major = u16::from_le_bytes([bytes[4], bytes[5]]);
        let minor = u16::from_le_bytes([bytes[6], bytes[7]]);
        Ok(Self { major, minor })
    }
}

/// Request message emitted by the gadget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub export_id: u32,
    pub request_id: u32,
    pub op: OpCode,
    pub lba: u64,
    pub num_blocks: u32,
    pub flags: u32,
}

impl Request {
    pub const fn new(
        export_id: u32,
        request_id: u32,
        op: OpCode,
        lba: u64,
        num_blocks: u32,
        flags: u32,
    ) -> Self {
        Self {
            export_id,
            request_id,
            op,
            lba,
            num_blocks,
            flags,
        }
    }

    pub fn encode(self) -> [u8; REQUEST_LEN] {
        let mut buf = [0u8; REQUEST_LEN];
        buf[0] = self.op.into();
        buf[4..8].copy_from_slice(&self.request_id.to_le_bytes());
        buf[8..12].copy_from_slice(&self.export_id.to_le_bytes());
        buf[12..20].copy_from_slice(&self.lba.to_le_bytes());
        buf[20..24].copy_from_slice(&self.num_blocks.to_le_bytes());
        buf[24..28].copy_from_slice(&self.flags.to_le_bytes());
        buf
    }

    pub fn decode(bytes: [u8; REQUEST_LEN]) -> Result<Self> {
        let request_id = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let export_id = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let lba = u64::from_le_bytes([
            bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
        ]);
        let num_blocks = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let flags = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
        let op = OpCode::try_from(bytes[0])?;
        Ok(Self {
            export_id,
            request_id,
            op,
            lba,
            num_blocks,
            flags,
        })
    }
}

impl TryFrom<&[u8]> for Request {
    type Error = ProtoError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != REQUEST_LEN {
            return Err(ProtoError::InvalidLength {
                expected: REQUEST_LEN,
                actual: value.len(),
            });
        }
        let mut buf = [0u8; REQUEST_LEN];
        buf.copy_from_slice(value);
        Self::decode(buf)
    }
}

/// Response message sent back by the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    pub export_id: u32,
    pub request_id: u32,
    pub op: OpCode,
    pub status: u8,
    pub lba: u64,
    pub num_blocks: u32,
    pub flags: u32,
}

impl Response {
    pub const fn new(
        export_id: u32,
        request_id: u32,
        op: OpCode,
        status: u8,
        lba: u64,
        num_blocks: u32,
        flags: u32,
    ) -> Self {
        Self {
            export_id,
            request_id,
            op,
            status,
            lba,
            num_blocks,
            flags,
        }
    }

    pub fn encode(self) -> [u8; RESPONSE_LEN] {
        let mut buf = [0u8; RESPONSE_LEN];
        buf[0] = self.op.into();
        buf[1] = self.status;
        buf[4..8].copy_from_slice(&self.request_id.to_le_bytes());
        buf[8..12].copy_from_slice(&self.export_id.to_le_bytes());
        buf[12..20].copy_from_slice(&self.lba.to_le_bytes());
        buf[20..24].copy_from_slice(&self.num_blocks.to_le_bytes());
        buf[24..28].copy_from_slice(&self.flags.to_le_bytes());
        buf
    }

    pub fn decode(bytes: [u8; RESPONSE_LEN]) -> Result<Self> {
        let request_id = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let export_id = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let lba = u64::from_le_bytes([
            bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
        ]);
        let num_blocks = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let flags = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
        let op = OpCode::try_from(bytes[0])?;
        let status = bytes[1];
        Ok(Self {
            export_id,
            request_id,
            op,
            lba,
            num_blocks,
            flags,
            status,
        })
    }
}

impl TryFrom<&[u8]> for Response {
    type Error = ProtoError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != RESPONSE_LEN {
            return Err(ProtoError::InvalidLength {
                expected: RESPONSE_LEN,
                actual: value.len(),
            });
        }
        let mut buf = [0u8; RESPONSE_LEN];
        buf.copy_from_slice(value);
        Self::decode(buf)
    }
}

/// Heartbeat/status payload returned by the gadget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmooStatusV0 {
    pub version: u16,
    pub flags: u16,
    pub export_count: u32,
    pub session_id: u64,
}

impl SmooStatusV0 {
    /// Create a v0 status payload with the provided flags/count/session.
    pub const fn new(flags: u16, export_count: u32, session_id: u64) -> Self {
        Self {
            version: SMOO_STATUS_VERSION,
            flags,
            export_count,
            session_id,
        }
    }

    /// Serialize the status payload to its on-wire representation.
    pub fn encode(self) -> [u8; SMOO_STATUS_LEN] {
        let mut buf = [0u8; SMOO_STATUS_LEN];
        buf[0..2].copy_from_slice(&self.version.to_le_bytes());
        buf[2..4].copy_from_slice(&self.flags.to_le_bytes());
        buf[4..8].copy_from_slice(&self.export_count.to_le_bytes());
        buf[8..16].copy_from_slice(&self.session_id.to_le_bytes());
        buf
    }

    /// Decode a status payload from a fixed-size buffer.
    pub fn decode(bytes: [u8; SMOO_STATUS_LEN]) -> Result<Self> {
        let version = u16::from_le_bytes([bytes[0], bytes[1]]);
        if version != SMOO_STATUS_VERSION {
            return Err(ProtoError::InvalidVersion {
                expected: SMOO_STATUS_VERSION,
                actual: version,
            });
        }
        let flags = u16::from_le_bytes([bytes[2], bytes[3]]);
        let export_count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let session_id = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        Ok(Self {
            version,
            flags,
            export_count,
            session_id,
        })
    }

    /// Decode a status payload from a borrowed slice.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != SMOO_STATUS_LEN {
            return Err(ProtoError::InvalidLength {
                expected: SMOO_STATUS_LEN,
                actual: slice.len(),
            });
        }
        let mut buf = [0u8; SMOO_STATUS_LEN];
        buf.copy_from_slice(slice);
        Self::decode(buf)
    }

    /// Returns true when the export_active flag is set.
    pub fn export_active(&self) -> bool {
        (self.flags & SMOO_STATUS_FLAG_EXPORT_ACTIVE) != 0
    }
}

/// Encoded CONFIG_EXPORTS payload for protocol version 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigExportsV0 {
    entries: heapless::Vec<ConfigExport, 32>,
}

impl ConfigExportsV0 {
    /// Supported CONFIG_EXPORTS payload version.
    pub const VERSION: u16 = 0;
    /// Number of bytes in the payload header.
    pub const HEADER_LEN: usize = 8;
    /// Number of bytes in each entry.
    pub const ENTRY_LEN: usize = 24;
    /// Maximum exports supported in one payload.
    pub const MAX_EXPORTS: usize = 32;

    pub fn new(entries: heapless::Vec<ConfigExport, 32>) -> Result<Self> {
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[ConfigExport] {
        &self.entries
    }

    pub fn from_slice(entries: &[ConfigExport]) -> Result<Self> {
        let mut vec: heapless::Vec<ConfigExport, 32> = heapless::Vec::new();
        for entry in entries {
            vec.push(*entry)
                .map_err(|_| ProtoError::InvalidValue("too many exports"))?;
        }
        Self::new(vec)
    }

    /// Serialize the payload to its wire representation.
    pub fn encode(
        &self,
    ) -> heapless::Vec<u8, { Self::HEADER_LEN + Self::ENTRY_LEN * Self::MAX_EXPORTS }> {
        let mut buf: heapless::Vec<u8, { Self::HEADER_LEN + Self::ENTRY_LEN * Self::MAX_EXPORTS }> =
            heapless::Vec::new();
        buf.resize(Self::HEADER_LEN + self.entries.len() * Self::ENTRY_LEN, 0)
            .unwrap();
        buf[0..2].copy_from_slice(&Self::VERSION.to_le_bytes());
        buf[2..4].copy_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for (idx, entry) in self.entries.iter().enumerate() {
            let offset = Self::HEADER_LEN + idx * Self::ENTRY_LEN;
            buf[offset..offset + 4].copy_from_slice(&entry.export_id.to_le_bytes());
            buf[offset + 4..offset + 8].copy_from_slice(&entry.block_size.to_le_bytes());
            buf[offset + 8..offset + 16].copy_from_slice(&entry.size_bytes.to_le_bytes());
        }
        buf
    }

    /// Decode a CONFIG_EXPORTS payload from a borrowed slice.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(ProtoError::InvalidLength {
                expected: Self::HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let version = u16::from_le_bytes([bytes[0], bytes[1]]);
        if version != Self::VERSION {
            return Err(ProtoError::InvalidVersion {
                expected: Self::VERSION,
                actual: version,
            });
        }
        let count = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        if count > Self::MAX_EXPORTS {
            return Err(ProtoError::InvalidValue(
                "CONFIG_EXPORTS count exceeds maximum",
            ));
        }
        let flags = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if flags != 0 {
            return Err(ProtoError::InvalidValue(
                "CONFIG_EXPORTS header flags must be zero",
            ));
        }
        let expected_len = Self::HEADER_LEN + count * Self::ENTRY_LEN;
        if bytes.len() != expected_len {
            return Err(ProtoError::InvalidLength {
                expected: expected_len,
                actual: bytes.len(),
            });
        }
        let mut entries: heapless::Vec<ConfigExport, 32> = heapless::Vec::new();
        for idx in 0..count {
            let offset = Self::HEADER_LEN + idx * Self::ENTRY_LEN;
            let export_id = u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            let block_size = u32::from_le_bytes([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
            let size_bytes = u64::from_le_bytes([
                bytes[offset + 8],
                bytes[offset + 9],
                bytes[offset + 10],
                bytes[offset + 11],
                bytes[offset + 12],
                bytes[offset + 13],
                bytes[offset + 14],
                bytes[offset + 15],
            ]);
            entries
                .push(validate_export(export_id, block_size, size_bytes)?)
                .map_err(|_| ProtoError::InvalidValue("too many exports"))?;
        }
        Ok(Self { entries })
    }
}

/// Parameters describing a single export entry in v0 CONFIG_EXPORTS payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigExport {
    pub export_id: u32,
    pub block_size: u32,
    pub size_bytes: u64,
}

fn validate_export(export_id: u32, block_size: u32, size_bytes: u64) -> Result<ConfigExport> {
    if export_id == 0 {
        return Err(ProtoError::InvalidValue("export_id must be non-zero"));
    }
    if !block_size.is_power_of_two() {
        return Err(ProtoError::InvalidValue("block size must be power-of-two"));
    }
    if !(512..=65536).contains(&block_size) {
        return Err(ProtoError::InvalidValue(
            "block size out of supported range",
        ));
    }
    if size_bytes != 0 && !size_bytes.is_multiple_of(block_size as u64) {
        return Err(ProtoError::InvalidValue(
            "size_bytes must be multiple of block_size",
        ));
    }
    Ok(ConfigExport {
        export_id,
        block_size,
        size_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_round_trip() {
        let ident = Ident::new(1, 2);
        let bytes = ident.encode();
        assert_eq!(Ident::decode(bytes).unwrap(), ident);
    }

    #[test]
    fn ident_magic_guard() {
        let mut bytes = Ident::new(1, 2).encode();
        bytes[0] = b'X';
        assert!(matches!(
            Ident::decode(bytes),
            Err(ProtoError::InvalidMagic)
        ));
    }

    #[test]
    fn request_round_trip() {
        let req = Request::new(2, 99, OpCode::Write, 42, 8, 0xAA55AA55);
        let bytes = req.encode();
        assert_eq!(Request::decode(bytes).unwrap(), req);
        assert_eq!(Request::try_from(bytes.as_slice()).unwrap(), req);
    }

    #[test]
    fn response_round_trip() {
        let resp = Response::new(3, 77, OpCode::Read, 0, 9001, 16, 0);
        let bytes = resp.encode();
        assert_eq!(Response::decode(bytes).unwrap(), resp);
        assert_eq!(Response::try_from(bytes.as_slice()).unwrap(), resp);
    }

    #[test]
    fn status_round_trip() {
        let status = SmooStatusV0::new(SMOO_STATUS_FLAG_EXPORT_ACTIVE, 1, 0x0102_0304_0506_0708);
        let bytes = status.encode();
        assert_eq!(SmooStatusV0::try_from_slice(&bytes).unwrap(), status);
        assert!(SmooStatusV0::decode(bytes).unwrap().export_active());
    }

    #[test]
    fn bad_opcode() {
        let mut bytes = Request::new(1, 2, OpCode::Flush, 0, 0, 0).encode();
        bytes[0] = 0xFF;
        assert!(matches!(
            Request::decode(bytes),
            Err(ProtoError::InvalidOpcode(0xFF))
        ));
    }

    #[test]
    fn invalid_len() {
        assert!(matches!(
            Request::try_from(&[0u8; 27][..]),
            Err(ProtoError::InvalidLength {
                expected: 28,
                actual: 27
            })
        ));
    }

    #[test]
    fn config_exports_zero_round_trip() {
        let payload = ConfigExportsV0::new(heapless::Vec::new()).unwrap();
        let encoded = payload.encode();
        let decoded = ConfigExportsV0::try_from_slice(&encoded).unwrap();
        assert!(decoded.entries().is_empty());
    }

    #[test]
    fn config_exports_single_round_trip() {
        let mut entries = heapless::Vec::new();
        entries
            .push(ConfigExport {
                export_id: 7,
                block_size: 4096,
                size_bytes: 4096 * 8,
            })
            .unwrap();
        let payload = ConfigExportsV0::new(entries).unwrap();
        let encoded = payload.encode();
        let decoded = ConfigExportsV0::try_from_slice(&encoded).unwrap();
        let export = decoded.entries().first().unwrap();
        assert_eq!(export.export_id, 7);
        assert_eq!(export.block_size, 4096);
        assert_eq!(export.size_bytes, 4096 * 8);
    }

    #[test]
    fn config_exports_invalid_flags() {
        let mut encoded = ConfigExportsV0::new(heapless::Vec::new()).unwrap().encode();
        encoded[4] = 1;
        assert!(matches!(
            ConfigExportsV0::try_from_slice(&encoded),
            Err(ProtoError::InvalidValue(_))
        ));
    }

    #[test]
    fn config_exports_invalid_block_size() {
        let mut entries = heapless::Vec::new();
        entries
            .push(ConfigExport {
                export_id: 1,
                block_size: 1024,
                size_bytes: 0,
            })
            .unwrap();
        let mut encoded = ConfigExportsV0::new(entries).unwrap().encode();
        encoded[4..8].copy_from_slice(&1u32.to_le_bytes()); // count = 1
        encoded[8..12].copy_from_slice(&500u32.to_le_bytes());
        assert!(matches!(
            ConfigExportsV0::try_from_slice(&encoded),
            Err(ProtoError::InvalidValue(_))
        ));
    }
}
