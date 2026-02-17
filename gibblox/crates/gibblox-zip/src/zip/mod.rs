extern crate alloc;

use alloc::string::String;
use gibblox_core::{GibbloxError, GibbloxErrorKind};

pub(crate) mod archive;
pub(crate) mod bytes;
pub(crate) mod records;

pub(crate) type ZipResult<T> = core::result::Result<T, ZipError>;

#[derive(Clone, Debug)]
pub(crate) struct ZipError {
    kind: GibbloxErrorKind,
    message: String,
}

impl ZipError {
    pub(crate) fn new(kind: GibbloxErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(GibbloxErrorKind::InvalidInput, message)
    }

    pub(crate) fn out_of_range(message: impl Into<String>) -> Self {
        Self::new(GibbloxErrorKind::OutOfRange, message)
    }

    pub(crate) fn io(message: impl Into<String>) -> Self {
        Self::new(GibbloxErrorKind::Io, message)
    }

    pub(crate) fn unsupported(message: impl Into<String>) -> Self {
        Self::new(GibbloxErrorKind::Unsupported, message)
    }

    pub(crate) fn kind(&self) -> GibbloxErrorKind {
        self.kind
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl From<ZipError> for GibbloxError {
    fn from(value: ZipError) -> Self {
        GibbloxError::with_message(value.kind(), value.message())
    }
}
