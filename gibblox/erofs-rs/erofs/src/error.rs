use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone)]
pub enum Error {
    InvalidSuperblock(String),

    InvalidDirentFileType(u8),

    InvalidLayout(u8),

    PathNotFound(String),

    NotAFile(String),

    NotADirectory(String),

    OutOfBounds(String),

    OutOfRange(usize, usize),

    NotSupported(String),

    CorruptedData(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSuperblock(msg) => write!(f, "invalid super block: {msg}"),
            Self::InvalidDirentFileType(val) => {
                write!(f, "invalid dirent file type: {val}")
            }
            Self::InvalidLayout(val) => write!(f, "invalid layout: {val}"),
            Self::PathNotFound(path) => write!(f, "path not found: {path}"),
            Self::NotAFile(msg) => write!(f, "not a file: {msg}"),
            Self::NotADirectory(msg) => write!(f, "not a directory: {msg}"),
            Self::OutOfBounds(msg) => write!(f, "out of bounds: {msg}"),
            Self::OutOfRange(got, max) => write!(f, "out of range {got} of {max}"),
            Self::NotSupported(msg) => write!(f, "{msg} not supported yet"),
            Self::CorruptedData(msg) => write!(f, "corrupted data: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
