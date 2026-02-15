#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod index;
mod reader;

pub use index::{
    CASYNC_CHUNK_ID_LEN, CasyncChunkId, CasyncChunkRef, CasyncIndex, CasyncIndexValidation,
};
pub use reader::{CasyncBlockReader, CasyncChunkStore, CasyncIndexSource, CasyncReaderConfig};
