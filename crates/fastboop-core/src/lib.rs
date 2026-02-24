#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod block_reader;
pub mod bootimg;
pub mod bootprofile;
pub mod builtin;
pub mod channel_stream;
pub mod device;
pub mod devpro;
pub mod fastboot;
pub mod personalization;
pub mod prober;

use alloc::{string::String, vec::Vec};

pub use block_reader::*;
pub use bootprofile::*;
pub use channel_stream::*;
pub use device::*;
pub use devpro::*;
pub use personalization::*;
pub use prober::*;

/// Newline-separated list of modules to load, in deterministic order.
pub type ModuleLoadList = Vec<String>;
