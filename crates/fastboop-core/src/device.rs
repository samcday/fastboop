extern crate alloc;

use alloc::boxed::Box;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceEvent {
    Arrived,
    Left,
}

pub trait DeviceWatcher {
    type Error;
    type Handler: 'static;

    fn new(handler: Self::Handler) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

pub type DeviceEventHandler = Box<dyn Fn(DeviceEvent) + 'static>;
