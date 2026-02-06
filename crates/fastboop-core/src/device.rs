extern crate alloc;

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::DeviceProfile;
use crate::fastboot::FastbootWire;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceFilter {
    pub vid: u16,
    pub pid: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceEvent<D> {
    Arrived { device: D },
    Left { device: D },
}

pub trait DeviceHandle: Clone + Send + Sync + 'static {
    type FastbootWire: FastbootWire;
    type OpenFastbootError;

    type OpenFastbootFuture<'a>: Future<Output = Result<Self::FastbootWire, Self::OpenFastbootError>>
        + 'a
    where
        Self: 'a;

    fn vid(&self) -> u16;
    fn pid(&self) -> u16;
    fn open_fastboot<'a>(&'a self) -> Self::OpenFastbootFuture<'a>;
}

pub trait DeviceWatcher {
    type Device: DeviceHandle;
    type Error;

    fn poll_next_event(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<DeviceEvent<Self::Device>, Self::Error>>;

    fn next_event(&mut self) -> NextDeviceEvent<'_, Self>
    where
        Self: Sized + Unpin,
    {
        NextDeviceEvent { watcher: self }
    }

    fn try_next_event(&mut self) -> Poll<Result<DeviceEvent<Self::Device>, Self::Error>>
    where
        Self: Sized + Unpin,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(self).poll_next_event(&mut cx)
    }
}

pub struct NextDeviceEvent<'a, W: DeviceWatcher + Unpin + ?Sized> {
    watcher: &'a mut W,
}

impl<W> Future for NextDeviceEvent<'_, W>
where
    W: DeviceWatcher + Unpin + ?Sized,
{
    type Output = Result<DeviceEvent<W::Device>, W::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.watcher).poll_next_event(cx)
    }
}

pub fn profile_filters(profiles: &[DeviceProfile]) -> Vec<DeviceFilter> {
    let mut filters = Vec::new();
    for profile in profiles {
        for rule in &profile.r#match {
            let filter = DeviceFilter {
                vid: rule.fastboot.vid,
                pid: rule.fastboot.pid,
            };
            if !filters.contains(&filter) {
                filters.push(filter);
            }
        }
    }
    filters
}

fn noop_raw_waker() -> RawWaker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }

    unsafe fn wake(_: *const ()) {}

    unsafe fn wake_by_ref(_: *const ()) {}

    unsafe fn drop(_: *const ()) {}

    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
    RawWaker::new(core::ptr::null(), &VTABLE)
}

fn noop_waker() -> Waker {
    unsafe { Waker::from_raw(noop_raw_waker()) }
}
