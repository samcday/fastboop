use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::future::Future;
use core::hint;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

pub fn unbounded<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
    let inner = Arc::new(SpinMutex::new(ChannelInner {
        queue: VecDeque::new(),
        sender_count: 1,
        receiver_closed: false,
        receiver_waker: None,
    }));
    (
        UnboundedSender {
            inner: inner.clone(),
        },
        UnboundedReceiver { inner },
    )
}

pub struct UnboundedSender<T> {
    inner: Arc<SpinMutex<ChannelInner<T>>>,
}

impl<T> Clone for UnboundedSender<T> {
    fn clone(&self) -> Self {
        {
            let mut guard = self.inner.lock();
            guard.sender_count = guard.sender_count.saturating_add(1);
        }
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Drop for UnboundedSender<T> {
    fn drop(&mut self) {
        let mut guard = self.inner.lock();
        guard.sender_count = guard.sender_count.saturating_sub(1);
        if guard.sender_count == 0 {
            if let Some(waker) = guard.receiver_waker.take() {
                waker.wake();
            }
        }
    }
}

impl<T> UnboundedSender<T> {
    pub fn unbounded_send(&self, item: T) -> Result<(), SendError<T>> {
        let mut guard = self.inner.lock();
        if guard.receiver_closed {
            return Err(SendError(item));
        }
        guard.queue.push_back(item);
        if let Some(waker) = guard.receiver_waker.take() {
            waker.wake();
        }
        Ok(())
    }
}

pub struct UnboundedReceiver<T> {
    inner: Arc<SpinMutex<ChannelInner<T>>>,
}

impl<T> Drop for UnboundedReceiver<T> {
    fn drop(&mut self) {
        let mut guard = self.inner.lock();
        guard.receiver_closed = true;
        guard.queue.clear();
        guard.receiver_waker = None;
    }
}

impl<T> UnboundedReceiver<T> {
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut guard = self.inner.lock();
        if let Some(item) = guard.queue.pop_front() {
            return Poll::Ready(Some(item));
        }
        if guard.sender_count == 0 {
            return Poll::Ready(None);
        }
        guard.receiver_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    pub fn recv(&mut self) -> Recv<'_, T> {
        Recv { receiver: self }
    }
}

pub struct Recv<'a, T> {
    receiver: &'a mut UnboundedReceiver<T>,
}

impl<T> Future for Recv<'_, T> {
    type Output = Option<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.receiver.poll_recv(cx)
    }
}

pub struct SendError<T>(pub T);

struct ChannelInner<T> {
    queue: VecDeque<T>,
    sender_count: usize,
    receiver_closed: bool,
    receiver_waker: Option<Waker>,
}

struct SpinMutex<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

impl<T> SpinMutex<T> {
    const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    fn lock(&self) -> SpinMutexGuard<'_, T> {
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            hint::spin_loop();
        }
        SpinMutexGuard { lock: self }
    }
}

unsafe impl<T: Send> Send for SpinMutex<T> {}
unsafe impl<T: Send> Sync for SpinMutex<T> {}

struct SpinMutexGuard<'a, T> {
    lock: &'a SpinMutex<T>,
}

impl<T> core::ops::Deref for SpinMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: protected by spin lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> core::ops::DerefMut for SpinMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: protected by spin lock and unique guard.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<T> core::fmt::Debug for SendError<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SendError(..)")
    }
}

impl<T> core::fmt::Display for SendError<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("channel send failed")
    }
}
