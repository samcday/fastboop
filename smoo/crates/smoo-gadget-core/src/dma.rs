use anyhow::{Context, Result, anyhow, ensure};
use dma_heap::HeapKind;
use mmap::MemoryMap;
use nix::{
    ioctl_readwrite, ioctl_write_ptr,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use std::{
    collections::VecDeque,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
};
use tracing::{trace, warn};

const FUNCTIONFS_IOC_MAGIC: u8 = b'g';
const FUNCTIONFS_DMABUF_ATTACH_NR: u8 = 131;
const FUNCTIONFS_DMABUF_DETACH_NR: u8 = 132;
const FUNCTIONFS_DMABUF_TRANSFER_NR: u8 = 133;

#[repr(C, packed)]
struct UsbFfsDmabufTransferReq {
    fd: libc::c_int,
    flags: u32,
    length: u64,
}

ioctl_write_ptr!(
    ffs_dmabuf_attach,
    FUNCTIONFS_IOC_MAGIC,
    FUNCTIONFS_DMABUF_ATTACH_NR,
    libc::c_int
);

ioctl_write_ptr!(
    ffs_dmabuf_detach,
    FUNCTIONFS_IOC_MAGIC,
    FUNCTIONFS_DMABUF_DETACH_NR,
    libc::c_int
);

ioctl_write_ptr!(
    ffs_dmabuf_transfer,
    FUNCTIONFS_IOC_MAGIC,
    FUNCTIONFS_DMABUF_TRANSFER_NR,
    UsbFfsDmabufTransferReq
);

#[repr(C)]
struct dma_buf_export_sync_file_req {
    flags: u32,
    fd: i32,
}

const DMA_BUF_SYNC_READ: u32 = 1 << 0;
const DMA_BUF_SYNC_WRITE: u32 = 1 << 1;
const DMA_BUF_SYNC_RW: u32 = DMA_BUF_SYNC_READ | DMA_BUF_SYNC_WRITE;

ioctl_readwrite!(
    dma_buf_export_sync_file,
    b'b',
    2,
    dma_buf_export_sync_file_req
);

#[repr(C)]
struct DmaBufSync {
    flags: u64,
}

const DMA_BUF_SYNC_NR: u8 = 0;
const DMA_BUF_SYNC_START: u64 = 0 << 2;
const DMA_BUF_SYNC_END: u64 = 1 << 2;
const DMA_BUF_SYNC_READ_FLAG: u64 = 1 << 0;
const DMA_BUF_SYNC_WRITE_FLAG: u64 = 1 << 1;

ioctl_write_ptr!(dma_buf_sync, b'b', DMA_BUF_SYNC_NR, DmaBufSync);

/// Unified pool that hands out DMA-BUF-backed buffers where available, falling back to
/// copy buffers when DMA allocation/attachment fails. Buffers are held for the gadget
/// lifetime; preallocation is attempted but the pool can grow up to `cap`.
pub(crate) struct BufferPool {
    dma: DmaPool,
    copy: CopyPool,
}

// Safe because BufferPool is only accessed behind a Mutex, and its internal raw
// pointers never outlive the pool itself.
unsafe impl Send for BufferPool {}

impl BufferPool {
    pub(crate) fn new(
        bulk_in_fd: RawFd,
        bulk_out_fd: RawFd,
        heap_kind: Option<HeapKind>,
        buf_len: usize,
        prealloc: usize,
        cap: usize,
    ) -> Result<Self> {
        ensure!(buf_len > 0, "buffer length must be positive");
        ensure!(cap > 0, "buffer pool cap must be positive");
        ensure!(prealloc <= cap, "prealloc cannot exceed cap");
        let dma = DmaPool::new(bulk_in_fd, bulk_out_fd, heap_kind, buf_len, prealloc, cap)
            .context("init DMA pool")?;
        let copy = CopyPool::new(buf_len, cap.saturating_sub(dma.len()));
        Ok(Self { dma, copy })
    }

    pub(crate) fn checkout(&mut self) -> BufferHandle {
        if let Some(handle) = self.dma.checkout() {
            return BufferHandle::Dma(handle);
        }
        if let Some(handle) = self.copy.checkout() {
            return BufferHandle::Copy(handle);
        }
        // As a last resort, try to grow DMA then copy.
        if let Some(handle) = self.dma.grow_one() {
            return BufferHandle::Dma(handle);
        }
        BufferHandle::Copy(self.copy.fallback())
    }

    pub(crate) fn checkin(&mut self, handle: BufferHandle) {
        match handle {
            BufferHandle::Dma(buf) => self.dma.checkin(buf),
            BufferHandle::Copy(buf) => self.copy.checkin(buf),
        }
    }
}

pub(crate) enum BufferHandle {
    Dma(DmaBufferHandle),
    Copy(CopyBuffer),
}

unsafe impl Send for BufferHandle {}

impl BufferHandle {
    pub(crate) fn len(&self) -> usize {
        match self {
            BufferHandle::Dma(h) => h.len(),
            BufferHandle::Copy(h) => h.buf.len(),
        }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            BufferHandle::Dma(h) => h.as_mut_slice(),
            BufferHandle::Copy(h) => &mut h.buf,
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            BufferHandle::Dma(h) => h.as_slice(),
            BufferHandle::Copy(h) => &h.buf,
        }
    }

    pub(crate) fn dma_fd(&self) -> Option<RawFd> {
        match self {
            BufferHandle::Dma(h) => Some(h.fd()),
            BufferHandle::Copy(_) => None,
        }
    }

    pub(crate) fn prepare_device_read(&mut self) -> Result<()> {
        match self {
            BufferHandle::Dma(h) => h.prepare_device_read(),
            BufferHandle::Copy(_) => Ok(()),
        }
    }

    pub(crate) fn finish_device_write(&mut self) -> Result<()> {
        match self {
            BufferHandle::Dma(h) => h.finish_device_write(),
            BufferHandle::Copy(_) => Ok(()),
        }
    }
}

pub(crate) fn dmabuf_transfer_blocking(
    endpoint_fd: RawFd,
    buf_fd: RawFd,
    len: usize,
) -> Result<()> {
    let length = u64::try_from(len).context("dma-buf transfer length exceeds u64")?;
    trace!(endpoint_fd, buf_fd, len, "FUNCTIONFS_DMABUF_TRANSFER begin");
    unsafe {
        ffs_dmabuf_transfer(
            endpoint_fd,
            &UsbFfsDmabufTransferReq {
                fd: buf_fd,
                flags: 0,
                length,
            },
        )
    }
    .map_err(|err| anyhow!("FUNCTIONFS_DMABUF_TRANSFER failed: {err}"))?;
    trace!(
        endpoint_fd,
        buf_fd, len, "FUNCTIONFS_DMABUF_TRANSFER submitted"
    );
    wait_for_dmabuf_completion(buf_fd)
}

fn wait_for_dmabuf_completion(dmabuf_fd: RawFd) -> Result<()> {
    trace!(buf_fd = dmabuf_fd, "DMA_BUF_IOCTL_EXPORT_SYNC_FILE begin");
    let sync_fd = unsafe {
        let mut req = dma_buf_export_sync_file_req {
            flags: DMA_BUF_SYNC_RW,
            fd: -1,
        };
        dma_buf_export_sync_file(dmabuf_fd, &mut req)
            .map_err(|err| anyhow!("DMA_BUF_IOCTL_EXPORT_SYNC_FILE failed: {err}"))?;
        ensure!(req.fd >= 0, "sync file descriptor invalid");
        OwnedFd::from_raw_fd(req.fd)
    };
    trace!(
        buf_fd = dmabuf_fd,
        sync_fd = sync_fd.as_raw_fd(),
        "DMA_BUF_IOCTL_EXPORT_SYNC_FILE complete"
    );

    let mut fds = [PollFd::new(sync_fd.as_fd(), PollFlags::POLLIN)];
    loop {
        trace!(
            sync_fd = sync_fd.as_raw_fd(),
            "polling for dma-buf completion"
        );
        match poll(&mut fds, PollTimeout::NONE) {
            Ok(0) => continue,
            Ok(_) => {
                let revents = fds[0].revents().unwrap_or(PollFlags::empty());
                if revents.contains(PollFlags::POLLERR) {
                    return Err(anyhow!("dma-buf completion poll error"));
                }
                if revents.intersects(PollFlags::POLLIN) {
                    break;
                }
            }
            Err(err) => return Err(err.into()),
        }
    }
    trace!(buf_fd = dmabuf_fd, "dma-buf completion fence signaled");
    Ok(())
}

struct DmaPool {
    heap: Option<dma_heap::Heap>,
    bulk_in_fd: RawFd,
    bulk_out_fd: RawFd,
    buf_len: usize,
    cap: usize,
    available: VecDeque<DmaBuffer>,
    allocated: usize,
    dma_disabled: bool,
}

impl DmaPool {
    fn new(
        bulk_in_fd: RawFd,
        bulk_out_fd: RawFd,
        heap_kind: Option<HeapKind>,
        buf_len: usize,
        prealloc: usize,
        cap: usize,
    ) -> Result<Self> {
        let heap = match heap_kind {
            Some(kind) => Some(dma_heap::Heap::new(kind).context("open DMA heap")?),
            None => None,
        };
        let mut pool = Self {
            heap,
            bulk_in_fd,
            bulk_out_fd,
            buf_len,
            cap,
            available: VecDeque::new(),
            allocated: 0,
            dma_disabled: false,
        };
        for _ in 0..prealloc {
            if let Some(buf) = pool.try_allocate_buf() {
                pool.available.push_back(buf);
            } else {
                break;
            }
        }
        Ok(pool)
    }

    fn len(&self) -> usize {
        self.allocated
    }

    fn checkout(&mut self) -> Option<DmaBufferHandle> {
        if self.dma_disabled {
            return None;
        }
        self.available
            .pop_front()
            .map(|buf| DmaBufferHandle { buf })
    }

    fn checkin(&mut self, handle: DmaBufferHandle) {
        self.available.push_back(handle.buf);
    }

    fn grow_one(&mut self) -> Option<DmaBufferHandle> {
        if self.dma_disabled {
            return None;
        }
        if let Some(buf) = self.try_allocate_buf() {
            return Some(DmaBufferHandle { buf });
        }
        None
    }

    fn try_allocate_buf(&mut self) -> Option<DmaBuffer> {
        if self.allocated >= self.cap || self.heap.is_none() {
            return None;
        }
        let heap = self.heap.as_ref()?;
        let fd = match heap.allocate(self.buf_len) {
            Ok(fd) => fd,
            Err(err) => {
                warn!(error = %err, "dma-heap allocation failed, disabling dma");
                self.dma_disabled = true;
                return None;
            }
        };
        match DmaBuffer::new(fd, self.buf_len, self.bulk_in_fd, self.bulk_out_fd) {
            Ok(buf) => {
                self.allocated += 1;
                Some(buf)
            }
            Err(err) => {
                warn!(error = %err, "dma buffer init failed, disabling dma");
                self.dma_disabled = true;
                None
            }
        }
    }
}

struct DmaBuffer {
    fd: OwnedFd,
    map: MemoryMap,
    len: usize,
}

impl DmaBuffer {
    fn new(fd: OwnedFd, len: usize, bulk_in_fd: RawFd, bulk_out_fd: RawFd) -> Result<Self> {
        let raw_fd = fd.as_raw_fd();
        let map = MemoryMap::new(
            len,
            &[
                mmap::MapOption::MapReadable,
                mmap::MapOption::MapWritable,
                mmap::MapOption::MapFd(raw_fd),
                mmap::MapOption::MapNonStandardFlags(libc::MAP_SHARED),
            ],
        )
        .map_err(|err| anyhow!("map DMA buffer: {err}"))?;
        let mut attachments = EndpointAttachments::new(bulk_in_fd);
        attachments.attach(raw_fd)?;
        let mut out_attachments = EndpointAttachments::new(bulk_out_fd);
        out_attachments.attach(raw_fd)?;
        Ok(Self { fd, map, len })
    }

    fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.map.data(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.map.data(), self.len) }
    }
}

pub(crate) struct DmaBufferHandle {
    buf: DmaBuffer,
}

unsafe impl Send for DmaBufferHandle {}

impl DmaBufferHandle {
    pub(crate) fn fd(&self) -> RawFd {
        self.buf.raw_fd()
    }

    pub(crate) fn len(&self) -> usize {
        self.buf.len
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf.as_mut_slice()
    }

    pub(crate) fn prepare_device_read(&mut self) -> Result<()> {
        dma_buf_sync_start(self.fd(), DMA_BUF_SYNC_WRITE_FLAG)?;
        dma_buf_sync_end(self.fd(), DMA_BUF_SYNC_WRITE_FLAG)
    }

    pub(crate) fn finish_device_write(&mut self) -> Result<()> {
        dma_buf_sync_start(self.fd(), DMA_BUF_SYNC_READ_FLAG)?;
        dma_buf_sync_end(self.fd(), DMA_BUF_SYNC_READ_FLAG)
    }
}

struct CopyPool {
    buf_len: usize,
    available: VecDeque<CopyBuffer>,
    cap: usize,
}

impl CopyPool {
    fn new(buf_len: usize, cap: usize) -> Self {
        Self {
            buf_len,
            available: VecDeque::new(),
            cap,
        }
    }

    fn checkout(&mut self) -> Option<CopyBuffer> {
        self.available.pop_front()
    }

    fn checkin(&mut self, buf: CopyBuffer) {
        if self.available.len() < self.cap {
            self.available.push_back(buf);
        }
    }

    fn fallback(&self) -> CopyBuffer {
        CopyBuffer {
            buf: vec![0u8; self.buf_len],
        }
    }
}

pub(crate) struct CopyBuffer {
    buf: Vec<u8>,
}

struct EndpointAttachments {
    fd: RawFd,
    attached: Vec<RawFd>,
}

impl EndpointAttachments {
    fn new(fd: RawFd) -> Self {
        Self {
            fd,
            attached: Vec::new(),
        }
    }

    fn attach(&mut self, buf_fd: RawFd) -> Result<()> {
        trace!(
            endpoint_fd = self.fd,
            buf_fd, "FUNCTIONFS_DMABUF_ATTACH begin"
        );
        unsafe { ffs_dmabuf_attach(self.fd, &buf_fd) }
            .map_err(|err| anyhow!(err))
            .with_context(|| format!("FUNCTIONFS_DMABUF_ATTACH failed for fd {buf_fd}"))?;
        trace!(
            endpoint_fd = self.fd,
            buf_fd, "FUNCTIONFS_DMABUF_ATTACH complete"
        );
        self.attached.push(buf_fd);
        Ok(())
    }

    fn detach_all(&mut self) {
        for buf_fd in self.attached.drain(..) {
            trace!(
                endpoint_fd = self.fd,
                buf_fd, "FUNCTIONFS_DMABUF_DETACH begin"
            );
            let res = unsafe { ffs_dmabuf_detach(self.fd, &buf_fd) };
            match res {
                Ok(_) => trace!(
                    endpoint_fd = self.fd,
                    buf_fd, "FUNCTIONFS_DMABUF_DETACH complete"
                ),
                Err(err) => warn!(
                    endpoint_fd = self.fd,
                    buf_fd,
                    error = %err,
                    "FUNCTIONFS_DMABUF_DETACH failed"
                ),
            }
        }
    }
}

impl Drop for EndpointAttachments {
    fn drop(&mut self) {
        self.detach_all();
    }
}

fn dma_buf_sync_call(fd: RawFd, flags: u64) -> Result<()> {
    let req = DmaBufSync { flags };
    trace!(fd, flags, "DMA_BUF_IOCTL_SYNC begin");
    let res = unsafe { dma_buf_sync(fd, &req) };
    match res {
        Ok(0) => {
            trace!(fd, flags, "DMA_BUF_IOCTL_SYNC complete");
            Ok(())
        }
        Ok(code) => Err(anyhow!("DMA_BUF_IOCTL_SYNC unexpected code {code}")),
        Err(err) => {
            warn!(fd, flags, error = %err, "DMA_BUF_IOCTL_SYNC failed");
            Err(anyhow!("DMA_BUF_IOCTL_SYNC failed: {err}"))
        }
    }
}

fn dma_buf_sync_start(fd: RawFd, dir: u64) -> Result<()> {
    dma_buf_sync_call(fd, DMA_BUF_SYNC_START | dir)
}

fn dma_buf_sync_end(fd: RawFd, dir: u64) -> Result<()> {
    dma_buf_sync_call(fd, DMA_BUF_SYNC_END | dir)
}
