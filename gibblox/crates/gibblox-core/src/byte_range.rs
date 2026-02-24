use alloc::{sync::Arc, vec, vec::Vec};

use crate::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};

#[derive(Clone)]
pub struct ByteRangeReader {
    inner: Arc<dyn BlockReader>,
    block_size: usize,
    size_bytes: u64,
}

impl ByteRangeReader {
    pub fn new(inner: Arc<dyn BlockReader>, block_size: usize, size_bytes: u64) -> Self {
        Self {
            inner,
            block_size,
            size_bytes,
        }
    }

    pub async fn read_vec_at(
        &self,
        offset: u64,
        len: usize,
        ctx: ReadContext,
    ) -> GibbloxResult<Vec<u8>> {
        let mut out = vec![0u8; len];
        self.read_exact_at(offset, &mut out, ctx).await?;
        Ok(out)
    }

    pub async fn read_exact_at(
        &self,
        offset: u64,
        out: &mut [u8],
        ctx: ReadContext,
    ) -> GibbloxResult<()> {
        if out.is_empty() {
            return Ok(());
        }

        let bs = u64::try_from(self.block_size).map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "block size exceeds addressable range",
            )
        })?;
        if bs == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero",
            ));
        }

        let end = offset.checked_add(out.len() as u64).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "range overflow")
        })?;
        if end > self.size_bytes {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "read range exceeds source size",
            ));
        }

        if (offset % bs) == 0 && out.len().is_multiple_of(self.block_size) {
            self.read_full_blocks(offset / bs, out, ctx).await?;
            return Ok(());
        }

        let aligned_start = (offset / bs) * bs;
        let aligned_end = end.div_ceil(bs).checked_mul(bs).ok_or_else(|| {
            GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "aligned read end overflow")
        })?;
        let aligned_len = usize::try_from(aligned_end - aligned_start).map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "aligned read length exceeds addressable memory",
            )
        })?;

        let mut scratch = vec![0u8; aligned_len];
        self.read_full_blocks(aligned_start / bs, &mut scratch, ctx)
            .await?;

        let head = usize::try_from(offset - aligned_start).map_err(|_| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "aligned read head offset exceeds addressable memory",
            )
        })?;
        let tail = head.checked_add(out.len()).ok_or_else(|| {
            GibbloxError::with_message(
                GibbloxErrorKind::OutOfRange,
                "aligned read tail offset overflow",
            )
        })?;

        out.copy_from_slice(&scratch[head..tail]);
        Ok(())
    }

    async fn read_full_blocks(
        &self,
        start_lba: u64,
        out: &mut [u8],
        ctx: ReadContext,
    ) -> GibbloxResult<()> {
        if out.is_empty() {
            return Ok(());
        }
        if self.block_size == 0 {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "block size must be non-zero",
            ));
        }
        if !out.len().is_multiple_of(self.block_size) {
            return Err(GibbloxError::with_message(
                GibbloxErrorKind::InvalidInput,
                "internal byte-range read requested unaligned buffer",
            ));
        }

        let mut filled = 0usize;
        while filled < out.len() {
            let consumed_blocks = filled / self.block_size;
            let lba = start_lba
                .checked_add(consumed_blocks as u64)
                .ok_or_else(|| {
                    GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "lba overflow")
                })?;
            let read = self.inner.read_blocks(lba, &mut out[filled..], ctx).await?;
            if read == 0 {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "unexpected EOF while servicing aligned read",
                ));
            }
            if read > out.len() - filled {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "block source returned more bytes than requested",
                ));
            }
            if read % self.block_size != 0 && filled + read < out.len() {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::Io,
                    "unaligned short read from block source",
                ));
            }
            filled = filled.checked_add(read).ok_or_else(|| {
                GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "aligned read progress overflow",
                )
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
    use std::sync::Mutex;

    use async_trait::async_trait;
    use futures::executor::block_on;

    use crate::{BlockReader, GibbloxError, GibbloxErrorKind, GibbloxResult, ReadContext};

    struct RecordingReader {
        block_size: u32,
        data: Vec<u8>,
        requests: Arc<Mutex<Vec<(u64, usize)>>>,
    }

    #[async_trait]
    impl BlockReader for RecordingReader {
        fn block_size(&self) -> u32 {
            self.block_size
        }

        async fn total_blocks(&self) -> GibbloxResult<u64> {
            Ok(self.data.len().div_ceil(self.block_size as usize) as u64)
        }

        fn write_identity(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
            out.write_str("recording")
        }

        async fn read_blocks(
            &self,
            lba: u64,
            buf: &mut [u8],
            _ctx: ReadContext,
        ) -> GibbloxResult<usize> {
            self.requests
                .lock()
                .expect("lock request log")
                .push((lba, buf.len()));

            let offset = (lba as usize)
                .checked_mul(self.block_size as usize)
                .ok_or_else(|| {
                    GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "offset overflow")
                })?;
            let end = offset.checked_add(buf.len()).ok_or_else(|| {
                GibbloxError::with_message(GibbloxErrorKind::OutOfRange, "range overflow")
            })?;
            if end > self.data.len() {
                return Err(GibbloxError::with_message(
                    GibbloxErrorKind::OutOfRange,
                    "read exceeds backing store",
                ));
            }
            buf.copy_from_slice(&self.data[offset..end]);
            Ok(buf.len())
        }
    }

    #[test]
    fn byte_range_reader_coalesces_unaligned_reads() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let data = patterned_data(1024 * 1024);
        let source: Arc<dyn BlockReader> = Arc::new(RecordingReader {
            block_size: 512,
            data,
            requests: Arc::clone(&requests),
        });
        let reader = super::ByteRangeReader::new(source, 512, 1024 * 1024);

        let mut out = vec![0u8; 64 * 1024];
        block_on(reader.read_exact_at(123, &mut out, ReadContext::FOREGROUND))
            .expect("read unaligned range");

        let calls = requests.lock().expect("lock request log");
        assert_eq!(calls.as_slice(), &[(0, 129 * 512)]);
    }

    #[test]
    fn byte_range_reader_rejects_out_of_bounds_read() {
        let source: Arc<dyn BlockReader> = Arc::new(RecordingReader {
            block_size: 512,
            data: patterned_data(4096),
            requests: Arc::new(Mutex::new(Vec::new())),
        });
        let reader = super::ByteRangeReader::new(source, 512, 4096);

        let mut out = vec![0u8; 32];
        let err = block_on(reader.read_exact_at(4090, &mut out, ReadContext::FOREGROUND))
            .err()
            .expect("out-of-bounds read should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::OutOfRange);
    }

    #[test]
    fn byte_range_reader_rejects_zero_block_size() {
        let source: Arc<dyn BlockReader> = Arc::new(RecordingReader {
            block_size: 512,
            data: patterned_data(4096),
            requests: Arc::new(Mutex::new(Vec::new())),
        });
        let reader = super::ByteRangeReader::new(source, 0, 4096);

        let mut out = vec![0u8; 16];
        let err = block_on(reader.read_exact_at(0, &mut out, ReadContext::FOREGROUND))
            .err()
            .expect("zero block size should fail");
        assert_eq!(err.kind(), GibbloxErrorKind::InvalidInput);
    }

    fn patterned_data(len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for (idx, byte) in out.iter_mut().enumerate() {
            *byte = ((idx * 31) % 251) as u8;
        }
        out
    }
}
