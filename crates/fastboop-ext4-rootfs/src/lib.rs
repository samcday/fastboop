use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use ext4_view::Ext4;
use fastboop_core::RootfsProvider;
use gibblox_core::BlockReader;
use gibblox_file::StdFileBlockReader;
use gibblox_paged_lru::PagedLruBlockReader;

const DEFAULT_BLOCK_SIZE: u32 = 512;

/// RootfsProvider implementation backed by an ext4 filesystem.
/// 
/// SAFETY: ext4-view uses Rc internally which is not thread-safe. We wrap in Mutex
/// and mark as Send/Sync. This is safe for single-threaded access within async contexts
/// (which is our use case - CLI boot flow is single-threaded with blocking I/O).
pub struct Ext4Rootfs {
    ext4: Arc<Mutex<Ext4>>,
    identity: String,
}

// SAFETY: See struct documentation. Safe for single-threaded async usage.
unsafe impl Send for Ext4Rootfs {}
unsafe impl Sync for Ext4Rootfs {}

impl Ext4Rootfs {
    /// Create a new Ext4Rootfs from a BlockReader.
    pub async fn new(reader: Arc<dyn BlockReader>) -> Result<Self> {
        let mut identity = String::new();
        reader.write_identity(&mut identity)?;

        let adapter = GibbloxReadAtAdapter { reader };
        let ext4 = Ext4::load(Box::new(adapter))
            .map_err(|e| anyhow::anyhow!("failed to load ext4 filesystem: {:?}", e))?;

        Ok(Self {
            ext4: Arc::new(Mutex::new(ext4)),
            identity,
        })
    }

    pub fn identity(&self) -> String {
        self.identity.clone()
    }
}

impl RootfsProvider for Ext4Rootfs {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        let ext4 = self.ext4.lock().unwrap();
        ext4.read(path)
            .with_context(|| format!("reading {}", path))
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        let ext4 = self.ext4.lock().unwrap();
        let mut file = ext4
            .open(path)
            .with_context(|| format!("opening {} for range read", path))?;

        file.seek_to(offset)
            .with_context(|| format!("seeking {} to {}", path, offset))?;

        let mut buf = vec![0u8; len];
        file.read_bytes(&mut buf)
            .with_context(|| format!("reading range from {}", path))?;

        Ok(buf)
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        let ext4 = self.ext4.lock().unwrap();
        let entries = ext4
            .read_dir(path)
            .with_context(|| format!("reading directory {}", path))?;

        entries
            .map(|e| {
                let entry = e.map_err(|err| anyhow::anyhow!("reading dir entry: {:?}", err))?;
                let name = entry
                    .file_name()
                    .as_str()
                    .unwrap_or("<invalid utf8>")
                    .to_string();
                Ok(name)
            })
            .collect()
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let ext4 = self.ext4.lock().unwrap();
        Ok(ext4.exists(path).unwrap_or(false))
    }
}

/// Adapter to bridge gibblox BlockReader to ext4-view's Ext4Read trait.
struct GibbloxReadAtAdapter {
    reader: Arc<dyn BlockReader>,
}

impl ext4_view::Ext4Read for GibbloxReadAtAdapter {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if dst.is_empty() {
            return Ok(());
        }

        let block_size = self.reader.block_size() as u64;
        let start_block = start_byte / block_size;
        let block_offset = (start_byte % block_size) as usize;
        let end_byte = start_byte
            .checked_add(dst.len() as u64)
            .ok_or("offset overflow")?;
        let end_block = end_byte.saturating_sub(1) / block_size;
        let block_count = (end_block - start_block + 1) as usize;

        // Aligned read
        if block_offset == 0 && dst.len() == block_size as usize * block_count {
            return pollster::block_on(self.reader.read_blocks(
                start_block,
                dst,
                gibblox_core::ReadContext::FOREGROUND,
            ))
            .map(|_| ())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
        }

        // Misaligned read
        let total_bytes = block_count * self.reader.block_size() as usize;
        let mut scratch = vec![0u8; total_bytes];

        pollster::block_on(self.reader.read_blocks(
            start_block,
            &mut scratch,
            gibblox_core::ReadContext::FOREGROUND,
        ))
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        let copy_len = dst.len().min(total_bytes - block_offset);
        dst[..copy_len].copy_from_slice(&scratch[block_offset..block_offset + copy_len]);

        Ok(())
    }
}

/// Result of opening an ext4 rootfs.
pub struct OpenedExt4Rootfs {
    pub provider: Ext4Rootfs,
    pub reader: Arc<dyn BlockReader>,
    pub size_bytes: u64,
    pub identity: String,
}

/// Open an ext4 rootfs from a local file path.
pub async fn open_ext4_rootfs(path: &str) -> Result<OpenedExt4Rootfs> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("canonicalize {}", path))?;

    let file_reader = StdFileBlockReader::open(&canonical, DEFAULT_BLOCK_SIZE)
        .map_err(|err| anyhow::anyhow!("open ext4 image {}: {err}", canonical.display()))?;
    
    let size_bytes = file_reader.size_bytes();
    let reader: Arc<dyn BlockReader> = Arc::new(file_reader);

    open_ext4_rootfs_from_reader(reader, size_bytes).await
}

/// Open an ext4 rootfs from a BlockReader.
pub async fn open_ext4_rootfs_from_reader(
    reader: Arc<dyn BlockReader>,
    size_bytes: u64,
) -> Result<OpenedExt4Rootfs> {
    let ext4_reader = Arc::new(
        PagedLruBlockReader::new(reader.clone(), Default::default())
            .await
            .map_err(|err| anyhow::anyhow!("initialize paged LRU for ext4 reader: {err}"))?,
    );

    let identity = {
        let mut id = String::new();
        ext4_reader.write_identity(&mut id)?;
        id
    };

    let provider = Ext4Rootfs::new(ext4_reader.clone()).await?;

    Ok(OpenedExt4Rootfs {
        provider,
        reader: ext4_reader,
        size_bytes,
        identity,
    })
}
