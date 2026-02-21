use std::sync::Arc;

use anyhow::{Result, anyhow};
use fastboop_core::{LruBlockReader, PagedBlockReader, RootfsEntryType, RootfsProvider};
use gibblox_core::BlockReader;
use gibblox_ext4::{Ext4EntryType, Ext4Fs};

pub const DEFAULT_IMAGE_BLOCK_SIZE: u32 = 512;

#[derive(Clone)]
pub struct Ext4Rootfs {
    fs: Ext4Fs,
}

impl Ext4Rootfs {
    pub async fn new(reader: Arc<dyn BlockReader>) -> Result<Self> {
        let lru = LruBlockReader::new(reader, Default::default())
            .await
            .map_err(|err| anyhow!("initialize LRU for rootfs reader: {err}"))?;
        let paged = PagedBlockReader::new(lru, Default::default())
            .await
            .map_err(|err| anyhow!("initialize paged reader for rootfs reader: {err}"))?;
        let fs = Ext4Fs::open(paged)
            .await
            .map_err(|err| anyhow!("open ext4 rootfs image: {err}"))?;
        Ok(Self { fs })
    }
}

impl RootfsProvider for Ext4Rootfs {
    type Error = anyhow::Error;

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        self.fs
            .read_all(path)
            .await
            .map_err(|err| anyhow!("read ext4 file {path}: {err}"))
    }

    async fn read_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.fs
            .read_range(path, offset, len)
            .await
            .map_err(|err| anyhow!("read ext4 file range {path}: {err}"))
    }

    async fn read_dir(&self, path: &str) -> Result<Vec<String>> {
        self.fs
            .read_dir(path)
            .await
            .map_err(|err| anyhow!("read ext4 directory {path}: {err}"))
    }

    async fn entry_type(&self, path: &str) -> Result<Option<RootfsEntryType>> {
        let entry_type = self
            .fs
            .entry_type(path)
            .await
            .map_err(|err| anyhow!("read ext4 path type {path}: {err}"))?;

        Ok(entry_type.map(|entry_type| match entry_type {
            Ext4EntryType::File => RootfsEntryType::File,
            Ext4EntryType::Directory => RootfsEntryType::Directory,
            Ext4EntryType::Symlink => RootfsEntryType::Symlink,
            Ext4EntryType::Other => RootfsEntryType::Other,
        }))
    }

    async fn read_link(&self, path: &str) -> Result<String> {
        self.fs
            .read_link(path)
            .await
            .map_err(|err| anyhow!("read ext4 symlink {path}: {err}"))
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        self.fs
            .exists(path)
            .await
            .map_err(|err| anyhow!("check ext4 path {path}: {err}"))
    }
}
