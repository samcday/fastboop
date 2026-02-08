use alloc::vec::Vec;
use core::cmp;

use crate::image::ReadAt;
use crate::{EroFS, Result, types::Inode};

#[derive(Debug)]
pub struct File<R: ReadAt> {
    inode: Inode,
    erofs: EroFS<R>,
    offset: usize,
    cached_block: Option<(usize, Vec<u8>)>,
}

impl<R: ReadAt> File<R> {
    pub(crate) fn new(inode: Inode, erofs: EroFS<R>) -> Self {
        Self {
            inode,
            erofs,
            offset: 0,
            cached_block: None,
        }
    }

    pub fn size(&self) -> usize {
        self.inode.data_size()
    }

    pub async fn read_into(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.offset >= self.inode.data_size() || buf.is_empty() {
            return Ok(0);
        }

        if let Some((block_start, block)) = &self.cached_block {
            let rel = self.offset.saturating_sub(*block_start);
            if rel < block.len() {
                let n = cmp::min(buf.len(), block.len() - rel);
                buf[..n].copy_from_slice(&block[rel..rel + n]);
                self.offset += n;
                if rel + n >= block.len() {
                    self.cached_block = None;
                }
                return Ok(n);
            }
            self.cached_block = None;
        }

        let block_start = (self.offset / self.erofs.block_size()) * self.erofs.block_size();
        let block = self.erofs.get_inode_block(&self.inode, self.offset).await?;
        let rel = self.offset.saturating_sub(block_start);
        let n = cmp::min(buf.len(), block.len().saturating_sub(rel));
        buf[..n].copy_from_slice(&block[rel..rel + n]);
        self.offset += n;
        if n < block.len().saturating_sub(rel) {
            self.cached_block = Some((block_start, block));
        }
        Ok(n)
    }
}
