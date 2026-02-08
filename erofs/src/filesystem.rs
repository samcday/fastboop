use alloc::{format, string::ToString, sync::Arc, vec, vec::Vec};

#[cfg(feature = "std")]
use memmap2::Mmap;

#[cfg(feature = "std")]
use std::path::{Component, Path};

use core::convert::TryInto;

use spin::Mutex;

use crate::dirent;
use crate::file::File;
use crate::image::ReadAt;
use crate::read::ReadCursor;
use crate::types::*;
use crate::{Error, Result};

#[derive(Debug)]
pub struct EroFS<R: ReadAt> {
    reader: Arc<R>,
    image_size: u64,
    super_block: SuperBlock,
    block_size: usize,
    compressed_cache: Arc<Mutex<Option<CompressedExtentCache>>>,
}

impl<R: ReadAt> Clone for EroFS<R> {
    fn clone(&self) -> Self {
        Self {
            reader: Arc::clone(&self.reader),
            image_size: self.image_size,
            super_block: self.super_block,
            block_size: self.block_size,
            compressed_cache: Arc::clone(&self.compressed_cache),
        }
    }
}

impl<R: ReadAt> EroFS<R> {
    pub async fn from_image(reader: R, image_size: u64) -> Result<Self> {
        let reader = Arc::new(reader);
        let mut sb_buf = vec![0u8; SuperBlock::size()];
        read_exact_at(
            reader.as_ref(),
            image_size,
            SUPER_BLOCK_OFFSET as u64,
            &mut sb_buf,
        )
        .await?;
        let super_block = SuperBlock::read_from(&sb_buf)?;

        if super_block.magic != MAGIC_NUMBER {
            return Err(Error::InvalidSuperblock(format!(
                "invalid magic number: 0x{:x}",
                super_block.magic
            )));
        }
        if !(9..=24).contains(&super_block.blk_size_bits) {
            return Err(Error::InvalidSuperblock(format!(
                "invalid block size bits: {}",
                super_block.blk_size_bits
            )));
        }

        Ok(Self {
            reader,
            image_size,
            super_block,
            block_size: (1u64 << super_block.blk_size_bits) as usize,
            compressed_cache: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(feature = "std")]
    pub async fn new(mmap: Mmap) -> Result<EroFS<Arc<Mmap>>> {
        let arc = Arc::new(mmap);
        let size = arc.len() as u64;
        EroFS::from_image(arc, size).await
    }

    pub fn super_block(&self) -> &SuperBlock {
        &self.super_block
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    pub async fn open_path(&self, path: &str) -> Result<File<R>> {
        let inode = self
            .get_path_inode_str(path)
            .await?
            .ok_or_else(|| Error::PathNotFound(path.to_string()))?;
        self.open_inode_file(inode).await
    }

    #[cfg(feature = "std")]
    pub async fn open<P: AsRef<Path>>(&self, path: P) -> Result<File<R>> {
        let inode = self
            .get_path_inode(path.as_ref())
            .await?
            .ok_or_else(|| Error::PathNotFound(path.as_ref().to_string_lossy().into_owned()))?;
        self.open_inode_file(inode).await
    }

    #[cfg(not(feature = "std"))]
    pub async fn open_str<P: AsRef<str>>(&self, path: P) -> Result<File<R>> {
        self.open_path(path.as_ref()).await
    }

    pub async fn open_inode_file(&self, inode: Inode) -> Result<File<R>> {
        if !inode.is_file() {
            return Err(Error::NotAFile(format!(
                "inode {} is not a regular file",
                inode.id()
            )));
        }
        Ok(File::new(inode, self.clone()))
    }

    pub async fn get_inode(&self, nid: u64) -> Result<Inode> {
        let offset = self.get_inode_offset(nid);
        let mut layout_buf = [0u8; 2];
        read_exact_at(
            self.reader.as_ref(),
            self.image_size,
            offset,
            &mut layout_buf,
        )
        .await?;
        let layout = u16::from_le_bytes(layout_buf);
        if Inode::is_compact_format(layout) {
            let mut inode_buf = vec![0u8; InodeCompact::size()];
            read_exact_at(
                self.reader.as_ref(),
                self.image_size,
                offset,
                &mut inode_buf,
            )
            .await?;
            Ok(Inode::Compact((nid, InodeCompact::read_from(&inode_buf)?)))
        } else {
            let mut inode_buf = vec![0u8; InodeExtended::size()];
            read_exact_at(
                self.reader.as_ref(),
                self.image_size,
                offset,
                &mut inode_buf,
            )
            .await?;
            Ok(Inode::Extended((
                nid,
                InodeExtended::read_from(&inode_buf)?,
            )))
        }
    }

    pub async fn read_inode_range(
        &self,
        inode: &Inode,
        file_offset: usize,
        out: &mut [u8],
    ) -> Result<usize> {
        if out.is_empty() || file_offset >= inode.data_size() {
            return Ok(0);
        }

        if matches!(
            inode.layout()?,
            Layout::CompressedFull | Layout::CompressedCompact
        ) {
            return self
                .read_compressed_inode_range(inode, file_offset, out)
                .await;
        }

        let mut written = 0usize;
        let mut offset = file_offset;
        while written < out.len() && offset < inode.data_size() {
            let block = self.get_inode_block(inode, offset).await?;
            let in_block = offset % self.block_size;
            let available = block.len().saturating_sub(in_block);
            let n = (out.len() - written).min(available);
            out[written..written + n].copy_from_slice(&block[in_block..in_block + n]);
            written += n;
            offset += n;
        }

        Ok(written)
    }

    pub(crate) async fn get_inode_block(&self, inode: &Inode, offset: usize) -> Result<Vec<u8>> {
        match inode.layout()? {
            Layout::FlatPlain => {
                let block_count = inode.data_size().div_ceil(self.block_size);
                let block_index = offset / self.block_size;
                if block_index >= block_count {
                    return Err(Error::OutOfRange(block_index, block_count));
                }
                let start = self
                    .block_offset(inode.raw_block_addr())
                    .checked_add((block_index * self.block_size) as u64)
                    .ok_or_else(|| Error::OutOfBounds("inode block offset overflow".to_string()))?;
                let len =
                    (inode.data_size() - (block_index * self.block_size)).min(self.block_size);
                let mut out = vec![0u8; len];
                read_exact_at(self.reader.as_ref(), self.image_size, start, &mut out).await?;
                Ok(out)
            }
            Layout::FlatInline => {
                let block_count = inode.data_size().div_ceil(self.block_size);
                let block_index = offset / self.block_size;
                if block_index >= block_count {
                    return Err(Error::OutOfRange(block_index, block_count));
                }

                if block_count != 0 && block_index == block_count - 1 {
                    let start = self
                        .get_inode_offset(inode.id())
                        .checked_add((inode.size() + inode.xattr_size()) as u64)
                        .ok_or_else(|| {
                            Error::OutOfBounds("inode tail offset overflow".to_string())
                        })?;
                    let len = inode.data_size() % self.block_size;
                    let mut out = vec![0u8; len];
                    read_exact_at(self.reader.as_ref(), self.image_size, start, &mut out).await?;
                    return Ok(out);
                }

                let start = self
                    .block_offset(inode.raw_block_addr())
                    .checked_add((block_index * self.block_size) as u64)
                    .ok_or_else(|| Error::OutOfBounds("inode block offset overflow".to_string()))?;
                let len =
                    (inode.data_size() - (block_index * self.block_size)).min(self.block_size);
                let mut out = vec![0u8; len];
                read_exact_at(self.reader.as_ref(), self.image_size, start, &mut out).await?;
                Ok(out)
            }
            Layout::CompressedFull | Layout::CompressedCompact => {
                Err(Error::NotSupported("compressed compact layout".to_string()))
            }
            Layout::ChunkBased => {
                let chunk_format = ChunkBasedFormat::new(inode.raw_block_addr());
                if !chunk_format.is_valid() {
                    return Err(Error::CorruptedData(format!(
                        "invalid chunk based format {}",
                        inode.raw_block_addr()
                    )));
                }
                if chunk_format.is_indexes() {
                    return Err(Error::NotSupported(
                        "chunk based format with indexes".to_string(),
                    ));
                }

                let chunk_bits = chunk_format.chunk_size_bits() + self.super_block.blk_size_bits;
                let chunk_size = 1usize << chunk_bits;
                let chunk_count = inode.data_size().div_ceil(chunk_size);
                let chunk_index = offset >> chunk_bits;
                let chunk_fixed = (offset % chunk_size) / self.block_size;
                if chunk_index >= chunk_count {
                    return Err(Error::OutOfRange(chunk_index, chunk_count));
                }

                let addr_offset = self
                    .get_inode_offset(inode.id())
                    .checked_add((inode.size() + inode.xattr_size() + (chunk_index * 4)) as u64)
                    .ok_or_else(|| Error::OutOfBounds("chunk addr offset overflow".to_string()))?;
                let mut addr_buf = [0u8; 4];
                read_exact_at(
                    self.reader.as_ref(),
                    self.image_size,
                    addr_offset,
                    &mut addr_buf,
                )
                .await?;
                let chunk_addr = i32::from_le_bytes(addr_buf);
                if chunk_addr <= 0 {
                    return Err(Error::CorruptedData(
                        "sparse chunks are not supported".to_string(),
                    ));
                }

                let len = if chunk_index == chunk_count - 1 {
                    inode.data_size() % self.block_size
                } else {
                    self.block_size
                };
                let start = self.block_offset(chunk_addr as u32 + chunk_fixed as u32);
                let mut out = vec![0u8; len];
                read_exact_at(self.reader.as_ref(), self.image_size, start, &mut out).await?;
                Ok(out)
            }
        }
    }

    async fn read_compressed_inode_range(
        &self,
        inode: &Inode,
        file_offset: usize,
        out: &mut [u8],
    ) -> Result<usize> {
        let meta = self.read_compressed_map_header(inode).await?;
        let mut written = 0usize;
        let mut offset = file_offset;
        while written < out.len() && offset < inode.data_size() {
            let extent = self.map_compressed_extent(inode, &meta, offset).await?;
            let in_extent = offset.saturating_sub(extent.logical_start);
            let available = extent.logical_len.saturating_sub(in_extent);
            let n = (out.len() - written).min(available);
            if n == 0 {
                break;
            }

            if extent.encoded {
                let data = self
                    .get_or_decode_extent_data(inode.id(), &meta, &extent)
                    .await?;
                let end = in_extent + n;
                out[written..written + n].copy_from_slice(&data[in_extent..end]);
            } else {
                let read_offset = extent
                    .physical_offset
                    .checked_add(in_extent as u64)
                    .ok_or_else(|| Error::OutOfBounds("plain extent read overflow".to_string()))?;
                read_exact_at(
                    self.reader.as_ref(),
                    self.image_size,
                    read_offset,
                    &mut out[written..written + n],
                )
                .await?;
            }
            written += n;
            offset += n;
        }
        Ok(written)
    }

    async fn get_or_decode_extent_data(
        &self,
        inode_id: u64,
        meta: &CompressedMapMeta,
        extent: &CompressedExtent,
    ) -> Result<Arc<Vec<u8>>> {
        {
            let guard = self.compressed_cache.lock();
            if let Some(cache) = &*guard
                && cache.inode_id == inode_id
                && cache.logical_start == extent.logical_start
                && cache.logical_len == extent.logical_len
            {
                return Ok(Arc::clone(&cache.data));
            }
        }

        let mut compressed = vec![0u8; extent.physical_len];
        read_exact_at(
            self.reader.as_ref(),
            self.image_size,
            extent.physical_offset,
            &mut compressed,
        )
        .await?;

        let out = match extent.algorithm {
            Z_EROFS_COMPRESSION_LZ4 => {
                if (self.super_block.feature_incompat & FEATURE_INCOMPAT_ZERO_PADDING) != 0 {
                    let first_non_zero =
                        compressed.iter().position(|b| *b != 0).ok_or_else(|| {
                            Error::CorruptedData(
                                "compressed extent has only zero padding".to_string(),
                            )
                        })?;
                    if first_non_zero > 0 {
                        compressed.drain(..first_non_zero);
                    }
                }
                let mut out = vec![0u8; extent.logical_len];
                let decoded = lz4_flex::block::decompress_into(&compressed, &mut out)
                    .map_err(|err| Error::CorruptedData(format!("lz4 decompress failed: {err}")))?;
                if decoded != extent.logical_len {
                    return Err(Error::CorruptedData(format!(
                        "lz4 decoded length mismatch {} != {}",
                        decoded, extent.logical_len
                    )));
                }
                out
            }
            Z_EROFS_COMPRESSION_DEFLATE => {
                let out = miniz_oxide::inflate::decompress_to_vec_with_limit(
                    &compressed,
                    extent.logical_len,
                )
                .map_err(|err| Error::CorruptedData(format!("deflate decompress failed: {err}")))?;
                if out.len() != extent.logical_len {
                    return Err(Error::CorruptedData(format!(
                        "deflate decoded length mismatch {} != {}",
                        out.len(),
                        extent.logical_len
                    )));
                }
                out
            }
            _ => {
                return Err(Error::NotSupported(format!(
                    "compression algorithm {}",
                    extent.algorithm
                )));
            }
        };

        let data = Arc::new(out);
        let mut guard = self.compressed_cache.lock();
        *guard = Some(CompressedExtentCache {
            inode_id,
            logical_start: extent.logical_start,
            logical_len: extent.logical_len,
            data: Arc::clone(&data),
        });
        drop(guard);
        let _ = meta;
        Ok(data)
    }

    async fn read_compressed_map_header(&self, inode: &Inode) -> Result<CompressedMapMeta> {
        let inode_end = self
            .get_inode_offset(inode.id())
            .checked_add((inode.size() + inode.xattr_size()) as u64)
            .ok_or_else(|| Error::OutOfBounds("inode metadata end overflow".to_string()))?;
        let map_header_offset = align8(inode_end);
        let mut map_header_buf = [0u8; MapHeader::size()];
        read_exact_at(
            self.reader.as_ref(),
            self.image_size,
            map_header_offset,
            &mut map_header_buf,
        )
        .await?;
        let map_header = MapHeader::read_from(&map_header_buf)?;
        if map_header.packed_inode() {
            return Err(Error::NotSupported(
                "packed inode compressed layout".to_string(),
            ));
        }
        if matches!(inode.layout()?, Layout::CompressedFull)
            && (map_header.advise & Z_EROFS_ADVISE_EXTENTS) != 0
        {
            return Err(Error::NotSupported(
                "compressed extents metadata layout".to_string(),
            ));
        }
        if (map_header.advise & Z_EROFS_ADVISE_FRAGMENT_PCLUSTER) != 0 {
            return Err(Error::NotSupported(
                "compressed fragment pcluster layout".to_string(),
            ));
        }
        if (map_header.advise & Z_EROFS_ADVISE_INLINE_PCLUSTER) != 0 {
            return Err(Error::NotSupported(
                "compressed inline pcluster layout".to_string(),
            ));
        }

        Ok(CompressedMapMeta {
            map_header,
            map_header_end: map_header_offset + MapHeader::size() as u64,
            lclusterbits: map_header.lclusterbits(self.super_block.blk_size_bits),
        })
    }

    async fn map_compressed_extent(
        &self,
        inode: &Inode,
        meta: &CompressedMapMeta,
        file_offset: usize,
    ) -> Result<CompressedExtent> {
        let lcluster_size = 1usize << meta.lclusterbits;
        let total_lclusters = inode.data_size().div_ceil(lcluster_size);
        let initial_lcn = file_offset >> meta.lclusterbits;
        if initial_lcn >= total_lclusters {
            return Err(Error::OutOfRange(initial_lcn, total_lclusters));
        }
        let endoff = file_offset & (lcluster_size - 1);

        let initial = self
            .load_lcluster(inode, meta, total_lclusters, initial_lcn, false)
            .await?;
        let map_la: usize;
        let end: usize;
        let head_lcn: usize;
        let head_rec: LclusterRecord;

        if initial.kind != Z_EROFS_LCLUSTER_TYPE_NONHEAD && endoff >= initial.clusterofs {
            head_lcn = initial.lcn;
            head_rec = initial;
            map_la = (head_lcn << meta.lclusterbits) | head_rec.clusterofs;
            end = ((head_lcn + 1) << meta.lclusterbits).min(inode.data_size());
        } else {
            end = if initial.kind != Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                (initial.lcn << meta.lclusterbits) | initial.clusterofs
            } else {
                ((initial.lcn + 1) << meta.lclusterbits).min(inode.data_size())
            };

            let mut lookback = if initial.kind == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                initial.delta0 as usize
            } else {
                1usize
            };
            let mut lcn = initial.lcn;
            loop {
                if lookback == 0 || lcn < lookback {
                    return Err(Error::CorruptedData(
                        "invalid compressed lcluster lookback".to_string(),
                    ));
                }
                lcn -= lookback;
                let rec = self
                    .load_lcluster(inode, meta, total_lclusters, lcn, false)
                    .await?;
                if rec.kind == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                    lookback = rec.delta0 as usize;
                    continue;
                }
                head_lcn = lcn;
                head_rec = rec;
                map_la = (head_lcn << meta.lclusterbits) | head_rec.clusterofs;
                break;
            }
        }

        let mut next_lcn = head_lcn.saturating_add(1);
        let logical_len = loop {
            let logical = next_lcn << meta.lclusterbits;
            if logical >= inode.data_size() {
                break inode.data_size().saturating_sub(map_la);
            }
            let rec = self
                .load_lcluster(inode, meta, total_lclusters, next_lcn, true)
                .await?;
            if rec.kind != Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                let next_head_la = (next_lcn << meta.lclusterbits) | rec.clusterofs;
                break next_head_la.saturating_sub(map_la);
            }
            let step = rec.delta1.max(1) as usize;
            next_lcn = next_lcn.saturating_add(step);
        };

        if logical_len == 0 {
            return Err(Error::CorruptedData(
                "zero-sized compressed extent".to_string(),
            ));
        }

        let head_kind = head_rec.kind;
        let big_1 = (meta.map_header.advise & Z_EROFS_ADVISE_BIG_PCLUSTER_1) != 0;
        let big_2 = (meta.map_header.advise & Z_EROFS_ADVISE_BIG_PCLUSTER_2) != 0;
        let mut compressed_blocks = 1usize;
        let head_next_at_eof = ((head_lcn + 1) << meta.lclusterbits) >= inode.data_size();
        if !head_next_at_eof
            && !((head_kind == Z_EROFS_LCLUSTER_TYPE_HEAD1 && !big_1)
                || ((head_kind == Z_EROFS_LCLUSTER_TYPE_PLAIN
                    || head_kind == Z_EROFS_LCLUSTER_TYPE_HEAD2)
                    && !big_2))
        {
            let next = self
                .load_lcluster(inode, meta, total_lclusters, head_lcn + 1, false)
                .await?;
            if next.kind == Z_EROFS_LCLUSTER_TYPE_NONHEAD
                && next.delta0 == 1
                && next.compressedblks > 0
            {
                compressed_blocks = next.compressedblks as usize;
            }
        }

        let algorithm = if head_kind == Z_EROFS_LCLUSTER_TYPE_HEAD2 {
            meta.map_header.algorithm_head2()
        } else {
            meta.map_header.algorithm_head1()
        };

        let physical_offset = self.block_offset(head_rec.pblk);
        let physical_len = compressed_blocks
            .checked_mul(self.block_size)
            .ok_or_else(|| Error::OutOfBounds("compressed physical length overflow".to_string()))?;

        if map_la >= inode.data_size() {
            return Err(Error::OutOfRange(map_la, inode.data_size()));
        }
        let _ = end;
        Ok(CompressedExtent {
            logical_start: map_la,
            logical_len,
            physical_offset,
            physical_len,
            algorithm,
            encoded: head_kind != Z_EROFS_LCLUSTER_TYPE_PLAIN,
        })
    }

    async fn load_lcluster(
        &self,
        inode: &Inode,
        meta: &CompressedMapMeta,
        total_lclusters: usize,
        lcn: usize,
        lookahead: bool,
    ) -> Result<LclusterRecord> {
        match inode.layout()? {
            Layout::CompressedFull => self.load_full_lcluster(meta, total_lclusters, lcn).await,
            Layout::CompressedCompact => {
                self.load_compact_lcluster(meta, total_lclusters, lcn, lookahead)
                    .await
            }
            _ => Err(Error::InvalidLayout(0xff)),
        }
    }

    async fn load_full_lcluster(
        &self,
        meta: &CompressedMapMeta,
        total_lclusters: usize,
        lcn: usize,
    ) -> Result<LclusterRecord> {
        if lcn >= total_lclusters {
            return Err(Error::OutOfRange(lcn, total_lclusters));
        }
        let pos = meta
            .map_header_end
            .checked_add(8)
            .and_then(|x| x.checked_add((lcn * 8) as u64))
            .ok_or_else(|| Error::OutOfBounds("full index position overflow".to_string()))?;
        let mut buf = [0u8; 8];
        read_exact_at(self.reader.as_ref(), self.image_size, pos, &mut buf).await?;
        let mut c = ReadCursor::new(&buf);
        let advise = c.read_u16_le()?;
        let clusterofs = c.read_u16_le()?;
        let a = c.read_u16_le()?;
        let b = c.read_u16_le()?;
        let kind = (advise & Z_EROFS_LI_LCLUSTER_TYPE_MASK) as u8;
        let mut rec = LclusterRecord {
            lcn,
            kind,
            clusterofs: clusterofs as usize,
            delta0: 0,
            delta1: 0,
            pblk: 0,
            compressedblks: 0,
        };
        if kind == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
            rec.clusterofs = 1usize << meta.lclusterbits;
            rec.delta0 = a;
            if (rec.delta0 & Z_EROFS_LI_D0_CBLKCNT) != 0 {
                rec.compressedblks = rec.delta0 & !Z_EROFS_LI_D0_CBLKCNT;
                rec.delta0 = 1;
            }
            rec.delta1 = b;
        } else {
            rec.pblk = u32::from(a) | (u32::from(b) << 16);
        }
        Ok(rec)
    }

    async fn load_compact_lcluster(
        &self,
        meta: &CompressedMapMeta,
        total_lclusters: usize,
        mut lcn: usize,
        lookahead: bool,
    ) -> Result<LclusterRecord> {
        let original_lcn = lcn;
        if lcn >= total_lclusters || meta.lclusterbits > 14 {
            return Err(Error::OutOfRange(lcn, total_lclusters));
        }

        let ebase = meta.map_header_end;
        let compacted_4b_initial = ((32 - (ebase as usize % 32)) / 4) & 7;
        let compacted_2b = if (meta.map_header.advise & Z_EROFS_ADVISE_COMPACTED_2B) != 0
            && compacted_4b_initial < total_lclusters
        {
            (total_lclusters - compacted_4b_initial) & !15
        } else {
            0usize
        };

        let mut pos = ebase;
        let mut amortizedshift = 2usize;
        if lcn >= compacted_4b_initial {
            pos = pos
                .checked_add((compacted_4b_initial * 4) as u64)
                .ok_or_else(|| Error::OutOfBounds("compact index overflow".to_string()))?;
            lcn -= compacted_4b_initial;
            if lcn < compacted_2b {
                amortizedshift = 1;
            } else {
                pos = pos
                    .checked_add((compacted_2b * 2) as u64)
                    .ok_or_else(|| Error::OutOfBounds("compact index overflow".to_string()))?;
                lcn -= compacted_2b;
            }
        }
        pos = pos
            .checked_add((lcn << amortizedshift) as u64)
            .ok_or_else(|| Error::OutOfBounds("compact index overflow".to_string()))?;

        let vcnt = if (1usize << amortizedshift) == 4 && meta.lclusterbits <= 14 {
            2usize
        } else if (1usize << amortizedshift) == 2 && meta.lclusterbits <= 12 {
            16usize
        } else {
            return Err(Error::NotSupported("compact index format".to_string()));
        };

        let pack_size = vcnt << amortizedshift;
        let pack_base = (pos as usize) & !(pack_size - 1);
        let bytes = (pos as usize) & (pack_size - 1);
        let mut pack = vec![0u8; pack_size];
        read_exact_at(
            self.reader.as_ref(),
            self.image_size,
            pack_base as u64,
            &mut pack,
        )
        .await?;

        let i = bytes >> amortizedshift;
        let lobits = usize::from(meta.lclusterbits.max(12));
        let encodebits = ((pack_size - 4) * 8) / vcnt;
        let (mut lo, kind) = decode_compactedbits(lobits, &pack, encodebits * i)?;

        let mut rec = LclusterRecord {
            lcn: original_lcn,
            kind,
            clusterofs: lo,
            delta0: 0,
            delta1: 0,
            pblk: 0,
            compressedblks: 0,
        };

        if kind == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
            rec.clusterofs = 1usize << meta.lclusterbits;
            if lookahead {
                rec.delta1 =
                    compacted_lookahead_distance(lobits, encodebits, vcnt, &pack, i)? as u16;
            }
            if (lo as u16 & Z_EROFS_LI_D0_CBLKCNT) != 0 {
                rec.compressedblks = (lo as u16) & !Z_EROFS_LI_D0_CBLKCNT;
                rec.delta0 = 1;
                return Ok(rec);
            }
            if i + 1 != vcnt {
                rec.delta0 = lo as u16;
                return Ok(rec);
            }
            let (prev_lo, prev_kind) = decode_compactedbits(lobits, &pack, encodebits * (i - 1))?;
            lo = if prev_kind != Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                0
            } else if (prev_lo as u16 & Z_EROFS_LI_D0_CBLKCNT) != 0 {
                1
            } else {
                prev_lo
            };
            rec.delta0 = (lo + 1) as u16;
            return Ok(rec);
        }

        let big_pcluster = (meta.map_header.advise & Z_EROFS_ADVISE_BIG_PCLUSTER_1) != 0;
        let mut nblk = 0u32;
        let mut j = i as isize;
        if !big_pcluster {
            nblk = 1;
            while j > 0 {
                j -= 1;
                let (xlo, xtype) = decode_compactedbits(lobits, &pack, encodebits * j as usize)?;
                if xtype == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                    j -= xlo as isize;
                }
                if j >= 0 {
                    nblk = nblk.saturating_add(1);
                }
            }
        } else {
            while j > 0 {
                j -= 1;
                let (xlo, xtype) = decode_compactedbits(lobits, &pack, encodebits * j as usize)?;
                if xtype == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                    if (xlo as u16 & Z_EROFS_LI_D0_CBLKCNT) != 0 {
                        j -= 1;
                        nblk = nblk.saturating_add((xlo as u32) & !(Z_EROFS_LI_D0_CBLKCNT as u32));
                        continue;
                    }
                    if xlo <= 1 {
                        return Err(Error::CorruptedData(
                            "invalid compact big pcluster delta".to_string(),
                        ));
                    }
                    j -= (xlo - 2) as isize;
                    continue;
                }
                nblk = nblk.saturating_add(1);
            }
        }
        let base = u32::from_le_bytes(
            pack[pack_size - 4..pack_size]
                .try_into()
                .map_err(|_| Error::CorruptedData("invalid compact block base".to_string()))?,
        );
        rec.pblk = base.saturating_add(nblk);
        Ok(rec)
    }

    #[cfg(feature = "std")]
    pub async fn get_path_inode(&self, path: &Path) -> Result<Option<Inode>> {
        let mut nid = self.super_block.root_nid as u64;
        'outer: for part in path.components() {
            if part == Component::RootDir {
                continue;
            }
            let inode = self.get_inode(nid).await?;
            let block_count = inode.data_size().div_ceil(self.block_size);
            if block_count == 0 {
                return Ok(None);
            }
            for i in 0..block_count {
                let block = self.get_inode_block(&inode, i * self.block_size).await?;
                if let Some(found_nid) = dirent::find_nodeid_by_name(part.as_os_str(), &block)? {
                    nid = found_nid;
                    continue 'outer;
                }
            }
            return Ok(None);
        }
        Ok(Some(self.get_inode(nid).await?))
    }

    #[cfg(feature = "std")]
    pub async fn get_path_inode_str(&self, path: &str) -> Result<Option<Inode>> {
        self.get_path_inode(Path::new(path)).await
    }

    #[cfg(not(feature = "std"))]
    pub async fn get_path_inode_str(&self, path: &str) -> Result<Option<Inode>> {
        let mut nid = self.super_block.root_nid as u64;
        'outer: for part in path.split('/') {
            if part.is_empty() || part == "." {
                continue;
            }
            let inode = self.get_inode(nid).await?;
            let block_count = inode.data_size().div_ceil(self.block_size);
            if block_count == 0 {
                return Ok(None);
            }
            for i in 0..block_count {
                let block = self.get_inode_block(&inode, i * self.block_size).await?;
                if let Some(found_nid) = dirent::find_nodeid_by_name(part, &block)? {
                    nid = found_nid;
                    continue 'outer;
                }
            }
            return Ok(None);
        }
        Ok(Some(self.get_inode(nid).await?))
    }

    fn get_inode_offset(&self, nid: u64) -> u64 {
        self.block_offset(self.super_block.meta_blk_addr) + (nid * InodeCompact::size() as u64)
    }

    fn block_offset(&self, block: u32) -> u64 {
        (block as u64) << self.super_block.blk_size_bits
    }
}

#[derive(Debug, Clone)]
struct CompressedExtent {
    logical_start: usize,
    logical_len: usize,
    physical_offset: u64,
    physical_len: usize,
    algorithm: u8,
    encoded: bool,
}

#[derive(Debug)]
struct CompressedExtentCache {
    inode_id: u64,
    logical_start: usize,
    logical_len: usize,
    data: Arc<Vec<u8>>,
}

#[derive(Debug, Clone, Copy)]
struct CompressedMapMeta {
    map_header: MapHeader,
    map_header_end: u64,
    lclusterbits: u8,
}

#[derive(Debug, Clone, Copy)]
struct LclusterRecord {
    lcn: usize,
    kind: u8,
    clusterofs: usize,
    delta0: u16,
    delta1: u16,
    pblk: u32,
    compressedblks: u16,
}

fn align8(x: u64) -> u64 {
    (x + 7) & !7
}

fn decode_compactedbits(lobits: usize, input: &[u8], pos: usize) -> Result<(usize, u8)> {
    let byte = pos / 8;
    let bits = pos & 7;
    let end = byte
        .checked_add(4)
        .ok_or_else(|| Error::OutOfBounds("compact bit decode overflow".to_string()))?;
    let data = input
        .get(byte..end)
        .ok_or_else(|| Error::CorruptedData("compact bit decode out of range".to_string()))?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(data);
    let v = u32::from_le_bytes(arr) >> bits;
    let lo_mask = if lobits >= 32 {
        u32::MAX
    } else {
        (1u32 << lobits) - 1
    };
    let lo = (v & lo_mask) as usize;
    let kind = ((v >> lobits) & 0x3) as u8;
    Ok((lo, kind))
}

fn compacted_lookahead_distance(
    lobits: usize,
    encodebits: usize,
    vcnt: usize,
    input: &[u8],
    mut i: usize,
) -> Result<usize> {
    if i >= vcnt {
        return Err(Error::OutOfRange(i, vcnt));
    }
    let mut d1 = 0usize;
    loop {
        let (lo, kind) = decode_compactedbits(lobits, input, encodebits * i)?;
        if kind != Z_EROFS_LCLUSTER_TYPE_NONHEAD {
            return Ok(d1);
        }
        d1 += 1;
        i += 1;
        if i >= vcnt {
            if (lo as u16 & Z_EROFS_LI_D0_CBLKCNT) == 0 {
                d1 += lo.saturating_sub(1);
            }
            return Ok(d1);
        }
    }
}

async fn read_exact_at<R: ReadAt + ?Sized>(
    reader: &R,
    image_size: u64,
    offset: u64,
    out: &mut [u8],
) -> Result<()> {
    let end = offset
        .checked_add(out.len() as u64)
        .ok_or_else(|| Error::OutOfBounds("read range overflow".to_string()))?;
    if end > image_size {
        return Err(Error::OutOfBounds("read beyond image size".to_string()));
    }

    let mut filled = 0usize;
    while filled < out.len() {
        let read = reader
            .read_at(offset + filled as u64, &mut out[filled..])
            .await?;
        if read == 0 {
            return Err(Error::OutOfBounds(
                "unexpected EOF from backing reader".to_string(),
            ));
        }
        filled += read;
    }
    Ok(())
}
