use std::env;
use std::io::{self, Write};
use std::sync::Arc;

use futures::executor::block_on;
use gibblox_cache::CachedBlockReader;
use gibblox_cache_store_std::StdCacheOps;
use gibblox_core::{BlockReader, EroBlockReader, ReadContext};
use gibblox_file::StdFileBlockReader;
use tracing::{debug, info, trace};
use tracing_subscriber::{EnvFilter, fmt};

fn main() {
    init_tracing();
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| String::from("erofs_cat"));
    let image_path = args
        .next()
        .ok_or_else(|| format!("usage: {program} <image.erofs> <path/in/erofs>"))?;
    let file_path = args
        .next()
        .ok_or_else(|| format!("usage: {program} <image.erofs> <path/in/erofs>"))?;

    let source_block_size = 4096u32;
    info!(image_path, file_path, "starting erofs_cat");
    let source = StdFileBlockReader::open(&image_path, source_block_size)?;
    let cache = block_on(StdCacheOps::open_default_for_reader(&source))?;
    let cached_source = Arc::new(block_on(CachedBlockReader::new(source, cache))?);
    let reader = block_on(EroBlockReader::new(
        Arc::clone(&cached_source),
        &file_path,
        4096,
    ))?;
    let total_blocks = block_on(reader.total_blocks())?;
    info!(
        total_blocks,
        file_size = reader.file_size_bytes(),
        "prepared file reader"
    );

    let mut remaining = reader.file_size_bytes();
    let mut block = vec![0u8; reader.block_size() as usize];
    let stdout = io::stdout();
    let mut lock = stdout.lock();

    for lba in 0..total_blocks {
        trace!(lba, remaining, "reading next logical block");
        let read = block_on(reader.read_blocks(lba, &mut block, ReadContext::FOREGROUND))?;
        let write_len = (read as u64).min(remaining) as usize;
        debug!(lba, read, write_len, "writing block bytes to stdout");
        lock.write_all(&block[..write_len])?;
        remaining -= write_len as u64;
    }

    block_on(cached_source.flush_cache())?;
    info!("finished erofs_cat output");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}
