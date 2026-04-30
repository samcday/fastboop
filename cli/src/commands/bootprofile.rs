use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::CString;
use std::fs;
use std::future::Future;
use std::io::{BufWriter, IsTerminal, Read, Write};
#[cfg(target_family = "unix")]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use fastboop_core::{
    BootProfile, BootProfileArtifactSource, BootProfileManifest, decode_boot_profile,
    encode_boot_profile, encode_channel_pipeline_hints_record, validate_boot_profile,
};
use gibblox_android_sparse::AndroidSparseBlockReader;
#[cfg(test)]
use gibblox_android_sparse::AndroidSparseImageIndex;
use gibblox_core::{BlockReader, ReadContext};
use gibblox_optimizer::{PipelineOptimizeOptions, optimize_pipeline_hints};
#[cfg(test)]
use gibblox_pipeline::{PipelineAndroidSparseChunkIndexHint, PipelineAndroidSparseIndexHint};
use gibblox_pipeline::{
    PipelineContentDigestHint, PipelineHint, PipelineHintEntry, PipelineHints, PipelineSource,
    PipelineSourceFileSource, pipeline_identity_string,
};
#[cfg(target_family = "unix")]
use rustix::fs::statvfs;
use sha2::{Digest, Sha512};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{debug, info};

use super::{ArtifactReaderResolver, hydrate_pipeline_file_content};

#[derive(Args)]
pub struct BootProfileArgs {
    #[command(subcommand)]
    pub command: BootProfileCommand,
}

#[derive(Subcommand)]
pub enum BootProfileCommand {
    /// Compile a YAML/JSON boot profile into binary form.
    Create(BootProfileCreateArgs),
    /// Alias of top-level `show` for channel-ish inputs.
    Show(BootProfileShowArgs),
    /// Materialize pipeline hints sidecar from a compiled boot profile.
    Optimize(BootProfileOptimizeArgs),
}

#[derive(Args)]
pub struct BootProfileCreateArgs {
    /// Input boot profile document path ("-" for stdin).
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Output compiled boot profile path ("-" for stdout).
    #[arg(short, long, value_name = "OUTPUT", default_value = "-")]
    pub output: String,
    /// Run optimize after create and emit pipeline hints sidecar.
    #[arg(long, default_value_t = false)]
    pub optimize: bool,
    /// Output path for optimize sidecar when --optimize is set.
    #[arg(long, value_name = "OUTPUT")]
    pub optimize_output: Option<String>,
    /// Local artifact file to short-circuit matching pipeline stages during --optimize (repeatable).
    #[arg(long = "local-artifact", value_name = "PATH")]
    pub local_artifact: Vec<PathBuf>,
}

#[derive(Args)]
pub struct BootProfileShowArgs {
    /// Input channel/profile path or URL ("-" for stdin bytes).
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Output report path ("-" for stdout).
    #[arg(short, long, value_name = "OUTPUT", default_value = "-")]
    pub output: String,
}

#[derive(Args)]
pub struct BootProfileOptimizeArgs {
    /// Input compiled boot profile path ("-" for stdin).
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Output pipeline hints binary path ("-" for stdout).
    #[arg(short, long, value_name = "OUTPUT", default_value = "-")]
    pub output: String,
    /// Local artifact file to short-circuit matching pipeline stages (repeatable).
    #[arg(long = "local-artifact", value_name = "PATH")]
    pub local_artifact: Vec<PathBuf>,
}

pub async fn run_bootprofile(args: BootProfileArgs) -> Result<()> {
    match args.command {
        BootProfileCommand::Create(args) => run_create(args).await,
        BootProfileCommand::Show(args) => {
            super::run_show(super::ShowArgs {
                input: args.input,
                output: args.output,
            })
            .await
        }
        BootProfileCommand::Optimize(args) => run_optimize(args).await,
    }
}

async fn run_create(args: BootProfileCreateArgs) -> Result<()> {
    debug!(
        input = %io_label(&args.input),
        output = %io_label(&args.output),
        "bootprofile create started"
    );

    let input = read_input_bytes(&args.input)?;
    debug!(
        bytes = input.len(),
        "bootprofile create read manifest bytes"
    );

    let manifest: BootProfileManifest = serde_yaml::from_slice(&input)
        .with_context(|| format!("parsing boot profile document {}", io_label(&args.input)))?;
    debug!(profile_id = %manifest.id, "bootprofile create parsed manifest");

    let mut compiled = manifest
        .compile_dt_overlays(compile_dt_overlay)
        .context("compiling dt_overlays with dtc")?;

    hydrate_profile_file_content(&mut compiled)?;

    validate_boot_profile(&compiled).map_err(|err| anyhow!("{err}"))?;

    let bytes = encode_boot_profile(&compiled).context("encoding boot profile binary")?;
    debug!(
        profile_id = %compiled.id,
        bytes = bytes.len(),
        "bootprofile create encoded boot profile"
    );

    validate_binary_output(
        &args.output,
        "bootprofile create",
        std::io::stdout().is_terminal(),
    )?;
    write_output_bytes(&args.output, &bytes)?;

    if args.optimize {
        let optimize_output =
            resolve_create_optimize_output(args.optimize_output.as_deref(), args.output.as_str())?;
        let mut resolver =
            ArtifactReaderResolver::with_local_artifacts(args.local_artifact.as_slice())?;
        let hints = collect_profile_pipeline_hints(&compiled, &mut resolver).await?;
        let hint_bytes =
            encode_channel_pipeline_hints_record(&hints).map_err(|err| anyhow!("{err}"))?;
        validate_binary_output(
            optimize_output.as_str(),
            "bootprofile optimize",
            std::io::stdout().is_terminal(),
        )?;
        if optimize_output == args.output {
            append_output_bytes(optimize_output.as_str(), hint_bytes.as_slice())?;
        } else {
            write_output_bytes(optimize_output.as_str(), hint_bytes.as_slice())?;
        }
        info!(
            profile_id = %compiled.id,
            output = %io_label(optimize_output.as_str()),
            bytes = hint_bytes.len(),
            "bootprofile create emitted optimize sidecar"
        );
    }

    debug!(
        output = %io_label(&args.output),
        "bootprofile create finished"
    );
    Ok(())
}

fn hydrate_profile_file_content(profile: &mut BootProfile) -> Result<()> {
    let mut cache = HashMap::new();
    hydrate_pipeline_file_content(profile.rootfs.source_mut(), &mut cache)?;
    if let Some(kernel) = profile.kernel.as_mut() {
        hydrate_pipeline_file_content(kernel.artifact_source_mut(), &mut cache)?;
    }
    if let Some(dtbs) = profile.dtbs.as_mut() {
        hydrate_pipeline_file_content(dtbs.artifact_source_mut(), &mut cache)?;
    }
    Ok(())
}

pub(super) fn render_boot_profile_yaml(compiled: &BootProfile) -> Result<String> {
    validate_boot_profile(compiled).map_err(|err| anyhow!("{err}"))?;
    let manifest = compiled
        .decompile_dt_overlays(decompile_dt_overlay)
        .context("decompiling dt_overlays with dtc")?;
    serde_yaml::to_string(&manifest).context("serializing boot profile YAML")
}

async fn run_optimize(args: BootProfileOptimizeArgs) -> Result<()> {
    debug!(
        input = %io_label(&args.input),
        output = %io_label(&args.output),
        "bootprofile optimize started"
    );

    let input = read_input_bytes(&args.input)?;
    let compiled = decode_boot_profile(&input).map_err(|err| anyhow!("{err}"))?;
    validate_boot_profile(&compiled).map_err(|err| anyhow!("{err}"))?;

    info!(
        profile_id = %compiled.id,
        local_artifacts = args.local_artifact.len(),
        "bootprofile optimize preparing artifact resolver"
    );

    let mut resolver =
        ArtifactReaderResolver::with_local_artifacts(args.local_artifact.as_slice())?;
    info!(
        profile_id = %compiled.id,
        "bootprofile optimize collecting pipeline hints"
    );
    let hints = collect_profile_pipeline_hints(&compiled, &mut resolver).await?;
    let bytes = encode_channel_pipeline_hints_record(&hints).map_err(|err| anyhow!("{err}"))?;
    info!(
        profile_id = %compiled.id,
        hint_entries = hints.entries.len(),
        bytes = bytes.len(),
        "bootprofile optimize materialized pipeline hints"
    );

    validate_binary_output(
        &args.output,
        "bootprofile optimize",
        std::io::stdout().is_terminal(),
    )?;
    write_output_bytes(&args.output, &bytes)?;
    debug!(
        output = %io_label(&args.output),
        "bootprofile optimize finished"
    );
    Ok(())
}

async fn collect_profile_pipeline_hints(
    profile: &BootProfile,
    resolver: &mut ArtifactReaderResolver,
) -> Result<PipelineHints> {
    let mut entries = BTreeMap::new();
    let mut visited_wrappers = BTreeSet::new();
    let mut digest_cache = BTreeMap::new();
    let mut materialized_cache = MaterializedCache::new()?;

    info!(profile_id = %profile.id, "collecting rootfs pipeline hints");

    collect_pipeline_hints_from_artifact_source(
        profile.rootfs.source(),
        resolver,
        &mut entries,
        &mut visited_wrappers,
        &mut digest_cache,
        &mut materialized_cache,
    )
    .await
    .context("materializing rootfs pipeline hints")?;
    collect_generic_pipeline_hints_from_artifact_source(
        profile.rootfs.source(),
        resolver,
        &mut entries,
    )
    .await
    .context("materializing rootfs generic pipeline hints")?;

    if let Some(kernel) = profile.kernel.as_ref() {
        info!(profile_id = %profile.id, "collecting kernel pipeline hints");
        collect_pipeline_hints_from_artifact_source(
            kernel.artifact_source(),
            resolver,
            &mut entries,
            &mut visited_wrappers,
            &mut digest_cache,
            &mut materialized_cache,
        )
        .await
        .context("materializing kernel pipeline hints")?;
        collect_generic_pipeline_hints_from_artifact_source(
            kernel.artifact_source(),
            resolver,
            &mut entries,
        )
        .await
        .context("materializing kernel generic pipeline hints")?;
    }

    if let Some(dtbs) = profile.dtbs.as_ref() {
        info!(profile_id = %profile.id, "collecting dtbs pipeline hints");
        collect_pipeline_hints_from_artifact_source(
            dtbs.artifact_source(),
            resolver,
            &mut entries,
            &mut visited_wrappers,
            &mut digest_cache,
            &mut materialized_cache,
        )
        .await
        .context("materializing dtbs pipeline hints")?;
        collect_generic_pipeline_hints_from_artifact_source(
            dtbs.artifact_source(),
            resolver,
            &mut entries,
        )
        .await
        .context("materializing dtbs generic pipeline hints")?;
    }

    Ok(PipelineHints {
        entries: entries.into_values().collect(),
    })
}

async fn collect_generic_pipeline_hints_from_artifact_source(
    source: &BootProfileArtifactSource,
    resolver: &ArtifactReaderResolver,
    entries: &mut BTreeMap<String, PipelineHintEntry>,
) -> Result<()> {
    let optimizer_source = optimizer_source_with_local_artifacts(source, resolver)?;
    let mut identity_map = BTreeMap::new();
    collect_optimizer_identity_map(source, &optimizer_source, &mut identity_map);
    let hints = optimize_pipeline_hints(
        &optimizer_source,
        &PipelineOptimizeOptions {
            image_block_size: super::DEFAULT_IMAGE_BLOCK_SIZE,
            ..PipelineOptimizeOptions::default()
        },
    )
    .await?;

    for mut entry in hints.entries {
        if let Some(original_identity) = identity_map.get(&entry.pipeline_identity).cloned() {
            entry.pipeline_identity = original_identity;
        }
        let pipeline_identity = entry.pipeline_identity;
        for hint in entry.hints {
            insert_pipeline_hint(entries, pipeline_identity.clone(), hint)?;
        }
    }
    Ok(())
}

fn optimizer_source_with_local_artifacts(
    source: &PipelineSource,
    resolver: &ArtifactReaderResolver,
) -> Result<PipelineSource> {
    if let Some(local_path) = resolver.match_local_artifact(source)? {
        return Ok(PipelineSource::File(PipelineSourceFileSource {
            file: local_path.to_string_lossy().into_owned(),
            content: super::artifact_source_content(source).cloned(),
        }));
    }

    Ok(match source {
        PipelineSource::Http(_) | PipelineSource::File(_) | PipelineSource::Casync(_) => {
            source.clone()
        }
        PipelineSource::Xz(source) => {
            PipelineSource::Xz(gibblox_pipeline::PipelineSourceXzSource {
                xz: Box::new(optimizer_source_with_local_artifacts(
                    source.xz.as_ref(),
                    resolver,
                )?),
                content: source.content.clone(),
            })
        }
        PipelineSource::AndroidSparseImg(source) => PipelineSource::AndroidSparseImg(
            gibblox_pipeline::PipelineSourceAndroidSparseImgSource {
                android_sparseimg: gibblox_pipeline::PipelineSourceAndroidSparseImg {
                    source: Box::new(optimizer_source_with_local_artifacts(
                        source.android_sparseimg.source.as_ref(),
                        resolver,
                    )?),
                    content: source.android_sparseimg.content.clone(),
                },
            },
        ),
        PipelineSource::Tar(source) => {
            PipelineSource::Tar(gibblox_pipeline::PipelineSourceTarSource {
                tar: gibblox_pipeline::PipelineSourceTar {
                    entry: source.tar.entry.clone(),
                    source: Box::new(optimizer_source_with_local_artifacts(
                        source.tar.source.as_ref(),
                        resolver,
                    )?),
                    content: source.tar.content.clone(),
                },
            })
        }
        PipelineSource::Mbr(source) => {
            PipelineSource::Mbr(gibblox_pipeline::PipelineSourceMbrSource {
                mbr: gibblox_pipeline::PipelineSourceMbr {
                    partuuid: source.mbr.partuuid.clone(),
                    index: source.mbr.index,
                    lba_size: source.mbr.lba_size,
                    source: Box::new(optimizer_source_with_local_artifacts(
                        source.mbr.source.as_ref(),
                        resolver,
                    )?),
                    content: source.mbr.content.clone(),
                },
            })
        }
        PipelineSource::Gpt(source) => {
            PipelineSource::Gpt(gibblox_pipeline::PipelineSourceGptSource {
                gpt: gibblox_pipeline::PipelineSourceGpt {
                    partlabel: source.gpt.partlabel.clone(),
                    partuuid: source.gpt.partuuid.clone(),
                    index: source.gpt.index,
                    lba_size: source.gpt.lba_size,
                    source: Box::new(optimizer_source_with_local_artifacts(
                        source.gpt.source.as_ref(),
                        resolver,
                    )?),
                    content: source.gpt.content.clone(),
                },
            })
        }
    })
}

fn collect_optimizer_identity_map(
    original: &PipelineSource,
    optimizer_source: &PipelineSource,
    out: &mut BTreeMap<String, String>,
) {
    out.insert(
        pipeline_identity_string(optimizer_source),
        pipeline_identity_string(original),
    );

    match (original, optimizer_source) {
        (PipelineSource::Xz(original), PipelineSource::Xz(optimizer_source)) => {
            collect_optimizer_identity_map(original.xz.as_ref(), optimizer_source.xz.as_ref(), out);
        }
        (
            PipelineSource::AndroidSparseImg(original),
            PipelineSource::AndroidSparseImg(optimizer_source),
        ) => {
            collect_optimizer_identity_map(
                original.android_sparseimg.source.as_ref(),
                optimizer_source.android_sparseimg.source.as_ref(),
                out,
            );
        }
        (PipelineSource::Tar(original), PipelineSource::Tar(optimizer_source)) => {
            collect_optimizer_identity_map(
                original.tar.source.as_ref(),
                optimizer_source.tar.source.as_ref(),
                out,
            );
        }
        (PipelineSource::Mbr(original), PipelineSource::Mbr(optimizer_source)) => {
            collect_optimizer_identity_map(
                original.mbr.source.as_ref(),
                optimizer_source.mbr.source.as_ref(),
                out,
            );
        }
        (PipelineSource::Gpt(original), PipelineSource::Gpt(optimizer_source)) => {
            collect_optimizer_identity_map(
                original.gpt.source.as_ref(),
                optimizer_source.gpt.source.as_ref(),
                out,
            );
        }
        _ => {}
    }
}

fn collect_pipeline_hints_from_artifact_source<'a>(
    source: &'a BootProfileArtifactSource,
    resolver: &'a mut ArtifactReaderResolver,
    entries: &'a mut BTreeMap<String, PipelineHintEntry>,
    visited_wrappers: &'a mut BTreeSet<String>,
    digest_cache: &'a mut BTreeMap<String, PipelineContentDigestHint>,
    materialized_cache: &'a mut MaterializedCache,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        match source {
            BootProfileArtifactSource::Xz(source) => {
                let xz_source = source.clone();
                collect_pipeline_hints_from_artifact_source(
                    source.xz.as_ref(),
                    resolver,
                    entries,
                    visited_wrappers,
                    digest_cache,
                    materialized_cache,
                )
                .await?;

                let source = BootProfileArtifactSource::Xz(xz_source.clone());
                let pipeline_identity = pipeline_identity_string(&source);
                let digest_hint = ensure_wrapper_materialized(
                    &source,
                    pipeline_identity.as_str(),
                    resolver,
                    visited_wrappers,
                    digest_cache,
                    materialized_cache,
                )
                .await?;
                if xz_source.content.is_none() {
                    insert_pipeline_hint(
                        entries,
                        pipeline_identity,
                        PipelineHint::ContentDigest(digest_hint),
                    )?;
                }
                Ok(())
            }
            BootProfileArtifactSource::AndroidSparseImg(source) => {
                collect_pipeline_hints_from_artifact_source(
                    source.android_sparseimg.source.as_ref(),
                    resolver,
                    entries,
                    visited_wrappers,
                    digest_cache,
                    materialized_cache,
                )
                .await?;

                let android_sparse_source = source.clone();
                let source =
                    BootProfileArtifactSource::AndroidSparseImg(android_sparse_source.clone());
                let pipeline_identity = pipeline_identity_string(&source);

                let digest_hint = if visited_wrappers.contains(&pipeline_identity) {
                    load_content_digest_hint(
                        &source,
                        pipeline_identity.as_str(),
                        resolver,
                        digest_cache,
                    )
                    .await?
                } else {
                    let upstream = resolver
                        .open_artifact_source(
                            android_sparse_source.android_sparseimg.source.as_ref(),
                        )
                        .await?;
                    info!(
                        pipeline_identity = %pipeline_identity,
                        "materializing android sparse index hint"
                    );
                    let reader = AndroidSparseBlockReader::new(upstream)
                        .await
                        .map_err(|err| anyhow!("open android sparse reader: {err}"))?;

                    let reader: Arc<dyn BlockReader> = Arc::new(reader);
                    let materialized = digest_and_materialize_reader_content(
                        reader,
                        pipeline_identity.as_str(),
                        materialized_cache,
                        digest_strategy_for_source(&source),
                    )
                    .await?;
                    materialized_cache.register_materialized_source(
                        resolver,
                        &source,
                        materialized.hint.digest.as_str(),
                        materialized.block_size,
                    )?;
                    digest_cache.insert(
                        super::artifact_source_cache_key(&source)?,
                        materialized.hint.clone(),
                    );
                    visited_wrappers.insert(pipeline_identity.clone());
                    materialized.hint
                };

                if android_sparse_source.android_sparseimg.content.is_none() {
                    insert_pipeline_hint(
                        entries,
                        pipeline_identity,
                        PipelineHint::ContentDigest(digest_hint),
                    )?;
                }
                Ok(())
            }
            BootProfileArtifactSource::Tar(source) => {
                let tar_source = source.clone();
                collect_pipeline_hints_from_artifact_source(
                    source.tar.source.as_ref(),
                    resolver,
                    entries,
                    visited_wrappers,
                    digest_cache,
                    materialized_cache,
                )
                .await?;

                let source = BootProfileArtifactSource::Tar(tar_source.clone());
                let pipeline_identity = pipeline_identity_string(&source);
                let digest_hint = ensure_wrapper_materialized(
                    &source,
                    pipeline_identity.as_str(),
                    resolver,
                    visited_wrappers,
                    digest_cache,
                    materialized_cache,
                )
                .await?;
                if tar_source.tar.content.is_none() {
                    insert_pipeline_hint(
                        entries,
                        pipeline_identity,
                        PipelineHint::ContentDigest(digest_hint),
                    )?;
                }
                Ok(())
            }
            BootProfileArtifactSource::Mbr(source) => {
                let mbr_source = source.clone();
                collect_pipeline_hints_from_artifact_source(
                    source.mbr.source.as_ref(),
                    resolver,
                    entries,
                    visited_wrappers,
                    digest_cache,
                    materialized_cache,
                )
                .await?;

                let source = BootProfileArtifactSource::Mbr(mbr_source.clone());
                let pipeline_identity = pipeline_identity_string(&source);
                let digest_hint = ensure_wrapper_materialized(
                    &source,
                    pipeline_identity.as_str(),
                    resolver,
                    visited_wrappers,
                    digest_cache,
                    materialized_cache,
                )
                .await?;
                if mbr_source.mbr.content.is_none() {
                    insert_pipeline_hint(
                        entries,
                        pipeline_identity,
                        PipelineHint::ContentDigest(digest_hint),
                    )?;
                }
                Ok(())
            }
            BootProfileArtifactSource::Gpt(source) => {
                let gpt_source = source.clone();
                collect_pipeline_hints_from_artifact_source(
                    source.gpt.source.as_ref(),
                    resolver,
                    entries,
                    visited_wrappers,
                    digest_cache,
                    materialized_cache,
                )
                .await?;

                let source = BootProfileArtifactSource::Gpt(gpt_source.clone());
                let pipeline_identity = pipeline_identity_string(&source);
                let digest_hint = ensure_wrapper_materialized(
                    &source,
                    pipeline_identity.as_str(),
                    resolver,
                    visited_wrappers,
                    digest_cache,
                    materialized_cache,
                )
                .await?;
                if gpt_source.gpt.content.is_none() {
                    insert_pipeline_hint(
                        entries,
                        pipeline_identity,
                        PipelineHint::ContentDigest(digest_hint),
                    )?;
                }
                Ok(())
            }
            BootProfileArtifactSource::Http(_)
            | BootProfileArtifactSource::File(_)
            | BootProfileArtifactSource::Casync(_) => Ok(()),
        }
    })
}

async fn load_content_digest_hint(
    source: &BootProfileArtifactSource,
    pipeline_identity: &str,
    resolver: &mut ArtifactReaderResolver,
    digest_cache: &mut BTreeMap<String, PipelineContentDigestHint>,
) -> Result<PipelineContentDigestHint> {
    let cache_key = super::artifact_source_cache_key(source)?;
    if let Some(hint) = digest_cache.get(&cache_key).cloned() {
        info!(pipeline_identity, "reusing cached content digest hint");
        return Ok(hint);
    }

    let reader = resolver.open_artifact_source(source).await?;
    let hint = digest_reader_content(
        reader,
        pipeline_identity,
        digest_strategy_for_source(source),
    )
    .await?;
    digest_cache.insert(cache_key, hint.clone());
    Ok(hint)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DigestStrategy {
    Sequential,
    ChunkedParallel,
}

fn digest_strategy_for_source(source: &BootProfileArtifactSource) -> DigestStrategy {
    match source {
        BootProfileArtifactSource::Http(_)
        | BootProfileArtifactSource::File(_)
        | BootProfileArtifactSource::Casync(_)
        | BootProfileArtifactSource::Xz(_)
        | BootProfileArtifactSource::Tar(_) => DigestStrategy::ChunkedParallel,
        BootProfileArtifactSource::AndroidSparseImg(_)
        | BootProfileArtifactSource::Mbr(_)
        | BootProfileArtifactSource::Gpt(_) => DigestStrategy::Sequential,
    }
}

async fn ensure_wrapper_materialized(
    source: &BootProfileArtifactSource,
    pipeline_identity: &str,
    resolver: &mut ArtifactReaderResolver,
    visited_wrappers: &mut BTreeSet<String>,
    digest_cache: &mut BTreeMap<String, PipelineContentDigestHint>,
    materialized_cache: &mut MaterializedCache,
) -> Result<PipelineContentDigestHint> {
    if visited_wrappers.contains(pipeline_identity) {
        return load_content_digest_hint(source, pipeline_identity, resolver, digest_cache).await;
    }

    let reader = resolver.open_artifact_source(source).await?;
    let materialized = digest_and_materialize_reader_content(
        reader,
        pipeline_identity,
        materialized_cache,
        digest_strategy_for_source(source),
    )
    .await?;
    materialized_cache.register_materialized_source(
        resolver,
        source,
        materialized.hint.digest.as_str(),
        materialized.block_size,
    )?;
    digest_cache.insert(
        super::artifact_source_cache_key(source)?,
        materialized.hint.clone(),
    );
    visited_wrappers.insert(pipeline_identity.to_string());
    Ok(materialized.hint)
}

#[cfg(test)]
fn insert_android_sparse_hint(
    entries: &mut BTreeMap<String, PipelineHintEntry>,
    pipeline_identity: String,
    index: AndroidSparseImageIndex,
) -> Result<()> {
    insert_pipeline_hint(
        entries,
        pipeline_identity,
        PipelineHint::AndroidSparseIndex(PipelineAndroidSparseIndexHint {
            file_hdr_sz: index.file_hdr_sz,
            chunk_hdr_sz: index.chunk_hdr_sz,
            blk_sz: index.blk_sz,
            total_blks: index.total_blks,
            total_chunks: index.total_chunks,
            image_checksum: index.image_checksum,
            chunks: index
                .chunks
                .into_iter()
                .map(|chunk| PipelineAndroidSparseChunkIndexHint {
                    chunk_index: chunk.chunk_index,
                    chunk_type: chunk.chunk_type,
                    chunk_sz: chunk.chunk_sz,
                    total_sz: chunk.total_sz,
                    chunk_offset: chunk.chunk_offset,
                    payload_offset: chunk.payload_offset,
                    payload_size: chunk.payload_size,
                    output_start: chunk.output_start,
                    output_end: chunk.output_end,
                    fill_pattern: chunk.fill_pattern,
                    crc32: chunk.crc32,
                })
                .collect(),
        }),
    )
}

fn insert_pipeline_hint(
    entries: &mut BTreeMap<String, PipelineHintEntry>,
    pipeline_identity: String,
    hint: PipelineHint,
) -> Result<()> {
    let entry = entries
        .entry(pipeline_identity.clone())
        .or_insert_with(|| PipelineHintEntry {
            pipeline_identity: pipeline_identity.clone(),
            hints: Vec::new(),
        });

    let duplicate = entry
        .hints
        .iter()
        .any(|existing| hint_discriminant(existing) == hint_discriminant(&hint));
    if duplicate {
        return Ok(());
    }
    entry.hints.push(hint);
    Ok(())
}

fn hint_discriminant(hint: &PipelineHint) -> &'static str {
    match hint {
        PipelineHint::AndroidSparseIndex(_) => "android-sparse-index",
        PipelineHint::TarEntryIndex(_) => "tar-entry-index",
        PipelineHint::ContentDigest(_) => "content-digest",
    }
}

async fn digest_reader_content(
    reader: Arc<dyn BlockReader>,
    pipeline_identity: &str,
    strategy: DigestStrategy,
) -> Result<PipelineContentDigestHint> {
    const DIGEST_CHUNK_TARGET_BYTES: usize = 32 * 1024 * 1024;
    const DIGEST_PARALLEL_MAX_CHUNKS: usize = 8;

    let block_size = reader.block_size() as usize;
    if block_size == 0 {
        bail!("reader block size is zero");
    }
    let blocks_per_read = core::cmp::max(1, DIGEST_CHUNK_TARGET_BYTES / block_size);
    let max_read_bytes = blocks_per_read * block_size;

    let total_blocks = reader.total_blocks().await?;
    info!(
        pipeline_identity,
        total_blocks, block_size, blocks_per_read, max_read_bytes, "digesting pipeline content"
    );

    let parallel_chunks = if strategy == DigestStrategy::ChunkedParallel {
        core::cmp::min(
            std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(1),
            DIGEST_PARALLEL_MAX_CHUNKS,
        )
    } else {
        1
    };

    if parallel_chunks > 1 {
        info!(
            pipeline_identity,
            parallel_chunks,
            chunk_bytes = max_read_bytes,
            "using chunked parallel digest reads"
        );
        return digest_reader_content_parallel(
            reader,
            pipeline_identity,
            total_blocks,
            block_size,
            blocks_per_read,
            parallel_chunks,
        )
        .await;
    }

    let mut hasher = Sha512::new();
    let mut size_bytes = 0u64;
    let mut buf = vec![0u8; max_read_bytes];
    let mut lba = 0u64;

    while lba < total_blocks {
        let remaining_blocks = total_blocks - lba;
        let requested_blocks = core::cmp::min(remaining_blocks, blocks_per_read as u64);
        let requested_bytes = requested_blocks as usize * block_size;
        let read = reader
            .read_blocks(lba, &mut buf[..requested_bytes], ReadContext::BACKGROUND)
            .await?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        size_bytes = size_bytes
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("digest size overflow"))?;
        let consumed_blocks = (read as u64).div_ceil(block_size as u64);
        if consumed_blocks == 0 {
            break;
        }
        lba = lba
            .checked_add(consumed_blocks)
            .ok_or_else(|| anyhow!("digest lba overflow"))?;
        if read < requested_bytes {
            break;
        }
    }

    let digest = format!("sha512:{:x}", hasher.finalize());
    info!(
        pipeline_identity,
        digest, size_bytes, "finished digesting pipeline content"
    );
    Ok(PipelineContentDigestHint { digest, size_bytes })
}

struct DigestChunkResult {
    chunk_idx: u64,
    requested_bytes: usize,
    bytes: Vec<u8>,
}

fn digest_parallel_chunks_for_strategy(strategy: DigestStrategy) -> usize {
    const DIGEST_PARALLEL_MAX_CHUNKS: usize = 8;
    if strategy != DigestStrategy::ChunkedParallel {
        return 1;
    }
    core::cmp::min(
        std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1),
        DIGEST_PARALLEL_MAX_CHUNKS,
    )
}

fn spawn_digest_chunk_reader(
    join_set: &mut JoinSet<Result<DigestChunkResult>>,
    chunk_idx: u64,
    reader: Arc<dyn BlockReader>,
    limiter: Arc<Semaphore>,
    total_blocks: u64,
    block_size: usize,
    blocks_per_read: usize,
) {
    join_set.spawn(async move {
        let _permit = limiter
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("digest parallel limiter closed"))?;

        let start_lba = chunk_idx
            .checked_mul(blocks_per_read as u64)
            .ok_or_else(|| anyhow!("digest chunk start lba overflow"))?;
        let remaining_blocks = total_blocks.saturating_sub(start_lba);
        let chunk_blocks = core::cmp::min(remaining_blocks, blocks_per_read as u64);
        let requested_bytes = chunk_blocks as usize * block_size;
        let mut bytes = vec![0u8; requested_bytes];
        let read = reader
            .read_blocks(start_lba, &mut bytes, ReadContext::BACKGROUND)
            .await?;
        bytes.truncate(read);
        Ok(DigestChunkResult {
            chunk_idx,
            requested_bytes,
            bytes,
        })
    });
}

async fn digest_reader_content_parallel(
    reader: Arc<dyn BlockReader>,
    pipeline_identity: &str,
    total_blocks: u64,
    block_size: usize,
    blocks_per_read: usize,
    parallel_chunks: usize,
) -> Result<PipelineContentDigestHint> {
    let total_chunks = total_blocks.div_ceil(blocks_per_read as u64);
    let limiter = Arc::new(Semaphore::new(parallel_chunks));
    let mut join_set = JoinSet::new();
    let mut next_chunk_to_spawn = 0u64;
    let mut next_chunk_to_hash = 0u64;
    let mut pending = BTreeMap::<u64, DigestChunkResult>::new();
    let mut hasher = Sha512::new();
    let mut size_bytes = 0u64;
    let mut saw_short_read = false;

    while next_chunk_to_spawn < total_chunks && join_set.len() < parallel_chunks && !saw_short_read
    {
        spawn_digest_chunk_reader(
            &mut join_set,
            next_chunk_to_spawn,
            reader.clone(),
            limiter.clone(),
            total_blocks,
            block_size,
            blocks_per_read,
        );
        next_chunk_to_spawn += 1;
    }

    while next_chunk_to_hash < total_chunks {
        let joined = join_set
            .join_next()
            .await
            .ok_or_else(|| anyhow!("digest parallel worker stream ended unexpectedly"))?;
        let result = joined.map_err(|err| anyhow!("digest parallel task failed: {err}"))??;
        pending.insert(result.chunk_idx, result);

        while let Some(chunk) = pending.remove(&next_chunk_to_hash) {
            if chunk.bytes.is_empty() {
                saw_short_read = true;
                next_chunk_to_hash += 1;
                break;
            }

            hasher.update(&chunk.bytes);
            size_bytes = size_bytes
                .checked_add(chunk.bytes.len() as u64)
                .ok_or_else(|| anyhow!("digest size overflow"))?;

            if chunk.bytes.len() < chunk.requested_bytes {
                saw_short_read = true;
            }

            next_chunk_to_hash += 1;
        }

        while next_chunk_to_spawn < total_chunks
            && join_set.len() < parallel_chunks
            && !saw_short_read
        {
            spawn_digest_chunk_reader(
                &mut join_set,
                next_chunk_to_spawn,
                reader.clone(),
                limiter.clone(),
                total_blocks,
                block_size,
                blocks_per_read,
            );
            next_chunk_to_spawn += 1;
        }

        if saw_short_read && pending.is_empty() {
            break;
        }
    }

    while let Some(joined) = join_set.join_next().await {
        let _ = joined.map_err(|err| anyhow!("digest parallel task failed: {err}"))??;
    }

    let digest = format!("sha512:{:x}", hasher.finalize());
    info!(
        pipeline_identity,
        digest, size_bytes, "finished digesting pipeline content"
    );
    Ok(PipelineContentDigestHint { digest, size_bytes })
}

struct MaterializedCache {
    cache_dir: PathBuf,
    protected_paths: BTreeSet<PathBuf>,
}

struct MaterializedDigest {
    hint: PipelineContentDigestHint,
    block_size: u32,
}

impl MaterializedCache {
    fn new() -> Result<Self> {
        let cache_dir = super::default_gibblox_cache_root().join("materialized");
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("create materialized cache dir {}", cache_dir.display()))?;
        Ok(Self {
            cache_dir,
            protected_paths: BTreeSet::new(),
        })
    }

    fn register_materialized_source(
        &mut self,
        resolver: &mut ArtifactReaderResolver,
        source: &BootProfileArtifactSource,
        digest: &str,
        block_size: u32,
    ) -> Result<()> {
        let path = self.path_for_digest(digest)?;
        self.protected_paths.insert(path.clone());
        resolver.substitute_artifact_source_with_file(source, path.as_path(), block_size)
    }

    fn create_temp_writer(&mut self) -> Result<(PathBuf, BufWriter<fs::File>)> {
        self.prune_before_write_best_effort()?;
        fs::create_dir_all(&self.cache_dir).with_context(|| {
            format!(
                "create materialized cache dir {} before write",
                self.cache_dir.display()
            )
        })?;

        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|err| anyhow!("materialized cache clock before unix epoch: {err}"))?
            .as_nanos();
        let temp_path = self
            .cache_dir
            .join(format!(".tmp-{}-{nonce}.part", std::process::id()));
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .with_context(|| format!("create materialized temp file {}", temp_path.display()))?;
        Ok((temp_path, BufWriter::new(file)))
    }

    fn finalize_temp_file(&mut self, temp_path: &Path, digest: &str) -> Result<PathBuf> {
        let final_path = self.path_for_digest(digest)?;
        if final_path.exists() {
            let _ = fs::remove_file(temp_path);
            return Ok(final_path);
        }

        fs::rename(temp_path, &final_path).with_context(|| {
            format!(
                "move materialized cache file {} -> {}",
                temp_path.display(),
                final_path.display()
            )
        })?;
        Ok(final_path)
    }

    fn path_for_digest(&self, digest: &str) -> Result<PathBuf> {
        Ok(self.cache_dir.join(digest_to_cache_filename(digest)?))
    }

    fn prune_before_write_best_effort(&self) -> Result<()> {
        const MIN_FREE_RATIO: f64 = 0.10;

        let mut free_ratio = match disk_free_ratio(self.cache_dir.as_path())? {
            Some(value) => value,
            None => return Ok(()),
        };
        if free_ratio >= MIN_FREE_RATIO {
            return Ok(());
        }

        let mut candidates =
            list_materialized_prune_candidates(self.cache_dir.as_path(), &self.protected_paths)?;
        if candidates.is_empty() {
            return Ok(());
        }

        candidates.sort_unstable_by_key(|entry| entry.modified_at);
        let mut pruned_files = 0u64;
        let mut reclaimed_bytes = 0u64;

        for candidate in candidates {
            if free_ratio >= MIN_FREE_RATIO {
                break;
            }
            match fs::remove_file(&candidate.path) {
                Ok(()) => {
                    pruned_files += 1;
                    reclaimed_bytes = reclaimed_bytes.saturating_add(candidate.size_bytes);
                    if let Some(next_ratio) = disk_free_ratio(self.cache_dir.as_path())? {
                        free_ratio = next_ratio;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    info!(
                        path = %candidate.path.display(),
                        error = %err,
                        "failed to remove materialized cache entry during prune"
                    );
                }
            }
        }

        info!(
            cache_dir = %self.cache_dir.display(),
            free_ratio,
            pruned_files,
            reclaimed_bytes,
            "materialized cache prune completed"
        );
        Ok(())
    }
}

struct MaterializedEntry {
    path: PathBuf,
    modified_at: SystemTime,
    size_bytes: u64,
}

fn list_materialized_prune_candidates(
    cache_dir: &Path,
    protected_paths: &BTreeSet<PathBuf>,
) -> Result<Vec<MaterializedEntry>> {
    let mut entries = Vec::new();
    let read_dir = match fs::read_dir(cache_dir) {
        Ok(read_dir) => read_dir,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read materialized cache dir {}", cache_dir.display()));
        }
    };

    for entry in read_dir {
        let entry = entry
            .with_context(|| format!("read materialized cache entry in {}", cache_dir.display()))?;
        let path = entry.path();
        if protected_paths.contains(&path) {
            continue;
        }

        let file_type = entry
            .file_type()
            .with_context(|| format!("read file type for {}", path.display()))?;
        if !file_type.is_file() {
            continue;
        }

        let metadata = entry
            .metadata()
            .with_context(|| format!("read metadata for {}", path.display()))?;
        let modified_at = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        entries.push(MaterializedEntry {
            path,
            modified_at,
            size_bytes: metadata.len(),
        });
    }

    Ok(entries)
}

fn digest_to_cache_filename(digest: &str) -> Result<String> {
    let hex = digest
        .strip_prefix("sha512:")
        .ok_or_else(|| anyhow!("expected sha512 digest, got {digest}"))?;
    if hex.len() != 128 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid sha512 digest {digest}");
    }
    Ok(hex.to_ascii_lowercase())
}

#[cfg(target_family = "unix")]
fn disk_free_ratio(path: &Path) -> Result<Option<f64>> {
    let path_cstr = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow!("path contains interior NUL bytes: {}", path.display()))?;
    let stats = statvfs(path_cstr.as_c_str())
        .map_err(|err| anyhow!("statvfs {}: {err}", path.display()))?;
    let blocks_total = stats.f_blocks;
    if blocks_total == 0 {
        return Ok(None);
    }

    let blocks_available = stats.f_bavail;
    Ok(Some(blocks_available as f64 / blocks_total as f64))
}

#[cfg(not(target_family = "unix"))]
fn disk_free_ratio(_path: &Path) -> Result<Option<f64>> {
    Ok(None)
}

async fn digest_and_materialize_reader_content(
    reader: Arc<dyn BlockReader>,
    pipeline_identity: &str,
    materialized_cache: &mut MaterializedCache,
    strategy: DigestStrategy,
) -> Result<MaterializedDigest> {
    const DIGEST_CHUNK_TARGET_BYTES: usize = 32 * 1024 * 1024;

    let block_size = reader.block_size() as usize;
    if block_size == 0 {
        bail!("reader block size is zero");
    }
    let blocks_per_read = core::cmp::max(1, DIGEST_CHUNK_TARGET_BYTES / block_size);
    let max_read_bytes = blocks_per_read * block_size;

    let total_blocks = reader.total_blocks().await?;
    let parallel_chunks = digest_parallel_chunks_for_strategy(strategy);
    info!(
        pipeline_identity,
        total_blocks,
        block_size,
        blocks_per_read,
        max_read_bytes,
        parallel_chunks,
        "digesting and materializing pipeline content"
    );

    let (temp_path, mut writer) = materialized_cache.create_temp_writer()?;
    let (digest, size_bytes) = if parallel_chunks > 1 {
        info!(
            pipeline_identity,
            parallel_chunks,
            chunk_bytes = max_read_bytes,
            "using chunked parallel digest+materialize reads"
        );
        digest_and_materialize_reader_content_parallel(
            reader,
            total_blocks,
            block_size,
            blocks_per_read,
            parallel_chunks,
            &mut writer,
            temp_path.as_path(),
        )
        .await?
    } else {
        digest_and_materialize_reader_content_sequential(
            reader,
            total_blocks,
            block_size,
            blocks_per_read,
            &mut writer,
            temp_path.as_path(),
        )
        .await?
    };

    writer
        .flush()
        .with_context(|| format!("flush materialized bytes to {}", temp_path.display()))?;
    drop(writer);

    let final_path = materialized_cache.finalize_temp_file(temp_path.as_path(), digest.as_str())?;
    info!(
        pipeline_identity,
        digest,
        size_bytes,
        cache_path = %final_path.display(),
        "finished digesting and materializing pipeline content"
    );

    Ok(MaterializedDigest {
        hint: PipelineContentDigestHint { digest, size_bytes },
        block_size: block_size as u32,
    })
}

async fn digest_and_materialize_reader_content_sequential(
    reader: Arc<dyn BlockReader>,
    total_blocks: u64,
    block_size: usize,
    blocks_per_read: usize,
    writer: &mut BufWriter<fs::File>,
    temp_path: &Path,
) -> Result<(String, u64)> {
    let mut hasher = Sha512::new();
    let mut size_bytes = 0u64;
    let mut buf = vec![0u8; blocks_per_read * block_size];
    let mut lba = 0u64;

    while lba < total_blocks {
        let remaining_blocks = total_blocks - lba;
        let requested_blocks = core::cmp::min(remaining_blocks, blocks_per_read as u64);
        let requested_bytes = requested_blocks as usize * block_size;
        let read = reader
            .read_blocks(lba, &mut buf[..requested_bytes], ReadContext::BACKGROUND)
            .await?;
        if read == 0 {
            break;
        }

        hasher.update(&buf[..read]);
        writer
            .write_all(&buf[..read])
            .with_context(|| format!("write materialized bytes to {}", temp_path.display()))?;
        size_bytes = size_bytes
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("digest size overflow"))?;

        let consumed_blocks = (read as u64).div_ceil(block_size as u64);
        if consumed_blocks == 0 {
            break;
        }
        lba = lba
            .checked_add(consumed_blocks)
            .ok_or_else(|| anyhow!("digest lba overflow"))?;
        if read < requested_bytes {
            break;
        }
    }

    Ok((format!("sha512:{:x}", hasher.finalize()), size_bytes))
}

async fn digest_and_materialize_reader_content_parallel(
    reader: Arc<dyn BlockReader>,
    total_blocks: u64,
    block_size: usize,
    blocks_per_read: usize,
    parallel_chunks: usize,
    writer: &mut BufWriter<fs::File>,
    temp_path: &Path,
) -> Result<(String, u64)> {
    let total_chunks = total_blocks.div_ceil(blocks_per_read as u64);
    let limiter = Arc::new(Semaphore::new(parallel_chunks));
    let mut join_set = JoinSet::new();
    let mut next_chunk_to_spawn = 0u64;
    let mut next_chunk_to_write = 0u64;
    let mut pending = BTreeMap::<u64, DigestChunkResult>::new();
    let mut hasher = Sha512::new();
    let mut size_bytes = 0u64;
    let mut saw_short_read = false;

    while next_chunk_to_spawn < total_chunks && join_set.len() < parallel_chunks && !saw_short_read
    {
        spawn_digest_chunk_reader(
            &mut join_set,
            next_chunk_to_spawn,
            reader.clone(),
            limiter.clone(),
            total_blocks,
            block_size,
            blocks_per_read,
        );
        next_chunk_to_spawn += 1;
    }

    while next_chunk_to_write < total_chunks {
        let joined = join_set
            .join_next()
            .await
            .ok_or_else(|| anyhow!("digest parallel worker stream ended unexpectedly"))?;
        let result = joined.map_err(|err| anyhow!("digest parallel task failed: {err}"))??;
        pending.insert(result.chunk_idx, result);

        while let Some(chunk) = pending.remove(&next_chunk_to_write) {
            if chunk.bytes.is_empty() {
                saw_short_read = true;
                next_chunk_to_write += 1;
                break;
            }

            hasher.update(&chunk.bytes);
            writer
                .write_all(&chunk.bytes)
                .with_context(|| format!("write materialized bytes to {}", temp_path.display()))?;

            size_bytes = size_bytes
                .checked_add(chunk.bytes.len() as u64)
                .ok_or_else(|| anyhow!("digest size overflow"))?;
            if chunk.bytes.len() < chunk.requested_bytes {
                saw_short_read = true;
            }

            next_chunk_to_write += 1;
        }

        while next_chunk_to_spawn < total_chunks
            && join_set.len() < parallel_chunks
            && !saw_short_read
        {
            spawn_digest_chunk_reader(
                &mut join_set,
                next_chunk_to_spawn,
                reader.clone(),
                limiter.clone(),
                total_blocks,
                block_size,
                blocks_per_read,
            );
            next_chunk_to_spawn += 1;
        }

        if saw_short_read && pending.is_empty() {
            break;
        }
    }

    while let Some(joined) = join_set.join_next().await {
        let _ = joined.map_err(|err| anyhow!("digest parallel task failed: {err}"))??;
    }

    Ok((format!("sha512:{:x}", hasher.finalize()), size_bytes))
}

fn compile_dt_overlay(dtso: &str) -> Result<Vec<u8>> {
    run_dtc(
        &["-@", "-I", "dts", "-O", "dtb", "-o", "-", "-"],
        dtso.as_bytes(),
        "compile DTS overlay",
    )
}

fn decompile_dt_overlay(dtbo: &[u8]) -> Result<String> {
    let output = run_dtc(
        &["-I", "dtb", "-O", "dts", "-o", "-", "-"],
        dtbo,
        "decompile DT overlay",
    )?;
    String::from_utf8(output).map_err(|err| anyhow!("dtc produced non-UTF8 output: {err}"))
}

fn run_dtc(args: &[&str], input: &[u8], context: &str) -> Result<Vec<u8>> {
    let mut child = Command::new("dtc")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning dtc to {context}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to open dtc stdin"))?;
    let write_result = stdin.write_all(input);
    drop(stdin);

    if let Err(err) = write_result {
        let output = child
            .wait_with_output()
            .with_context(|| format!("waiting for dtc after write failure for {context}"))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            return Err(err).with_context(|| format!("writing input to dtc for {context}"));
        }
        return Err(anyhow!(
            "writing input to dtc for {context}: {err}; dtc stderr: {stderr}"
        ));
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("waiting for dtc to {context}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            bail!("dtc failed to {context} (status: {})", output.status);
        }
        bail!("dtc failed to {context}: {stderr}");
    }
    Ok(output.stdout)
}

fn read_input_bytes(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("reading input from stdin")?;
        return Ok(buf);
    }

    fs::read(path).with_context(|| format!("reading {}", io_label(path)))
}

fn validate_binary_output(path: &str, command: &str, stdout_is_tty: bool) -> Result<()> {
    if path == "-" && stdout_is_tty {
        bail!(
            "{} output is binary and terminal output is disabled by default; use --output <FILE>",
            command
        );
    }
    Ok(())
}

fn write_output_bytes(path: &str, bytes: &[u8]) -> Result<()> {
    if path == "-" {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(bytes)
            .context("writing output to stdout")?;
        stdout.flush().context("flushing stdout")?;
        return Ok(());
    }

    fs::write(path, bytes).with_context(|| format!("writing {}", io_label(path)))
}

fn append_output_bytes(path: &str, bytes: &[u8]) -> Result<()> {
    if path == "-" {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(bytes)
            .context("writing output to stdout")?;
        stdout.flush().context("flushing stdout")?;
        return Ok(());
    }

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(path)
        .with_context(|| format!("opening {} for append", io_label(path)))?;
    file.write_all(bytes)
        .with_context(|| format!("appending {}", io_label(path)))
}

fn io_label(path: &str) -> String {
    if path == "-" {
        "stdin/stdout".to_string()
    } else {
        path.to_string()
    }
}

fn resolve_create_optimize_output(explicit: Option<&str>, create_output: &str) -> Result<String> {
    if let Some(explicit) = explicit {
        return Ok(explicit.to_string());
    }
    Ok(create_output.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastboop_core::{
        BootProfileArtifactSource, BootProfileRootfs, BootProfileRootfsFilesystemSource,
    };
    use gibblox_pipeline::PipelineSourceContent;
    use std::{
        collections::BTreeSet,
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn parses_nested_rootfs_pipeline_yaml() {
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: pmos-fajita
rootfs:
  fat:
    gpt:
      partlabel: rootfs
      android_sparseimg:
        xz:
          http: https://images.postmarketos.org/example.img.xz
"#,
        )
        .expect("parse manifest");

        match manifest.rootfs {
            BootProfileRootfs::Fat(_) => {}
            other => panic!("expected fat rootfs, got {other:?}"),
        }
    }

    #[test]
    fn parses_file_rootfs_source_yaml() {
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: local-erofs
rootfs:
  erofs:
    file: ./images/rootfs.ero
"#,
        )
        .expect("parse manifest");

        let source = manifest.rootfs.source();
        match source {
            BootProfileArtifactSource::File(source) => {
                assert_eq!(source.file, "./images/rootfs.ero")
            }
            other => panic!("expected file source, got {other:?}"),
        }
    }

    #[test]
    fn parses_ext4_rootfs_source_yaml() {
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: local-ext4
rootfs:
  ext4:
    file: ./images/rootfs.img
"#,
        )
        .expect("parse manifest");

        match manifest.rootfs {
            BootProfileRootfs::Ext4(_) => {}
            other => panic!("expected ext4 rootfs, got {other:?}"),
        }

        let source = manifest.rootfs.source();
        match source {
            BootProfileArtifactSource::File(source) => {
                assert_eq!(source.file, "./images/rootfs.img")
            }
            other => panic!("expected file source, got {other:?}"),
        }
    }

    #[test]
    fn parses_kernel_and_dtbs_profile_sources() {
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: pmos-fajita
rootfs:
  fat:
    gpt:
      index: 1
      android_sparseimg:
        xz:
          file: /tmp/rootfs.img.xz
kernel:
  path: /vmlinuz
  fat:
    gpt:
      index: 0
      android_sparseimg:
        xz:
          file: /tmp/rootfs.img.xz
dtbs:
  path: /dtbs
  fat:
    gpt:
      index: 0
      android_sparseimg:
        xz:
          file: /tmp/rootfs.img.xz
"#,
        )
        .expect("parse manifest");

        let kernel = manifest.kernel.expect("kernel source");
        assert_eq!(kernel.path, "/vmlinuz");
        let dtbs = manifest.dtbs.expect("dtbs source");
        assert_eq!(dtbs.path, "/dtbs");
    }

    #[test]
    fn parses_mbr_rootfs_source_yaml() {
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: pmos-arrow
rootfs:
  fat:
    mbr:
      index: 1
      android_sparseimg:
        xz:
          file: /var/home/sam/src/pmos/local-artifacts/arrow-db410c-console-20260223-1636.img.xz
"#,
        )
        .expect("parse manifest");

        match manifest.rootfs {
            BootProfileRootfs::Fat(_) => {
                let source = manifest.rootfs.source();
                match source {
                    BootProfileArtifactSource::Mbr(source) => {
                        assert_eq!(source.mbr.index, Some(1));
                        assert_eq!(source.mbr.partuuid, None);
                    }
                    other => panic!("expected mbr source, got {other:?}"),
                }
            }
            other => panic!("expected fat rootfs, got {other:?}"),
        }
    }

    #[test]
    fn parses_fat_profile_sources() {
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: pmos-fajita
rootfs:
  fat:
    gpt:
      index: 1
      android_sparseimg:
        xz:
          file: /tmp/rootfs.img.xz
kernel:
  path: /vmlinuz
  fat:
    gpt:
      index: 0
      android_sparseimg:
        xz:
          file: /tmp/rootfs.img.xz
dtbs:
  path: /dtbs
  fat:
    gpt:
      index: 0
      android_sparseimg:
        xz:
          file: /tmp/rootfs.img.xz
"#,
        )
        .expect("parse manifest");

        let kernel = manifest.kernel.expect("kernel source");
        assert_eq!(kernel.path, "/vmlinuz");
        match kernel.source {
            BootProfileRootfs::Fat(_) => {}
            other => panic!("expected fat kernel source, got {other:?}"),
        }

        let dtbs = manifest.dtbs.expect("dtbs source");
        assert_eq!(dtbs.path, "/dtbs");
        match dtbs.source {
            BootProfileRootfs::Fat(_) => {}
            other => panic!("expected fat dtbs source, got {other:?}"),
        }
    }

    #[test]
    fn parses_casync_rootfs_source_yaml() {
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: fedora-pocket
rootfs:
  ext4:
    casync:
      index: https://bleeding.fastboop.win/live-pocket-fedora/casync/indexes/compose-22240659617-1-bf887e869003.caibx
"#,
        )
        .expect("parse manifest");

        let source = manifest.rootfs.source();
        match source {
            BootProfileArtifactSource::Casync(source) => {
                assert!(source.casync.index.ends_with(".caibx"));
                assert_eq!(source.casync.chunk_store, None);
            }
            other => panic!("expected casync source, got {other:?}"),
        }
    }

    #[test]
    fn parses_ostree_rootfs_with_casync_shorthand_yaml() {
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: live-pocket-fedora
display_name: live-pocket-fedora
rootfs:
  ostree:
    erofs:
      casync: https://bleeding.fastboop.win/live-pocket-fedora/casync/indexes/compose-22240659617-1-bf887e869003.caibx
"#,
        )
        .expect("parse manifest");

        match &manifest.rootfs {
            BootProfileRootfs::Ostree(source) => match &source.ostree {
                BootProfileRootfsFilesystemSource::Erofs(_) => {}
                other => panic!("expected ostree erofs source, got {other:?}"),
            },
            other => panic!("expected ostree rootfs, got {other:?}"),
        }

        let source = manifest.rootfs.source();
        match source {
            BootProfileArtifactSource::Casync(source) => {
                assert!(source.casync.index.ends_with(".caibx"));
                assert_eq!(source.casync.chunk_store, None);
            }
            other => panic!("expected casync source, got {other:?}"),
        }
    }

    #[test]
    fn create_output_rejects_tty_stdout() {
        let err = validate_binary_output("-", "bootprofile create", true)
            .expect_err("expected tty stdout to be rejected");
        let message = format!("{err}");
        assert!(message.contains("terminal output is disabled by default"));
    }

    #[test]
    fn create_output_allows_non_tty_stdout() {
        assert!(
            validate_binary_output("-", "bootprofile create", false).is_ok(),
            "expected non-tty stdout to be allowed"
        );
    }

    #[test]
    fn create_optimize_default_output_follows_create_output() {
        let output = resolve_create_optimize_output(None, "/tmp/profile.fbp")
            .expect("resolve optimize output");
        assert_eq!(output, "/tmp/profile.fbp");

        let output = resolve_create_optimize_output(None, "-").expect("resolve stdout output");
        assert_eq!(output, "-");
    }

    #[test]
    fn optimize_output_rejects_tty_stdout() {
        let err = validate_binary_output("-", "bootprofile optimize", true)
            .expect_err("expected tty stdout to be rejected");
        let message = format!("{err}");
        assert!(message.contains("terminal output is disabled by default"));
    }

    #[test]
    fn digest_filename_uses_sha512_hex() {
        let digest = format!("sha512:{}", "a".repeat(128));
        let filename = digest_to_cache_filename(&digest).expect("derive digest filename");
        assert_eq!(filename, "a".repeat(128));
    }

    #[test]
    fn digest_filename_rejects_non_sha512() {
        let err = digest_to_cache_filename("sha256:abcd").expect_err("reject non-sha512");
        let message = format!("{err}");
        assert!(message.contains("expected sha512 digest"));
    }

    #[test]
    fn materialized_prune_candidates_skip_protected_files() {
        let cache_dir = temp_path("materialized-cache");
        fs::create_dir_all(&cache_dir).expect("create cache dir");

        let protected = cache_dir.join("protected.bin");
        let prunable = cache_dir.join("prunable.bin");
        fs::write(&protected, b"abc").expect("write protected file");
        fs::write(&prunable, b"xyz").expect("write prunable file");

        let mut protected_paths = BTreeSet::new();
        protected_paths.insert(protected.clone());
        let candidates = list_materialized_prune_candidates(&cache_dir, &protected_paths)
            .expect("list prune candidates");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, prunable);

        let _ = fs::remove_file(protected);
        let _ = fs::remove_file(cache_dir.join("prunable.bin"));
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn insert_android_sparse_hint_dedupes_duplicate_identity() {
        let mut entries = BTreeMap::new();
        let identity = String::from("android_sparseimg{source=file{path=len:7:/a.simg;}};");

        insert_android_sparse_hint(&mut entries, identity.clone(), sparse_index_fixture())
            .expect("insert first hint");
        insert_android_sparse_hint(&mut entries, identity.clone(), sparse_index_fixture())
            .expect("duplicate identity should be ignored");

        let entry = entries.get(&identity).expect("entry exists");
        assert_eq!(entry.hints.len(), 1);
    }

    #[test]
    fn optimize_collects_sparse_hints_deterministically() {
        let first_sparse = write_temp_sparse_image("first");
        let second_sparse = write_temp_sparse_image("second");

        let manifest: BootProfileManifest = serde_yaml::from_str(
            format!(
                "id: optimize-order\nrootfs:\n  ext4:\n    android_sparseimg:\n      file: '{}'\nkernel:\n  path: /vmlinuz\n  ext4:\n    android_sparseimg:\n      file: '{}'\n",
                second_sparse.display(),
                first_sparse.display(),
            )
            .as_str(),
        )
        .expect("parse manifest");

        let profile = manifest
            .compile_dt_overlays::<core::convert::Infallible, _>(|_| unreachable!())
            .expect("compile profile");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");

        let hints = runtime
            .block_on(async {
                let mut resolver = ArtifactReaderResolver::new();
                collect_profile_pipeline_hints(&profile, &mut resolver).await
            })
            .expect("collect profile pipeline hints");

        assert_eq!(hints.entries.len(), 2);
        let mut identities: Vec<&str> = hints
            .entries
            .iter()
            .map(|entry| entry.pipeline_identity.as_str())
            .collect();
        let mut sorted = identities.clone();
        sorted.sort_unstable();
        assert_eq!(identities, sorted);

        for entry in &hints.entries {
            assert_eq!(entry.hints.len(), 2);
            let sparse = entry
                .hints
                .iter()
                .find_map(|hint| match hint {
                    PipelineHint::AndroidSparseIndex(index) => Some(index),
                    PipelineHint::TarEntryIndex(_) => None,
                    PipelineHint::ContentDigest(_) => None,
                })
                .expect("android sparse hint exists");
            let digest = entry
                .hints
                .iter()
                .find_map(|hint| match hint {
                    PipelineHint::ContentDigest(digest) => Some(digest),
                    PipelineHint::AndroidSparseIndex(_) => None,
                    PipelineHint::TarEntryIndex(_) => None,
                })
                .expect("content digest hint exists");
            assert_eq!(sparse.total_blks, 2);
            assert_eq!(sparse.total_chunks, 2);
            assert_eq!(sparse.chunks.len(), 2);
            assert!(digest.digest.starts_with("sha512:"));
            assert_eq!(digest.size_bytes, 16);
        }

        let _ = fs::remove_file(first_sparse);
        let _ = fs::remove_file(second_sparse);

        identities.sort_unstable();
        assert_eq!(identities, sorted);
    }

    #[test]
    fn hydrate_profile_file_content_populates_bare_file_sources() {
        let rootfs_path = temp_path("hydrate-rootfs.img");
        let kernel_path = temp_path("hydrate-kernel.img");
        fs::write(&rootfs_path, b"rootfs fixture bytes").expect("write rootfs fixture");
        fs::write(&kernel_path, b"kernel fixture bytes").expect("write kernel fixture");

        let yaml = format!(
            "id: local-hydrate\nrootfs:\n  ext4:\n    gpt:\n      index: 1\n      android_sparseimg:\n        file: '{}'\nkernel:\n  path: /vmlinuz\n  fat:\n    file: '{}'\n",
            rootfs_path.display(),
            kernel_path.display(),
        );
        let manifest: BootProfileManifest =
            serde_yaml::from_str(&yaml).expect("parse hydrate manifest");

        let mut compiled = manifest
            .compile_dt_overlays::<core::convert::Infallible, _>(|_| unreachable!())
            .expect("compile profile");

        assert!(
            validate_boot_profile(&compiled).is_err(),
            "bare file sources should fail validation before hydration"
        );

        hydrate_profile_file_content(&mut compiled).expect("hydrate file content");
        validate_boot_profile(&compiled).expect("validation after hydration");

        fn rootfs_file_content(profile: &BootProfile) -> PipelineSourceContent {
            match profile.rootfs.source() {
                BootProfileArtifactSource::Gpt(gpt) => match gpt.gpt.source.as_ref() {
                    BootProfileArtifactSource::AndroidSparseImg(sparse) => {
                        match sparse.android_sparseimg.source.as_ref() {
                            BootProfileArtifactSource::File(file) => file
                                .content
                                .as_ref()
                                .expect("rootfs file content populated")
                                .clone(),
                            other => panic!("expected file inner source, got {other:?}"),
                        }
                    }
                    other => panic!("expected android_sparseimg inner source, got {other:?}"),
                },
                other => panic!("expected gpt root source, got {other:?}"),
            }
        }

        let rootfs_content = rootfs_file_content(&compiled);
        assert!(rootfs_content.digest.starts_with("sha512:"));
        assert_eq!(
            rootfs_content.size_bytes,
            b"rootfs fixture bytes".len() as u64
        );

        let kernel = compiled.kernel.as_ref().expect("kernel populated");
        let kernel_content = match kernel.artifact_source() {
            BootProfileArtifactSource::File(file) => file
                .content
                .as_ref()
                .expect("kernel file content populated"),
            other => panic!("expected kernel file source, got {other:?}"),
        };
        assert!(kernel_content.digest.starts_with("sha512:"));
        assert_eq!(
            kernel_content.size_bytes,
            b"kernel fixture bytes".len() as u64
        );

        hydrate_profile_file_content(&mut compiled).expect("second hydration is a no-op");
        let rootfs_content_after = rootfs_file_content(&compiled);
        assert_eq!(rootfs_content_after.digest, rootfs_content.digest);

        let _ = fs::remove_file(rootfs_path);
        let _ = fs::remove_file(kernel_path);
    }

    const SPARSE_MAGIC: u32 = 0xED26_FF3A;
    const SPARSE_MAJOR_VERSION: u16 = 1;
    const CHUNK_TYPE_RAW: u16 = 0xCAC1;
    const CHUNK_TYPE_DONT_CARE: u16 = 0xCAC3;

    fn sparse_index_fixture() -> AndroidSparseImageIndex {
        AndroidSparseImageIndex {
            file_hdr_sz: 28,
            chunk_hdr_sz: 12,
            blk_sz: 8,
            total_blks: 2,
            total_chunks: 2,
            image_checksum: 0,
            chunks: vec![
                gibblox_android_sparse::AndroidSparseChunkIndex {
                    chunk_index: 0,
                    chunk_type: CHUNK_TYPE_RAW,
                    chunk_sz: 1,
                    total_sz: 20,
                    chunk_offset: 28,
                    payload_offset: 40,
                    payload_size: 8,
                    output_start: Some(0),
                    output_end: Some(8),
                    fill_pattern: None,
                    crc32: None,
                },
                gibblox_android_sparse::AndroidSparseChunkIndex {
                    chunk_index: 1,
                    chunk_type: CHUNK_TYPE_DONT_CARE,
                    chunk_sz: 1,
                    total_sz: 12,
                    chunk_offset: 48,
                    payload_offset: 60,
                    payload_size: 0,
                    output_start: Some(8),
                    output_end: Some(16),
                    fill_pattern: None,
                    crc32: None,
                },
            ],
        }
    }

    fn write_temp_sparse_image(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        path.push(format!(
            "fastboop-bootprofile-optimize-{label}-{nonce}.simg"
        ));
        fs::write(&path, sparse_image_fixture()).expect("write sparse fixture");
        path
    }

    fn temp_path(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        path.push(format!("fastboop-{label}-{nonce}"));
        path
    }

    fn sparse_image_fixture() -> Vec<u8> {
        let mut out = Vec::new();
        append_sparse_header(&mut out, 8, 2, 2, 28, 12);
        append_raw_chunk(&mut out, 1, b"ABCDEFGH", 12);
        append_dont_care_chunk(&mut out, 1, 12);
        out
    }

    fn append_sparse_header(
        out: &mut Vec<u8>,
        blk_sz: u32,
        total_blks: u32,
        total_chunks: u32,
        file_hdr_sz: u16,
        chunk_hdr_sz: u16,
    ) {
        out.extend_from_slice(&SPARSE_MAGIC.to_le_bytes());
        out.extend_from_slice(&SPARSE_MAJOR_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&file_hdr_sz.to_le_bytes());
        out.extend_from_slice(&chunk_hdr_sz.to_le_bytes());
        out.extend_from_slice(&blk_sz.to_le_bytes());
        out.extend_from_slice(&total_blks.to_le_bytes());
        out.extend_from_slice(&total_chunks.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.resize(file_hdr_sz as usize, 0);
    }

    fn append_raw_chunk(out: &mut Vec<u8>, blocks: u32, payload: &[u8], chunk_hdr_sz: u16) {
        append_chunk_header(
            out,
            CHUNK_TYPE_RAW,
            blocks,
            (chunk_hdr_sz as u32) + (payload.len() as u32),
            chunk_hdr_sz,
        );
        out.extend_from_slice(payload);
    }

    fn append_dont_care_chunk(out: &mut Vec<u8>, blocks: u32, chunk_hdr_sz: u16) {
        append_chunk_header(
            out,
            CHUNK_TYPE_DONT_CARE,
            blocks,
            chunk_hdr_sz as u32,
            chunk_hdr_sz,
        );
    }

    fn append_chunk_header(
        out: &mut Vec<u8>,
        chunk_type: u16,
        chunk_sz: u32,
        total_sz: u32,
        chunk_hdr_sz: u16,
    ) {
        out.extend_from_slice(&chunk_type.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&chunk_sz.to_le_bytes());
        out.extend_from_slice(&total_sz.to_le_bytes());
        out.resize(out.len() + (chunk_hdr_sz as usize - 12), 0);
    }
}
