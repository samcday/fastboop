use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::future::Future;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result, anyhow, bail};
use fastboop_core::{
    BootProfile, BootProfileArtifactSource, BootProfileManifest, encode_boot_profile,
    encode_channel_pipeline_hints_record, validate_boot_profile,
};
use gibblox_android_sparse::{AndroidSparseBlockReader, AndroidSparseImageIndex};
use gibblox_cache::CachedBlockReader;
use gibblox_cache_store_std::StdCacheOps;
use gibblox_casync::{CasyncBlockReader, CasyncReaderConfig};
use gibblox_casync_std::{
    StdCasyncChunkStore, StdCasyncChunkStoreConfig, StdCasyncChunkStoreLocator,
    StdCasyncIndexLocator, StdCasyncIndexSource,
};
use gibblox_core::{
    AlignedByteReader, BlockByteReader, BlockReader, GptBlockReader, GptPartitionSelector,
    ReadContext,
};
use gibblox_file::FileReader;
use gibblox_http::HttpReader;
use gibblox_mbr::{MbrBlockReader, MbrPartitionSelector};
use gibblox_pipeline::{
    PipelineAndroidSparseChunkIndexHint, PipelineAndroidSparseIndexHint, PipelineContentDigestHint,
    PipelineHint, PipelineHintEntry, PipelineHints, PipelineSource, PipelineSourceContent,
    pipeline_identity_string,
};
use gibblox_xz::XzBlockReader;
use sha2::{Digest, Sha512};
use tracing::info;
use url::Url;

const DEFAULT_IMAGE_BLOCK_SIZE: u32 = 4096;

pub struct CompiledBootProfile {
    pub profile: BootProfile,
    pub bytes: Vec<u8>,
}

pub struct OptimizedBootProfile {
    pub hints: PipelineHints,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct BootProfileOptimizeOptions {
    pub local_artifacts: Vec<PathBuf>,
    pub materialized_cache_dir: Option<PathBuf>,
}

pub fn compile_manifest_yaml(bytes: &[u8]) -> Result<CompiledBootProfile> {
    let manifest: BootProfileManifest =
        serde_yaml::from_slice(bytes).context("parsing boot profile document")?;
    let mut profile = manifest
        .compile_dt_overlays(compile_dt_overlay)
        .context("compiling dt_overlays with dtc")?;
    hydrate_profile_file_content(&mut profile)?;
    validate_boot_profile(&profile).map_err(|err| anyhow!("{err}"))?;
    let bytes = encode_boot_profile(&profile).context("encoding boot profile binary")?;
    Ok(CompiledBootProfile { profile, bytes })
}

pub async fn optimize_boot_profile(
    profile: &BootProfile,
    options: BootProfileOptimizeOptions,
) -> Result<OptimizedBootProfile> {
    validate_boot_profile(profile).map_err(|err| anyhow!("{err}"))?;
    let mut resolver = ArtifactReaderResolver::with_local_artifacts(&options.local_artifacts)?;
    let hints = collect_profile_pipeline_hints(profile, &mut resolver, options).await?;
    let bytes = encode_channel_pipeline_hints_record(&hints).map_err(|err| anyhow!("{err}"))?;
    Ok(OptimizedBootProfile { hints, bytes })
}

pub async fn compile_manifest_yaml_with_optimize(
    bytes: &[u8],
    options: BootProfileOptimizeOptions,
) -> Result<(CompiledBootProfile, OptimizedBootProfile)> {
    let compiled = compile_manifest_yaml(bytes)?;
    let optimized = optimize_boot_profile(&compiled.profile, options).await?;
    Ok((compiled, optimized))
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

fn hydrate_pipeline_file_content(
    source: &mut PipelineSource,
    cache: &mut HashMap<PathBuf, PipelineSourceContent>,
) -> Result<()> {
    match source {
        PipelineSource::File(file) => {
            if file.content.is_some() {
                return Ok(());
            }
            let path = Path::new(file.file.as_str());
            let canonical = fs::canonicalize(path)
                .with_context(|| format!("canonicalize file pipeline source {}", path.display()))?;
            if let Some(cached) = cache.get(&canonical) {
                file.content = Some(cached.clone());
                return Ok(());
            }
            let metadata = fs::metadata(&canonical)
                .with_context(|| format!("stat file pipeline source {}", canonical.display()))?;
            if !metadata.is_file() {
                bail!(
                    "file pipeline source {} is not a regular file",
                    canonical.display()
                );
            }
            let content = PipelineSourceContent {
                digest: sha512_file(&canonical)?,
                size_bytes: metadata.len(),
            };
            cache.insert(canonical, content.clone());
            file.content = Some(content);
            Ok(())
        }
        PipelineSource::Http(_) | PipelineSource::Casync(_) => Ok(()),
        PipelineSource::Xz(source) => hydrate_pipeline_file_content(source.xz.as_mut(), cache),
        PipelineSource::AndroidSparseImg(source) => {
            hydrate_pipeline_file_content(source.android_sparseimg.source.as_mut(), cache)
        }
        PipelineSource::Mbr(source) => {
            hydrate_pipeline_file_content(source.mbr.source.as_mut(), cache)
        }
        PipelineSource::Gpt(source) => {
            hydrate_pipeline_file_content(source.gpt.source.as_mut(), cache)
        }
    }
}

async fn collect_profile_pipeline_hints(
    profile: &BootProfile,
    resolver: &mut ArtifactReaderResolver,
    options: BootProfileOptimizeOptions,
) -> Result<PipelineHints> {
    let mut entries = BTreeMap::new();
    let mut visited_wrappers = BTreeSet::new();
    let mut digest_cache = BTreeMap::new();
    let mut materialized_cache = MaterializedCache::new(options.materialized_cache_dir)?;

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

    if let Some(kernel) = profile.kernel.as_ref() {
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
    }

    if let Some(dtbs) = profile.dtbs.as_ref() {
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
    }

    Ok(PipelineHints {
        entries: entries.into_values().collect(),
    })
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
                    );
                }
                Ok(())
            }
            BootProfileArtifactSource::AndroidSparseImg(source) => {
                let android_sparse_source = source.clone();
                collect_pipeline_hints_from_artifact_source(
                    source.android_sparseimg.source.as_ref(),
                    resolver,
                    entries,
                    visited_wrappers,
                    digest_cache,
                    materialized_cache,
                )
                .await?;

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
                    let reader = AndroidSparseBlockReader::new(upstream)
                        .await
                        .map_err(|err| anyhow!("open android sparse reader: {err}"))?;
                    let index = reader
                        .materialize_index()
                        .await
                        .map_err(|err| anyhow!("materialize android sparse index: {err}"))?;
                    insert_android_sparse_hint(entries, pipeline_identity.clone(), index);

                    let reader: Arc<dyn BlockReader> = Arc::new(reader);
                    let materialized = digest_and_materialize_reader_content(
                        reader,
                        pipeline_identity.as_str(),
                        materialized_cache,
                    )
                    .await?;
                    materialized_cache.register_materialized_source(
                        resolver,
                        &source,
                        materialized.hint.digest.as_str(),
                        materialized.block_size,
                    )?;
                    digest_cache.insert(
                        artifact_source_cache_key(&source)?,
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
                    );
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
                    );
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
                    );
                }
                Ok(())
            }
            BootProfileArtifactSource::Http(_)
            | BootProfileArtifactSource::File(_)
            | BootProfileArtifactSource::Casync(_) => Ok(()),
        }
    })
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
    let materialized =
        digest_and_materialize_reader_content(reader, pipeline_identity, materialized_cache)
            .await?;
    materialized_cache.register_materialized_source(
        resolver,
        source,
        materialized.hint.digest.as_str(),
        materialized.block_size,
    )?;
    digest_cache.insert(
        artifact_source_cache_key(source)?,
        materialized.hint.clone(),
    );
    visited_wrappers.insert(pipeline_identity.to_string());
    Ok(materialized.hint)
}

async fn load_content_digest_hint(
    source: &BootProfileArtifactSource,
    pipeline_identity: &str,
    resolver: &mut ArtifactReaderResolver,
    digest_cache: &mut BTreeMap<String, PipelineContentDigestHint>,
) -> Result<PipelineContentDigestHint> {
    let cache_key = artifact_source_cache_key(source)?;
    if let Some(hint) = digest_cache.get(&cache_key).cloned() {
        return Ok(hint);
    }
    let reader = resolver.open_artifact_source(source).await?;
    let hint = digest_reader_content(reader, pipeline_identity).await?;
    digest_cache.insert(cache_key, hint.clone());
    Ok(hint)
}

fn insert_android_sparse_hint(
    entries: &mut BTreeMap<String, PipelineHintEntry>,
    pipeline_identity: String,
    index: AndroidSparseImageIndex,
) {
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
) {
    let entry = entries
        .entry(pipeline_identity.clone())
        .or_insert_with(|| PipelineHintEntry {
            pipeline_identity,
            hints: Vec::new(),
        });
    let duplicate = entry
        .hints
        .iter()
        .any(|existing| hint_discriminant(existing) == hint_discriminant(&hint));
    if !duplicate {
        entry.hints.push(hint);
    }
}

fn hint_discriminant(hint: &PipelineHint) -> &'static str {
    match hint {
        PipelineHint::AndroidSparseIndex(_) => "android-sparse-index",
        PipelineHint::ContentDigest(_) => "content-digest",
    }
}

#[derive(Default)]
struct ArtifactReaderResolver {
    cache: HashMap<String, Arc<dyn BlockReader>>,
    local_artifacts: HashMap<ArtifactContentKey, PathBuf>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ArtifactContentKey {
    digest: String,
    size_bytes: u64,
}

type OpenArtifactFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Arc<dyn BlockReader>>> + Send + 'a>>;

impl ArtifactReaderResolver {
    fn with_local_artifacts(paths: &[PathBuf]) -> Result<Self> {
        let mut resolver = Self::default();
        resolver.local_artifacts = build_local_artifact_index(paths)?;
        Ok(resolver)
    }

    fn substitute_artifact_source_with_file(
        &mut self,
        source: &BootProfileArtifactSource,
        path: &Path,
        block_size: u32,
    ) -> Result<()> {
        let cache_key = artifact_source_cache_key(source)?;
        let canonical = fs::canonicalize(path)
            .with_context(|| format!("canonicalize materialized path {}", path.display()))?;
        let file_reader = FileReader::open(&canonical, block_size)
            .map_err(|err| anyhow!("open materialized file {}: {err}", canonical.display()))?;
        self.cache.insert(cache_key, Arc::new(file_reader));
        Ok(())
    }

    fn open_artifact_source<'a>(
        &'a mut self,
        source: &'a BootProfileArtifactSource,
    ) -> OpenArtifactFuture<'a> {
        Box::pin(async move {
            if let Some(local_path) = self.match_local_artifact(source)? {
                let cache_key = format!("file:{}", local_path.display());
                if let Some(reader) = self.cache.get(&cache_key).cloned() {
                    return Ok(reader);
                }
                let file_reader =
                    FileReader::open(&local_path, DEFAULT_IMAGE_BLOCK_SIZE).map_err(|err| {
                        anyhow!("open local artifact {}: {err}", local_path.display())
                    })?;
                let reader: Arc<dyn BlockReader> = Arc::new(file_reader);
                self.cache.insert(cache_key, reader.clone());
                return Ok(reader);
            }

            let cache_key = artifact_source_cache_key(source)?;
            if let Some(reader) = self.cache.get(&cache_key).cloned() {
                return Ok(reader);
            }

            let reader: Arc<dyn BlockReader> = match source {
                BootProfileArtifactSource::Http(source) => {
                    let url = Url::parse(source.http.as_str())
                        .with_context(|| format!("parse HTTP artifact URL {}", source.http))?;
                    cache_artifact_reader(open_uncached_http_reader(url).await?).await?
                }
                BootProfileArtifactSource::File(source) => {
                    let path = Path::new(source.file.as_str());
                    let canonical = fs::canonicalize(path).with_context(|| {
                        format!("canonicalize file artifact path {}", path.display())
                    })?;
                    let file_reader = FileReader::open(&canonical, DEFAULT_IMAGE_BLOCK_SIZE)
                        .map_err(|err| {
                            anyhow!("open file artifact {}: {err}", canonical.display())
                        })?;
                    Arc::new(file_reader)
                }
                BootProfileArtifactSource::Casync(source) => {
                    let index_url =
                        Url::parse(source.casync.index.as_str()).with_context(|| {
                            format!("parse casync index URL {}", source.casync.index)
                        })?;
                    let chunk_store = source
                        .casync
                        .chunk_store
                        .as_deref()
                        .map(Url::parse)
                        .transpose()
                        .with_context(|| {
                            format!(
                                "parse casync chunk store URL {}",
                                source.casync.chunk_store.as_deref().unwrap_or_default()
                            )
                        })?;
                    cache_artifact_reader(open_casync_reader(index_url, chunk_store).await?).await?
                }
                BootProfileArtifactSource::Xz(source) => {
                    let upstream = self.open_artifact_source(source.xz.as_ref()).await?;
                    let upstream = AlignedByteReader::new(upstream)
                        .await
                        .map_err(|err| anyhow!("open aligned byte view for xz source: {err}"))?;
                    let reader = XzBlockReader::new_from_byte_reader(Arc::new(upstream))
                        .await
                        .map_err(|err| anyhow!("open xz block reader: {err}"))?;
                    let reader = BlockByteReader::new(reader, DEFAULT_IMAGE_BLOCK_SIZE)
                        .map_err(|err| anyhow!("open xz block view: {err}"))?;
                    Arc::new(reader)
                }
                BootProfileArtifactSource::AndroidSparseImg(source) => {
                    let upstream = self
                        .open_artifact_source(source.android_sparseimg.source.as_ref())
                        .await?;
                    let reader = AndroidSparseBlockReader::new(upstream)
                        .await
                        .map_err(|err| anyhow!("open android sparse reader: {err}"))?;
                    Arc::new(reader)
                }
                BootProfileArtifactSource::Mbr(source) => {
                    let selector = if let Some(partuuid) = source.mbr.partuuid.as_deref() {
                        MbrPartitionSelector::part_uuid(partuuid)
                    } else if let Some(index) = source.mbr.index {
                        MbrPartitionSelector::index(index)
                    } else {
                        bail!("boot profile MBR source missing selector")
                    };
                    let upstream = self
                        .open_artifact_source(source.mbr.source.as_ref())
                        .await?;
                    let reader = MbrBlockReader::new(upstream, selector, DEFAULT_IMAGE_BLOCK_SIZE)
                        .await
                        .map_err(|err| anyhow!("open MBR partition reader: {err}"))?;
                    Arc::new(reader)
                }
                BootProfileArtifactSource::Gpt(source) => {
                    let selector = if let Some(partlabel) = source.gpt.partlabel.as_deref() {
                        GptPartitionSelector::part_label(partlabel)
                    } else if let Some(partuuid) = source.gpt.partuuid.as_deref() {
                        GptPartitionSelector::part_uuid(partuuid)
                    } else if let Some(index) = source.gpt.index {
                        GptPartitionSelector::index(index)
                    } else {
                        bail!("boot profile GPT source missing selector")
                    };
                    let upstream = self
                        .open_artifact_source(source.gpt.source.as_ref())
                        .await?;
                    let reader = GptBlockReader::new(upstream, selector, DEFAULT_IMAGE_BLOCK_SIZE)
                        .await
                        .map_err(|err| anyhow!("open GPT partition reader: {err}"))?;
                    Arc::new(reader)
                }
            };

            self.cache.insert(cache_key, reader.clone());
            Ok(reader)
        })
    }

    fn match_local_artifact(&self, source: &PipelineSource) -> Result<Option<PathBuf>> {
        let Some(content) = artifact_source_content(source) else {
            return Ok(None);
        };
        let key = ArtifactContentKey {
            digest: content.digest.clone(),
            size_bytes: content.size_bytes,
        };
        Ok(self.local_artifacts.get(&key).cloned())
    }
}

fn artifact_source_content(source: &PipelineSource) -> Option<&PipelineSourceContent> {
    match source {
        PipelineSource::Http(source) => source.content.as_ref(),
        PipelineSource::File(source) => source.content.as_ref(),
        PipelineSource::Casync(source) => source.casync.content.as_ref(),
        PipelineSource::Xz(source) => source.content.as_ref(),
        PipelineSource::AndroidSparseImg(source) => source.android_sparseimg.content.as_ref(),
        PipelineSource::Mbr(source) => source.mbr.content.as_ref(),
        PipelineSource::Gpt(source) => source.gpt.content.as_ref(),
    }
}

fn artifact_source_cache_key(source: &BootProfileArtifactSource) -> Result<String> {
    match source {
        BootProfileArtifactSource::Http(source) => Ok(format!("http:{}", source.http)),
        BootProfileArtifactSource::File(source) => {
            let path = Path::new(source.file.as_str());
            let canonical = fs::canonicalize(path)
                .with_context(|| format!("canonicalize file artifact path {}", path.display()))?;
            Ok(format!("file:{}", canonical.display()))
        }
        BootProfileArtifactSource::Casync(source) => {
            let chunk_store = source.casync.chunk_store.as_deref().unwrap_or_default();
            Ok(format!("casync:{}:{}", source.casync.index, chunk_store))
        }
        BootProfileArtifactSource::Xz(source) => Ok(format!(
            "xz:{}",
            artifact_source_cache_key(source.xz.as_ref())?
        )),
        BootProfileArtifactSource::AndroidSparseImg(source) => Ok(format!(
            "android_sparseimg:{}",
            artifact_source_cache_key(source.android_sparseimg.source.as_ref())?
        )),
        BootProfileArtifactSource::Mbr(source) => {
            let selector = if let Some(partuuid) = source.mbr.partuuid.as_deref() {
                format!("partuuid={partuuid}")
            } else if let Some(index) = source.mbr.index {
                format!("index={index}")
            } else {
                bail!("boot profile MBR source missing selector")
            };
            Ok(format!(
                "mbr:{}:{}",
                selector,
                artifact_source_cache_key(source.mbr.source.as_ref())?
            ))
        }
        BootProfileArtifactSource::Gpt(source) => {
            let selector = if let Some(partlabel) = source.gpt.partlabel.as_deref() {
                format!("partlabel={partlabel}")
            } else if let Some(partuuid) = source.gpt.partuuid.as_deref() {
                format!("partuuid={partuuid}")
            } else if let Some(index) = source.gpt.index {
                format!("index={index}")
            } else {
                bail!("boot profile GPT source missing selector")
            };
            Ok(format!(
                "gpt:{}:{}",
                selector,
                artifact_source_cache_key(source.gpt.source.as_ref())?
            ))
        }
    }
}

fn build_local_artifact_index(paths: &[PathBuf]) -> Result<HashMap<ArtifactContentKey, PathBuf>> {
    let mut out = HashMap::new();
    for path in paths {
        let canonical = fs::canonicalize(path)
            .with_context(|| format!("canonicalize local artifact path {}", path.display()))?;
        let metadata = fs::metadata(&canonical)
            .with_context(|| format!("stat local artifact {}", canonical.display()))?;
        if !metadata.is_file() {
            bail!(
                "local artifact {} is not a regular file",
                canonical.display()
            );
        }
        let key = ArtifactContentKey {
            digest: sha512_file(&canonical)?,
            size_bytes: metadata.len(),
        };
        if let Some(existing) = out.insert(key, canonical.clone())
            && existing != canonical
        {
            bail!(
                "local artifact digest+size collision between {} and {}",
                existing.display(),
                canonical.display()
            );
        }
    }
    Ok(out)
}

async fn open_uncached_http_reader(url: Url) -> Result<Arc<dyn BlockReader>> {
    let http_reader = HttpReader::new(url.clone(), DEFAULT_IMAGE_BLOCK_SIZE)
        .await
        .map_err(|err| anyhow!("open HTTP reader {url}: {err}"))?;
    let block_reader = BlockByteReader::new(http_reader, DEFAULT_IMAGE_BLOCK_SIZE)
        .map_err(|err| anyhow!("open HTTP block view {url}: {err}"))?;
    Ok(Arc::new(block_reader))
}

async fn cache_artifact_reader(reader: Arc<dyn BlockReader>) -> Result<Arc<dyn BlockReader>> {
    let cache_root = default_gibblox_cache_root().join("pipelines");
    let cache_ops = StdCacheOps::open_in_for_reader(cache_root.as_path(), reader.as_ref())
        .await
        .map_err(|err| anyhow!("open pipeline cache file {}: {err}", cache_root.display()))?;
    let cached = CachedBlockReader::new(reader, cache_ops)
        .await
        .map_err(|err| anyhow!("open pipeline cached reader: {err}"))?;
    Ok(Arc::new(cached))
}

async fn open_casync_reader(
    index_url: Url,
    chunk_store_url: Option<Url>,
) -> Result<Arc<dyn BlockReader>> {
    let index_source = StdCasyncIndexSource::new(StdCasyncIndexLocator::url(index_url.clone()))
        .map_err(|err| anyhow!("open casync index source {index_url}: {err}"))?;
    let chunk_store_url = match chunk_store_url {
        Some(chunk_store_url) => chunk_store_url,
        None => derive_casync_chunk_store_url(&index_url)?,
    };
    let chunk_locator = StdCasyncChunkStoreLocator::url_prefix(chunk_store_url.clone())
        .map_err(|err| anyhow!("configure casync chunk store URL {chunk_store_url}: {err}"))?;
    let chunk_store = StdCasyncChunkStore::new(StdCasyncChunkStoreConfig::new(chunk_locator))
        .map_err(|err| anyhow!("build casync chunk store: {err}"))?;
    let reader = CasyncBlockReader::open(
        index_source,
        chunk_store,
        CasyncReaderConfig {
            block_size: DEFAULT_IMAGE_BLOCK_SIZE,
            strict_verify: false,
            identity: None,
        },
    )
    .await
    .map_err(|err| anyhow!("open casync reader {index_url}: {err}"))?;
    Ok(Arc::new(reader))
}

fn derive_casync_chunk_store_url(index_url: &Url) -> Result<Url> {
    if let Some(segments) = index_url.path_segments() {
        let segments: Vec<&str> = segments.collect();
        if let Some(index_pos) = segments.iter().rposition(|segment| *segment == "indexes") {
            let mut base_segments = segments[..=index_pos].to_vec();
            base_segments[index_pos] = "chunks";
            let mut url = index_url.clone();
            let mut path = String::from("/");
            path.push_str(&base_segments.join("/"));
            if !path.ends_with('/') {
                path.push('/');
            }
            url.set_path(&path);
            url.set_query(None);
            url.set_fragment(None);
            return Ok(url);
        }
    }
    index_url
        .join("./")
        .with_context(|| format!("derive casync chunk store URL from {index_url}"))
}

fn default_gibblox_cache_root() -> PathBuf {
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME")
        && !path.is_empty()
    {
        return PathBuf::from(path).join("gibblox");
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(path) = std::env::var_os("LOCALAPPDATA")
            && !path.is_empty()
        {
            return PathBuf::from(path).join("gibblox");
        }
    }
    if let Some(path) = std::env::var_os("HOME")
        && !path.is_empty()
    {
        return PathBuf::from(path).join(".cache").join("gibblox");
    }
    std::env::temp_dir().join("gibblox")
}

struct MaterializedCache {
    cache_dir: PathBuf,
}

struct MaterializedDigest {
    hint: PipelineContentDigestHint,
    block_size: u32,
}

impl MaterializedCache {
    fn new(cache_dir: Option<PathBuf>) -> Result<Self> {
        let cache_dir =
            cache_dir.unwrap_or_else(|| default_gibblox_cache_root().join("materialized"));
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("create materialized cache dir {}", cache_dir.display()))?;
        Ok(Self { cache_dir })
    }

    fn register_materialized_source(
        &self,
        resolver: &mut ArtifactReaderResolver,
        source: &BootProfileArtifactSource,
        digest: &str,
        block_size: u32,
    ) -> Result<()> {
        resolver.substitute_artifact_source_with_file(
            source,
            self.path_for_digest(digest)?.as_path(),
            block_size,
        )
    }

    fn create_temp_writer(&self) -> Result<(PathBuf, BufWriter<fs::File>)> {
        fs::create_dir_all(&self.cache_dir).with_context(|| {
            format!("create materialized cache dir {}", self.cache_dir.display())
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

    fn finalize_temp_file(&self, temp_path: &Path, digest: &str) -> Result<PathBuf> {
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

async fn digest_reader_content(
    reader: Arc<dyn BlockReader>,
    pipeline_identity: &str,
) -> Result<PipelineContentDigestHint> {
    let (digest, size_bytes, _block_size) =
        read_digest_and_optionally_materialize(reader, pipeline_identity, None).await?;
    Ok(PipelineContentDigestHint { digest, size_bytes })
}

async fn digest_and_materialize_reader_content(
    reader: Arc<dyn BlockReader>,
    pipeline_identity: &str,
    materialized_cache: &MaterializedCache,
) -> Result<MaterializedDigest> {
    let (temp_path, mut writer) = materialized_cache.create_temp_writer()?;
    let (digest, size_bytes, block_size) = read_digest_and_optionally_materialize(
        reader,
        pipeline_identity,
        Some((&mut writer, temp_path.as_path())),
    )
    .await?;
    writer
        .flush()
        .with_context(|| format!("flush materialized bytes to {}", temp_path.display()))?;
    drop(writer);
    let final_path = materialized_cache.finalize_temp_file(temp_path.as_path(), digest.as_str())?;
    info!(pipeline_identity, digest, size_bytes, cache_path = %final_path.display(), "materialized pipeline content");
    Ok(MaterializedDigest {
        hint: PipelineContentDigestHint { digest, size_bytes },
        block_size,
    })
}

async fn read_digest_and_optionally_materialize(
    reader: Arc<dyn BlockReader>,
    pipeline_identity: &str,
    mut materialize: Option<(&mut BufWriter<fs::File>, &Path)>,
) -> Result<(String, u64, u32)> {
    const DIGEST_CHUNK_TARGET_BYTES: usize = 32 * 1024 * 1024;

    let block_size = reader.block_size();
    if block_size == 0 {
        bail!("reader block size is zero");
    }
    let block_size_usize = block_size as usize;
    let blocks_per_read = core::cmp::max(1, DIGEST_CHUNK_TARGET_BYTES / block_size_usize);
    let total_blocks = reader.total_blocks().await?;
    info!(
        pipeline_identity,
        total_blocks, block_size, blocks_per_read, "digesting pipeline content"
    );

    let mut hasher = Sha512::new();
    let mut size_bytes = 0u64;
    let mut buf = vec![0u8; blocks_per_read * block_size_usize];
    let mut lba = 0u64;
    while lba < total_blocks {
        let remaining_blocks = total_blocks - lba;
        let requested_blocks = core::cmp::min(remaining_blocks, blocks_per_read as u64);
        let requested_bytes = requested_blocks as usize * block_size_usize;
        let read = reader
            .read_blocks(lba, &mut buf[..requested_bytes], ReadContext::BACKGROUND)
            .await?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        if let Some((writer, temp_path)) = materialize.as_mut() {
            writer
                .write_all(&buf[..read])
                .with_context(|| format!("write materialized bytes to {}", temp_path.display()))?;
        }
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
    Ok((
        format!("sha512:{:x}", hasher.finalize()),
        size_bytes,
        block_size,
    ))
}

fn sha512_file(path: &Path) -> Result<String> {
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::with_capacity(8 * 1024 * 1024, file);
    let mut hasher = Sha512::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let read = reader
            .read(&mut buf)
            .with_context(|| format!("read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("sha512:{:x}", hasher.finalize()))
}

fn compile_dt_overlay(dtso: &str) -> Result<Vec<u8>> {
    run_dtc(
        &["-@", "-I", "dts", "-O", "dtb", "-o", "-", "-"],
        dtso.as_bytes(),
        "compile DTS overlay",
    )
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
