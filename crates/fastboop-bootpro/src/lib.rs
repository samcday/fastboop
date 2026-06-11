use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use fastboop_core::{
    BootProfile, BootProfileArtifactSource, BootProfileManifest, encode_boot_profile,
    encode_channel_pipeline_hints_record, validate_boot_profile,
};
use gibblox_optimizer::{
    PipelineContentDigestOptions, PipelineOptimizeOptions, optimize_pipeline_hints,
};
use gibblox_pipeline::{
    LocalArtifactIndex, PipelineCachePolicy, PipelineHintEntry, PipelineHints, PipelineSource,
    PipelineSourceContent,
};
use sha2::{Digest, Sha512};

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
    let local_artifacts = LocalArtifactIndex::from_paths(&options.local_artifacts)?;
    let hints =
        collect_profile_pipeline_hints(profile, local_artifacts, options.materialized_cache_dir)
            .await?;
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
        PipelineSource::Tar(source) => {
            hydrate_pipeline_file_content(source.tar.source.as_mut(), cache)
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
    local_artifacts: LocalArtifactIndex,
    materialized_cache_dir: Option<PathBuf>,
) -> Result<PipelineHints> {
    let mut entries = BTreeMap::new();
    collect_artifact_source_pipeline_hints(
        profile.rootfs.source(),
        &local_artifacts,
        materialized_cache_dir.clone(),
        &mut entries,
    )
    .await
    .context("materializing rootfs pipeline hints")?;

    if let Some(kernel) = profile.kernel.as_ref() {
        collect_artifact_source_pipeline_hints(
            kernel.artifact_source(),
            &local_artifacts,
            materialized_cache_dir.clone(),
            &mut entries,
        )
        .await
        .context("materializing kernel pipeline hints")?;
    }

    if let Some(dtbs) = profile.dtbs.as_ref() {
        collect_artifact_source_pipeline_hints(
            dtbs.artifact_source(),
            &local_artifacts,
            materialized_cache_dir,
            &mut entries,
        )
        .await
        .context("materializing dtbs pipeline hints")?;
    }

    Ok(PipelineHints {
        entries: entries.into_values().collect(),
    })
}

async fn collect_artifact_source_pipeline_hints(
    source: &BootProfileArtifactSource,
    local_artifacts: &LocalArtifactIndex,
    materialized_cache_dir: Option<PathBuf>,
    entries: &mut BTreeMap<String, PipelineHintEntry>,
) -> Result<()> {
    let hints = optimize_pipeline_hints(
        source,
        &PipelineOptimizeOptions {
            image_block_size: DEFAULT_IMAGE_BLOCK_SIZE,
            cache_policy: PipelineCachePolicy::None,
            local_artifacts: Some(local_artifacts.clone()),
            content_digests: PipelineContentDigestOptions {
                enabled: true,
                materialize: true,
                cache_dir: materialized_cache_dir,
            },
            ..PipelineOptimizeOptions::default()
        },
    )
    .await?;

    for entry in hints.entries {
        merge_pipeline_hint_entry(entries, entry);
    }
    Ok(())
}

fn merge_pipeline_hint_entry(
    entries: &mut BTreeMap<String, PipelineHintEntry>,
    entry: PipelineHintEntry,
) {
    let out = entries
        .entry(entry.pipeline_identity.clone())
        .or_insert_with(|| PipelineHintEntry {
            pipeline_identity: entry.pipeline_identity,
            hints: Vec::new(),
        });
    for hint in entry.hints {
        if !out.hints.contains(&hint) {
            out.hints.push(hint);
        }
    }
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
