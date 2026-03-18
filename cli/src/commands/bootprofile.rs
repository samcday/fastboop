use std::collections::BTreeMap;
use std::fs;
use std::future::Future;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use fastboop_core::{
    BootProfile, BootProfileArtifactSource, BootProfileManifest, decode_boot_profile,
    encode_boot_profile, validate_boot_profile,
};
use gibblox_android_sparse::{AndroidSparseBlockReader, AndroidSparseImageIndex};
use gibblox_core::{BlockReader, ReadContext};
use gibblox_pipeline::{
    PipelineAndroidSparseChunkIndexHint, PipelineAndroidSparseIndexHint, PipelineContentDigestHint,
    PipelineHint, PipelineHintEntry, PipelineHints, encode_pipeline_hints,
    pipeline_identity_string,
};
use sha2::{Digest, Sha512};
use tracing::{debug, info};

use super::ArtifactReaderResolver;

#[derive(Args)]
pub struct BootProfileArgs {
    #[command(subcommand)]
    pub command: BootProfileCommand,
}

#[derive(Subcommand)]
pub enum BootProfileCommand {
    /// Compile a YAML/JSON boot profile into binary form.
    Create(BootProfileCreateArgs),
    /// Render a compiled boot profile binary as YAML.
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
    /// Input compiled boot profile path ("-" for stdin).
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Output YAML path ("-" for stdout).
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
        BootProfileCommand::Show(args) => run_show(args),
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

    let compiled = manifest
        .compile_dt_overlays(compile_dt_overlay)
        .context("compiling dt_overlays with dtc")?;

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
        let hint_bytes = encode_pipeline_hints(&hints).map_err(|err| anyhow!("{err}"))?;
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

fn run_show(args: BootProfileShowArgs) -> Result<()> {
    debug!(
        input = %io_label(&args.input),
        output = %io_label(&args.output),
        "bootprofile show started"
    );

    let input = read_input_bytes(&args.input)?;
    debug!(bytes = input.len(), "bootprofile show read binary bytes");

    let compiled = decode_boot_profile(&input).map_err(|err| anyhow!("{err}"))?;
    debug!(profile_id = %compiled.id, "bootprofile show decoded boot profile");

    validate_boot_profile(&compiled).map_err(|err| anyhow!("{err}"))?;

    let manifest = compiled
        .decompile_dt_overlays(decompile_dt_overlay)
        .context("decompiling dt_overlays with dtc")?;

    let yaml = serde_yaml::to_string(&manifest).context("serializing boot profile YAML")?;
    write_output_bytes(&args.output, yaml.as_bytes())?;
    debug!(
        profile_id = %manifest.id,
        yaml_bytes = yaml.len(),
        "bootprofile show finished"
    );
    Ok(())
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
    let bytes = encode_pipeline_hints(&hints).map_err(|err| anyhow!("{err}"))?;
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

    info!(profile_id = %profile.id, "collecting rootfs pipeline hints");

    collect_pipeline_hints_from_artifact_source(profile.rootfs.source(), resolver, &mut entries)
        .await
        .context("materializing rootfs pipeline hints")?;

    if let Some(kernel) = profile.kernel.as_ref() {
        info!(profile_id = %profile.id, "collecting kernel pipeline hints");
        collect_pipeline_hints_from_artifact_source(
            kernel.artifact_source(),
            resolver,
            &mut entries,
        )
        .await
        .context("materializing kernel pipeline hints")?;
    }

    if let Some(dtbs) = profile.dtbs.as_ref() {
        info!(profile_id = %profile.id, "collecting dtbs pipeline hints");
        collect_pipeline_hints_from_artifact_source(dtbs.artifact_source(), resolver, &mut entries)
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
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        match source {
            BootProfileArtifactSource::Xz(source) => {
                collect_pipeline_hints_from_artifact_source(source.xz.as_ref(), resolver, entries)
                    .await?;

                if source.content.is_none() {
                    let pipeline_identity =
                        pipeline_identity_string(&BootProfileArtifactSource::Xz(source.clone()));
                    let reader = resolver
                        .open_artifact_source(&BootProfileArtifactSource::Xz(source.clone()))
                        .await?;
                    let digest_hint =
                        digest_reader_content(reader, pipeline_identity.as_str()).await?;
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
                )
                .await?;

                let pipeline_identity = pipeline_identity_string(
                    &BootProfileArtifactSource::AndroidSparseImg(source.clone()),
                );

                let upstream = resolver
                    .open_artifact_source(source.android_sparseimg.source.as_ref())
                    .await?;
                info!(
                    pipeline_identity = %pipeline_identity,
                    "materializing android sparse index hint"
                );
                let reader = AndroidSparseBlockReader::new(upstream)
                    .await
                    .map_err(|err| anyhow!("open android sparse reader: {err}"))?;
                let index = reader
                    .materialize_index()
                    .await
                    .map_err(|err| anyhow!("materialize android sparse index: {err}"))?;
                insert_android_sparse_hint(entries, pipeline_identity.clone(), index)?;

                if source.android_sparseimg.content.is_none() {
                    let reader = resolver
                        .open_artifact_source(&BootProfileArtifactSource::AndroidSparseImg(
                            source.clone(),
                        ))
                        .await?;
                    let digest_hint =
                        digest_reader_content(reader, pipeline_identity.as_str()).await?;
                    insert_pipeline_hint(
                        entries,
                        pipeline_identity,
                        PipelineHint::ContentDigest(digest_hint),
                    )?;
                }
                Ok(())
            }
            BootProfileArtifactSource::Mbr(source) => {
                collect_pipeline_hints_from_artifact_source(
                    source.mbr.source.as_ref(),
                    resolver,
                    entries,
                )
                .await?;

                if source.mbr.content.is_none() {
                    let pipeline_identity =
                        pipeline_identity_string(&BootProfileArtifactSource::Mbr(source.clone()));
                    let reader = resolver
                        .open_artifact_source(&BootProfileArtifactSource::Mbr(source.clone()))
                        .await?;
                    let digest_hint =
                        digest_reader_content(reader, pipeline_identity.as_str()).await?;
                    insert_pipeline_hint(
                        entries,
                        pipeline_identity,
                        PipelineHint::ContentDigest(digest_hint),
                    )?;
                }
                Ok(())
            }
            BootProfileArtifactSource::Gpt(source) => {
                collect_pipeline_hints_from_artifact_source(
                    source.gpt.source.as_ref(),
                    resolver,
                    entries,
                )
                .await?;

                if source.gpt.content.is_none() {
                    let pipeline_identity =
                        pipeline_identity_string(&BootProfileArtifactSource::Gpt(source.clone()));
                    let reader = resolver
                        .open_artifact_source(&BootProfileArtifactSource::Gpt(source.clone()))
                        .await?;
                    let digest_hint =
                        digest_reader_content(reader, pipeline_identity.as_str()).await?;
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
        bail!(
            "duplicate pipeline hint type for identity '{}' is not allowed",
            pipeline_identity
        );
    }
    entry.hints.push(hint);
    Ok(())
}

fn hint_discriminant(hint: &PipelineHint) -> &'static str {
    match hint {
        PipelineHint::AndroidSparseIndex(_) => "android-sparse-index",
        PipelineHint::ContentDigest(_) => "content-digest",
    }
}

async fn digest_reader_content(
    reader: Arc<dyn BlockReader>,
    pipeline_identity: &str,
) -> Result<PipelineContentDigestHint> {
    let block_size = reader.block_size() as usize;
    if block_size == 0 {
        bail!("reader block size is zero");
    }

    let total_blocks = reader.total_blocks().await?;
    info!(
        pipeline_identity,
        total_blocks, block_size, "digesting pipeline content"
    );
    let mut hasher = Sha512::new();
    let mut size_bytes = 0u64;
    let mut buf = vec![0u8; block_size];

    for lba in 0..total_blocks {
        let read = reader
            .read_blocks(lba, buf.as_mut_slice(), ReadContext::BACKGROUND)
            .await?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        size_bytes = size_bytes
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("digest size overflow"))?;
        if read < block_size {
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
    use std::{
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
    fn insert_android_sparse_hint_rejects_duplicate_identity() {
        let mut entries = BTreeMap::new();
        let identity = String::from("android_sparseimg{source=file{path=len:7:/a.simg;}};");

        insert_android_sparse_hint(&mut entries, identity.clone(), sparse_index_fixture())
            .expect("insert first hint");
        let err = insert_android_sparse_hint(&mut entries, identity, sparse_index_fixture())
            .expect_err("duplicate identity should fail");

        assert!(
            format!("{err}").contains("duplicate pipeline hint type"),
            "unexpected error: {err}"
        );
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
                    PipelineHint::ContentDigest(_) => None,
                })
                .expect("android sparse hint exists");
            let digest = entry
                .hints
                .iter()
                .find_map(|hint| match hint {
                    PipelineHint::ContentDigest(digest) => Some(digest),
                    PipelineHint::AndroidSparseIndex(_) => None,
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
