use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use fastboop_bootpro::{BootProfileOptimizeOptions, compile_manifest_yaml, optimize_boot_profile};
use fastboop_core::{BootProfile, decode_boot_profile, validate_boot_profile};
use tracing::{debug, info};

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

    let compiled = compile_manifest_yaml(&input)
        .with_context(|| format!("compiling boot profile document {}", io_label(&args.input)))?;
    debug!(
        profile_id = %compiled.profile.id,
        bytes = compiled.bytes.len(),
        "bootprofile create encoded boot profile"
    );

    validate_binary_output(
        &args.output,
        "bootprofile create",
        std::io::stdout().is_terminal(),
    )?;
    write_output_bytes(&args.output, &compiled.bytes)?;

    if args.optimize {
        let optimize_output =
            resolve_create_optimize_output(args.optimize_output.as_deref(), args.output.as_str())?;
        let optimized = optimize_boot_profile(
            &compiled.profile,
            BootProfileOptimizeOptions {
                local_artifacts: args.local_artifact,
                materialized_cache_dir: None,
            },
        )
        .await?;
        validate_binary_output(
            optimize_output.as_str(),
            "bootprofile optimize",
            std::io::stdout().is_terminal(),
        )?;
        if optimize_output == args.output {
            append_output_bytes(optimize_output.as_str(), optimized.bytes.as_slice())?;
        } else {
            write_output_bytes(optimize_output.as_str(), optimized.bytes.as_slice())?;
        }
        info!(
            profile_id = %compiled.profile.id,
            output = %io_label(optimize_output.as_str()),
            bytes = optimized.bytes.len(),
            "bootprofile create emitted optimize sidecar"
        );
    }

    debug!(
        output = %io_label(&args.output),
        "bootprofile create finished"
    );
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

    info!(
        profile_id = %compiled.id,
        local_artifacts = args.local_artifact.len(),
        "bootprofile optimize preparing artifact resolver"
    );
    info!(
        profile_id = %compiled.id,
        "bootprofile optimize collecting pipeline hints"
    );
    let optimized = optimize_boot_profile(
        &compiled,
        BootProfileOptimizeOptions {
            local_artifacts: args.local_artifact,
            materialized_cache_dir: None,
        },
    )
    .await?;
    info!(
        profile_id = %compiled.id,
        hint_entries = optimized.hints.entries.len(),
        bytes = optimized.bytes.len(),
        "bootprofile optimize materialized pipeline hints"
    );

    validate_binary_output(
        &args.output,
        "bootprofile optimize",
        std::io::stdout().is_terminal(),
    )?;
    write_output_bytes(&args.output, &optimized.bytes)?;
    debug!(
        output = %io_label(&args.output),
        "bootprofile optimize finished"
    );
    Ok(())
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
        BootProfileArtifactSource, BootProfileManifest, BootProfileRootfs,
        BootProfileRootfsFilesystemSource,
    };
    use gibblox_pipeline::{PipelineHint, PipelineSourceContent};
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

        match &manifest.rootfs {
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
    fn parses_stage0_kernel_modules_and_inject_mac_yaml() {
        let manifest: BootProfileManifest = serde_yaml::from_str(
            r#"
id: pmos-fajita
rootfs:
  erofs:
    file: ./images/rootfs.ero
stage0:
  kernel_modules:
    - dwc3
  inject_mac:
    bluetooth: qcom,wcn3990-bt
  devices:
    oneplus-fajita:
      stage0:
        kernel_modules:
          - gcc-sdm845
        inject_mac:
          wifi: qcom,wcn3990-wifi
"#,
        )
        .expect("parse manifest");

        assert_eq!(manifest.stage0.kernel_modules, vec!["dwc3".to_string()]);
        assert_eq!(
            manifest
                .stage0
                .inject_mac
                .as_ref()
                .and_then(|mac| mac.bluetooth.as_deref()),
            Some("qcom,wcn3990-bt")
        );
        let device = manifest
            .stage0
            .devices
            .get("oneplus-fajita")
            .expect("device override");
        assert_eq!(device.stage0.kernel_modules, vec!["gcc-sdm845".to_string()]);
        assert_eq!(
            device
                .stage0
                .inject_mac
                .as_ref()
                .and_then(|mac| mac.wifi.as_deref()),
            Some("qcom,wcn3990-wifi")
        );
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

        match &manifest.rootfs {
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
    fn optimize_collects_sparse_hints_deterministically() {
        let first_sparse = write_temp_sparse_image("first");
        let second_sparse = write_temp_sparse_image("second");
        let materialized_cache_dir = temp_path("materialized-cache");

        let yaml = format!(
            "id: optimize-order\nrootfs:\n  ext4:\n    android_sparseimg:\n      file: '{}'\nkernel:\n  path: /vmlinuz\n  ext4:\n    android_sparseimg:\n      file: '{}'\n",
            second_sparse.display(),
            first_sparse.display(),
        );
        let compiled = compile_manifest_yaml(yaml.as_bytes()).expect("compile profile");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");

        let optimized = runtime
            .block_on(async {
                optimize_boot_profile(
                    &compiled.profile,
                    BootProfileOptimizeOptions {
                        local_artifacts: Vec::new(),
                        materialized_cache_dir: Some(materialized_cache_dir.clone()),
                    },
                )
                .await
            })
            .expect("collect profile pipeline hints");

        assert_eq!(optimized.hints.entries.len(), 2);
        let mut identities: Vec<&str> = optimized
            .hints
            .entries
            .iter()
            .map(|entry| entry.pipeline_identity.as_str())
            .collect();
        let mut sorted = identities.clone();
        sorted.sort_unstable();
        assert_eq!(identities, sorted);

        for entry in &optimized.hints.entries {
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
        let _ = fs::remove_dir_all(materialized_cache_dir);

        identities.sort_unstable();
        assert_eq!(identities, sorted);
    }

    #[test]
    fn compile_manifest_yaml_populates_bare_file_sources() {
        let rootfs_path = temp_path("hydrate-rootfs.img");
        let kernel_path = temp_path("hydrate-kernel.img");
        fs::write(&rootfs_path, b"rootfs fixture bytes").expect("write rootfs fixture");
        fs::write(&kernel_path, b"kernel fixture bytes").expect("write kernel fixture");

        let yaml = format!(
            "id: local-hydrate\nrootfs:\n  ext4:\n    gpt:\n      index: 1\n      android_sparseimg:\n        file: '{}'\nkernel:\n  path: /vmlinuz\n  fat:\n    file: '{}'\n",
            rootfs_path.display(),
            kernel_path.display(),
        );

        let compiled = compile_manifest_yaml(yaml.as_bytes()).expect("compile profile");
        validate_boot_profile(&compiled.profile).expect("validation after hydration");

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

        let rootfs_content = rootfs_file_content(&compiled.profile);
        assert!(rootfs_content.digest.starts_with("sha512:"));
        assert_eq!(
            rootfs_content.size_bytes,
            b"rootfs fixture bytes".len() as u64
        );

        let kernel = compiled.profile.kernel.as_ref().expect("kernel populated");
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

        let _ = fs::remove_file(rootfs_path);
        let _ = fs::remove_file(kernel_path);
    }

    const SPARSE_MAGIC: u32 = 0xED26_FF3A;
    const SPARSE_MAJOR_VERSION: u16 = 1;
    const CHUNK_TYPE_RAW: u16 = 0xCAC1;
    const CHUNK_TYPE_DONT_CARE: u16 = 0xCAC3;

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
