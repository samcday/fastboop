use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use fastboop_core::{
    BootProfile, BootProfileArtifactPathSource, BootProfileArtifactSource, BootProfileManifest,
    BootProfileRootfs, BootProfileRootfsFilesystemSource, decode_boot_profile, encode_boot_profile,
    validate_boot_profile,
};
use gibblox_pipeline::{OptimizePipelineOptions, OptimizePipelineReport, optimize_pipeline};

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
}

#[derive(Args)]
pub struct BootProfileCreateArgs {
    /// Input boot profile document path ("-" for stdin).
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Output compiled boot profile path ("-" for stdout).
    #[arg(short, long, value_name = "OUTPUT", default_value = "-")]
    pub output: String,
    /// Materialize pipeline optimization hints (currently android sparse indexes).
    #[arg(long)]
    pub optimize_pipeline_hints: bool,
    /// Recompute existing pipeline hints while optimizing.
    #[arg(long, requires = "optimize_pipeline_hints")]
    pub optimize_pipeline_hints_force: bool,
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

pub async fn run_bootprofile(args: BootProfileArgs) -> Result<()> {
    match args.command {
        BootProfileCommand::Create(args) => run_create(args).await,
        BootProfileCommand::Show(args) => run_show(args),
    }
}

async fn run_create(args: BootProfileCreateArgs) -> Result<()> {
    let input = read_input_bytes(&args.input)?;
    let manifest: BootProfileManifest = serde_yaml::from_slice(&input)
        .with_context(|| format!("parsing boot profile document {}", io_label(&args.input)))?;

    let mut compiled = manifest
        .compile_dt_overlays(compile_dt_overlay)
        .context("compiling dt_overlays with dtc")?;

    if args.optimize_pipeline_hints {
        optimize_profile_pipeline_hints(&mut compiled, args.optimize_pipeline_hints_force).await?;
    }

    validate_boot_profile(&compiled).map_err(|err| anyhow!("{err}"))?;

    let bytes = encode_boot_profile(&compiled).context("encoding boot profile binary")?;

    validate_binary_output(
        &args.output,
        "bootprofile create",
        std::io::stdout().is_terminal(),
    )?;
    write_output_bytes(&args.output, &bytes)
}

fn run_show(args: BootProfileShowArgs) -> Result<()> {
    let input = read_input_bytes(&args.input)?;
    let compiled = decode_boot_profile(&input).map_err(|err| anyhow!("{err}"))?;

    validate_boot_profile(&compiled).map_err(|err| anyhow!("{err}"))?;

    let manifest = compiled
        .decompile_dt_overlays(decompile_dt_overlay)
        .context("decompiling dt_overlays with dtc")?;

    let yaml = serde_yaml::to_string(&manifest).context("serializing boot profile YAML")?;
    write_output_bytes(&args.output, yaml.as_bytes())
}

async fn optimize_profile_pipeline_hints(
    profile: &mut BootProfile,
    force: bool,
) -> Result<OptimizePipelineReport> {
    let opts = OptimizePipelineOptions {
        force,
        ..OptimizePipelineOptions::default()
    };
    let mut report = OptimizePipelineReport::default();

    add_optimize_report(
        &mut report,
        optimize_pipeline(profile_rootfs_source_mut(&mut profile.rootfs), &opts)
            .await
            .context("optimizing boot profile rootfs pipeline hints")?,
    );

    if let Some(kernel) = profile.kernel.as_mut() {
        add_optimize_report(
            &mut report,
            optimize_pipeline(profile_artifact_path_source_mut(kernel), &opts)
                .await
                .context("optimizing boot profile kernel pipeline hints")?,
        );
    }

    if let Some(dtbs) = profile.dtbs.as_mut() {
        add_optimize_report(
            &mut report,
            optimize_pipeline(profile_artifact_path_source_mut(dtbs), &opts)
                .await
                .context("optimizing boot profile dtbs pipeline hints")?,
        );
    }

    Ok(report)
}

fn add_optimize_report(total: &mut OptimizePipelineReport, report: OptimizePipelineReport) {
    total.android_sparse_stages_visited = total
        .android_sparse_stages_visited
        .saturating_add(report.android_sparse_stages_visited);
    total.android_sparse_indexes_added = total
        .android_sparse_indexes_added
        .saturating_add(report.android_sparse_indexes_added);
    total.android_sparse_indexes_updated = total
        .android_sparse_indexes_updated
        .saturating_add(report.android_sparse_indexes_updated);
    total.android_sparse_indexes_skipped = total
        .android_sparse_indexes_skipped
        .saturating_add(report.android_sparse_indexes_skipped);
}

fn profile_artifact_path_source_mut(
    source: &mut BootProfileArtifactPathSource,
) -> &mut BootProfileArtifactSource {
    profile_rootfs_source_mut(&mut source.source)
}

fn profile_rootfs_source_mut(rootfs: &mut BootProfileRootfs) -> &mut BootProfileArtifactSource {
    match rootfs {
        BootProfileRootfs::Ostree(source) => match &mut source.ostree {
            BootProfileRootfsFilesystemSource::Erofs(source) => &mut source.erofs,
            BootProfileRootfsFilesystemSource::Ext4(source) => &mut source.ext4,
            BootProfileRootfsFilesystemSource::Fat(source) => &mut source.fat,
        },
        BootProfileRootfs::Erofs(source) => &mut source.erofs,
        BootProfileRootfs::Ext4(source) => &mut source.ext4,
        BootProfileRootfs::Fat(source) => &mut source.fat,
    }
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

fn io_label(path: &str) -> String {
    if path == "-" {
        "stdin/stdout".to_string()
    } else {
        path.to_string()
    }
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
    fn optimize_pipeline_hints_materializes_sparse_index() {
        let sparse_path = write_temp_sparse_image();
        let manifest: BootProfileManifest = serde_yaml::from_str(
            format!(
                "id: local-ext4\nrootfs:\n  ext4:\n    android_sparseimg:\n      file: '{}'\n",
                sparse_path.display()
            )
            .as_str(),
        )
        .expect("parse manifest");

        let mut profile = manifest
            .compile_dt_overlays::<core::convert::Infallible, _>(|_| unreachable!())
            .expect("compile profile");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        let report = runtime
            .block_on(optimize_profile_pipeline_hints(&mut profile, false))
            .expect("optimize profile pipeline hints");

        assert_eq!(report.android_sparse_stages_visited, 1);
        assert_eq!(report.android_sparse_indexes_added, 1);
        assert_eq!(report.android_sparse_indexes_updated, 0);
        assert_eq!(report.android_sparse_indexes_skipped, 0);

        let source = profile.rootfs.source();
        let BootProfileArtifactSource::AndroidSparseImg(source) = source else {
            panic!("expected android sparse source, got {source:?}")
        };
        let index = source
            .android_sparseimg
            .index
            .as_ref()
            .expect("android sparse index should be embedded");
        assert_eq!(index.total_blks, 2);
        assert_eq!(index.total_chunks, 2);

        let _ = fs::remove_file(sparse_path);
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

    const SPARSE_MAGIC: u32 = 0xED26_FF3A;
    const SPARSE_MAJOR_VERSION: u16 = 1;
    const CHUNK_TYPE_RAW: u16 = 0xCAC1;
    const CHUNK_TYPE_DONT_CARE: u16 = 0xCAC3;

    fn write_temp_sparse_image() -> PathBuf {
        let mut path = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        path.push(format!("fastboop-bootprofile-optimize-{nonce}.simg"));
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
