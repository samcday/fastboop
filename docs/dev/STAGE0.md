# Stage0

Stage0 is the minimal initramfs fastboop synthesizes and boots ephemerally.

Its job is short and strict: bring up gadget runtime, mount exported root, and exec distro init.

## Source of Truth

- Runtime PID1 flow: [`stage0/src/main.rs`](https://github.com/samcday/fastboop/blob/main/stage0/src/main.rs)
- Stage0 assembly: [`crates/fastboop-stage0-generator`](https://github.com/samcday/fastboop/tree/main/crates/fastboop-stage0-generator)
- CLI entrypoint: [`cli/src/commands/stage0.rs`](https://github.com/samcday/fastboop/blob/main/cli/src/commands/stage0.rs)

## Contract

Stage0 PID1 (`fastboop-stage0`) does this in order:

1. mount `/proc`, `/sys`, `/dev`, `/run`
2. load required kernel modules
3. configure configfs/FunctionFS and spawn embedded `smoo-gadget-app`
4. wait for exported block device (`/dev/ublkb0`)
5. mount lower root (`erofs` or `ext4`) + tmpfs upper overlay
6. switch root and `exec` init (`/lib/systemd/systemd`, `/usr/lib/systemd/systemd`, or `/sbin/init`)

If gadget startup or handoff fails, stage0 fails loudly.

## Inputs

- Device Profile (`stage0.kernel_modules`, `stage0.inject_mac`)
- Boot Profile stage0 additions (extra modules, overlays, per-device cmdline)
- CLI overrides (`--dtb`, `--dtbo`, `--require-module`, `--cmdline-append`, `--serial`)
- Rootfs artifact source (direct image or compiled Boot Profile)

## Settings Channel

Stage0 reads runtime settings from files under `/etc/stage0` in the generated initramfs.

Notable keys include:

- `stage0.rootfs` (required)
- `stage0.selinux` (`1` by default; set `0` to disable stage0 SELinux handoff policy install)
- `ostree`
- `smoo.acm`, `smoo.queue_count`, `smoo.queue_depth`, `smoo.max_io_bytes`
- `firstboot.locale`, `firstboot.locale-messages`, `firstboot.keymap`, `firstboot.timezone`

## Non-Goals

- no flashing/partitioning/persistent writes
- no installer behavior
- no interactive rescue environment
- no distro policy engine

## How To Bang On It

```sh
# build stage0 initrd only
cargo run -p fastboop-cli -- stage0 <rootfs-or-bootprofile> --device-profile <id> > /tmp/stage0.cpio

# build full boot payload without touching a device
cargo run -p fastboop-cli -- boot <rootfs-or-bootprofile> --device-profile <id> --output /tmp/boot.img

# targeted compile checks
cargo check -p fastboop-stage0
cargo check -p fastboop-stage0-generator
```
