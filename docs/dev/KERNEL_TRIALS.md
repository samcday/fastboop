# PocketFed kernel and userspace trials

For camera, fingerprint, networking, and other device bring-up, prefer a local
ephemeral boot through the PocketFed/kboop trial workflow. Cache a known userspace
root, build the changed kernel or userspace locally, and record the hardware
result before promoting a candidate through COPR and the published image
pipeline. Public CI, registry publication, and installation images are not
prerequisites for these disposable trials.

With sibling checkouts under `~/src`, start with
`../pocketfed/tools/liveboot/README.md` in
[PocketFed](https://github.com/samcday/pocketfed) and
`../kboop/KERNEL-BUNDLES.md` in [kboop](https://github.com/samcday/kboop).
PocketFed owns the device policy, fixture export, run records, UART ownership,
and recovery commands. Its integrated runner currently calls the development
kboop CLI and kboop-init; use the versions and arguments documented there.
Fastboop's `detect`, `stage0`, and `boot` CLI has its own interface and stage0
implementation.

## Scope of the retained integration

The PocketFed harness and extra kboop RAM-root/diagnostic code grew beyond the
original iteration task. Keep this runaway experiment and its evidence for now;
it is not an agreed fastboop architecture or a default task to continue. Its
whole-root RAM mode still fails Sargo startup. No device-side LRU cache or
learned prefetching was implemented by that work. The current split fixture is
validated through kboop, not as direct input to `fastboop boot rootfs.erofs`.

## Reuse the work that did not change

- For a kernel change, reuse the cached rootfs and produce a coherent Image,
  board DTB, configuration, and complete matching module tree from the candidate
  build. Feed that bundle to the PocketFed runner. Rebuilding the rootfs or
  packaging an RPM is unnecessary for this path.
- For a userspace change, export a new disposable fixture from a local image or
  the documented overlay path. Keep the kernel bundle when its inputs are
  unchanged. Preserve the candidate's SELinux policy when adding the required
  liveboot storage rule.
- Keep source commit and dirty changes, configuration, toolchain, artifact
  hashes, selected serial, UART log, and subsystem results with each run.
  Preparation or a successful systemd handoff does not establish camera,
  fingerprint, suspend, or other subsystem acceptance.

Keep reusable tools and recipes in their source repositories. Generated
fixtures, build caches, and run evidence belong in the chosen ignored lab
output directory. Successful trials can then enter the normal packaged and
installed-deployment validation process for daily-driver use or publication.

## Sargo recovery and storage modes

The Sargo reference pathway uses an explicit fastboot serial and a separate
hardware UART. Use one runner as the UART and USB-root owner, keep
`sysrq_always_enabled=1` in the kernel command line, and send SysRq through the
runner's `sysrq` command. UART SysRq HELP and reboot have been verified on the
reference init. The liveboot guide records the commands and recovery boundary;
RAM boot does not require flashing or slot changes.

The validated mode serves the rootfs and modules over USB. On 11 September 2026,
the packaged baseline and an exported local userspace candidate both passed
enforcing userspace handoff in about 65 seconds, with UART SysRq recovery verified. This
establishes the trial transport and handoff, not subsystem acceptance.

Tests that reset the USB controller, switch its role, or remove the cable need
a storage strategy validated through those interruptions. Sargo resident mode
remains experimental after repeated startup resets, including a diagnostic that
retained the gadget. See the PocketFed guide
for current evidence before selecting it. An independent UART alone does not
make root storage independent, and the USB-root recipe's gadget/service masks
must be considered when designing a Type-C test.
