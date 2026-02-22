# fastboop

fastboop boots Linux on supported phones/pocket devices over USB **without flashing**.

If your device supports non-mutating vendor boot (for now, fastboot RAM boot), fastboop builds an ephemeral boot payload and gets you into a live system.

## Core intent

- Keep boot flow non-mutating: no flash, no partition writes, no slot changes.
- Reuse upstream artifacts instead of distro forks.
- Be usable from CLI, desktop, and web frontends.

## First steps

1. Build the workspace:

```sh
cargo build --workspace --locked
```

2. Explore the CLI:

```sh
cargo run -p fastboop-cli -- --help
cargo run -p fastboop-cli -- detect --help
cargo run -p fastboop-cli -- stage0 --help
cargo run -p fastboop-cli -- boot --help
```

3. Check available device profiles in `devprofiles.d/`.

## Where to read next

- Contributor and architecture notes: `HACKING.md`
- Device profile model: `docs/dev/DEVICE_PROFILES.md`
- Stage0 contract and behavior: `docs/dev/STAGE0.md`
- UI stack notes: `docs/dev/DIOXUS.md`
