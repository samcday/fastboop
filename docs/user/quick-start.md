# Quick start

This is a starter quick-start. It will be expanded with distro- and device-specific examples.

## 1) Build fastboop

```sh
cargo build --workspace --locked
```

## 2) Confirm your device can be matched

```sh
cargo run -p fastboop-cli -- detect
```

## 3) Generate stage0 from your selected rootfs artifact

```sh
cargo run -p fastboop-cli -- stage0 --help
```

## 3b) Inspect and compile device profiles

```sh
cargo run -p fastboop-cli -- devprofile --help
```

## 4) Boot ephemerally

```sh
cargo run -p fastboop-cli -- boot --help
```

No flashing or partition mutation is performed in the supported flow.
