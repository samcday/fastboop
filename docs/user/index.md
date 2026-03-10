# fastboop

fastboop makes it simple to live boot your favourite (supported) mainline Linux distro on your favourite (supported) pocket computer, **without modifying the device**.

## Quickstart

fastboop is available as a web app, a desktop app, and a CLI tool.

### Web app

The quickest way to get started is to visit [www.fastboop.win][].

### Desktop app

A desktop app <del>is</del> [will be](https://github.com/samcday/fastboop/issues/41) available.

### CLI

fastboop is not yet widely packaged. You can install it from source if you have a recent Rust toolchain installed:

```sh
cargo install fastboop-cli@'>0.0.1-rc'
```

You can alternatively use [cargo-binstall][] to skip the build:

```sh
cargo binstall fastboop-cli@'>0.0.1-rc'
```

There's also [prebuilt binaries][latest-release] made available as part of each release.

## Next steps

- Read about [Device permissions](device-permissions.md) if you encounter "access denied" problems.
- Check the [FAQ](faq.md) for common gotchas.

[cargo-binstall]: https://github.com/cargo-bins/cargo-binstall
[latest-release]: https://github.com/samcday/fastboop/releases/latest
[www.fastboop.win]: https://www.fastboop.win
