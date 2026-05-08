# fastboop-mobile

This crate is the Android entrypoint for fastboop. It owns mobile-specific
assets, platform bindings, and route wiring while reusing shared Dioxus UI from
`packages/ui`.

Phase 0 established the development loop. Phase 1 adds a narrow Android USB host
spike that can enumerate devices, trigger Android USB permission prompts, and
open a device far enough to receive the raw Android file descriptor. Fastboot and
smoo transport binding land after this spike.

## Host Setup

Install the Rust Android targets:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

Install Android Studio or the Android command-line tools, then install these SDK
components:

- Android SDK Platform 33 (`platforms;android-33`)
- Android SDK Build-Tools 33 (`build-tools;33.0.0` or newer 33.x)
- Android SDK Platform-Tools
- Android SDK Command-line Tools
- NDK (Side by side)
- CMake

The Dioxus 0.7.3 Android template currently builds with `compileSdk = 33`,
`targetSdk = 33`, and `minSdk = 24`. `Dioxus.toml` pins
`android_min_sdk_version = 24` so Rust/NDK builds use the same API floor as the
generated Gradle app. Android USB host APIs are older than this, so Dioxus is the
practical minimum-version constraint.

Set the Android environment variables for your shell. Adjust the paths and NDK
version to match your install:

```sh
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export NDK_HOME="$ANDROID_HOME/ndk/<installed-version>"
export ANDROID_NDK_HOME="$NDK_HOME"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
```

Verify the tools are visible:

```sh
dx --version
adb version
sdkmanager --version
rustup target list --installed
```

For a physical Android host device, enable Developer Options and USB debugging,
connect it to this development machine, accept the adb authorization prompt, and
check that it appears:

```sh
adb devices
```

Later USB-host phases also need an Android device with USB OTG/host support and
an OTG cable or hub for the target device.

The app manifest declares `android.hardware.usb.host` as required. Direct `adb`
installs are still fine for development, but release distribution should target
devices that advertise USB host capability.

## USB Host Spike

`android/MainActivity.kt` owns the Android `UsbManager` calls because permission
prompts and `UsbDeviceConnection` lifetimes are platform concerns. Rust calls the
activity helpers through JNI from `src/android_usb.rs` and the home screen renders
a manual probe panel:

- `Refresh` reads `UsbManager.deviceList`.
- `Request` calls `UsbManager.requestPermission(...)` for the selected device.
- `Open fd` calls `UsbManager.openDevice(...)`, keeps the Java connection alive,
  and reports the raw file descriptor returned by Android.

The fd is not passed to `nusb` yet. The next phase should duplicate or otherwise
own the fd safely before wrapping it with `nusb::Device::from_fd(...)`.

## Build Loop

The mobile app does not depend on smoo yet, so raw Cargo/Dioxus commands are
enough for the current build loop:

```sh
cargo check -p fastboop-mobile
dx build -p fastboop-mobile --platform android --target aarch64-linux-android
```

Once mobile USB/smoo work starts, use the workspace wrappers from the repo root.
They detect `./smoo` and patch local smoo crates into Cargo/Dioxus builds without
mutating workspace manifests:

```sh
./tools/cargo-local.sh check -p fastboop-mobile
./tools/dx-local.sh build -p fastboop-mobile --platform android --target aarch64-linux-android
```

To deploy to a connected device during development:

```sh
dx serve -p fastboop-mobile --platform android --target aarch64-linux-android --device <adb-device-name>
```

If there is only one connected Android device or emulator, omit `--device` and
let `dx` choose it.

## Troubleshooting

- `sdkmanager: command not found`: install Android SDK Command-line Tools and add `cmdline-tools/latest/bin` to `PATH`.
- `aarch64-linux-android` target missing: rerun the `rustup target add ...` command above.
- `adb devices` is empty: enable USB debugging, accept the authorization prompt, and reconnect the device.
- Android build cannot find the NDK: check `NDK_HOME` and `ANDROID_NDK_HOME` point at an installed side-by-side NDK directory.
- Local smoo changes are ignored: use `./tools/dx-local.sh` or `./tools/cargo-local.sh`, not raw `dx`/`cargo`.
