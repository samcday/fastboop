# Maintainer: Sam Day <me@samcday.com>
pkgname=fastboop
pkgver=0.0.1_rc21_git
pkgrel=0
pkgdesc="Ephemeral Linux boot tool for USB-enabled pocket computers"
url=https://github.com/samcday/fastboop
arch="x86_64 aarch64"
license="GPL-3.0-only"
depends="$pkgname-cli $pkgname-desktop"
makedepends="
	binutils
	cargo
	clang-dev
	dtc
	gtk+3.0-dev
	libayatana-appindicator-dev
	libusb-dev
	librsvg-dev
	linux-headers
	openssl-dev
	pkgconf
	rust
	webkit2gtk-4.1-dev
	xdotool-dev"

_gitrev=main
source="https://github.com/samcday/fastboop/archive/$_gitrev/fastboop-$_gitrev.tar.gz"
builddir="$srcdir/fastboop-${_gitrev#v}"
subpackages="$pkgname-stage0 $pkgname-cli $pkgname-desktop"
options="net"

export RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$builddir=/build/"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER:-rust-lld}"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS:--C target-feature=+crt-static}"
export CARGO_TARGET_AARCH64_ALPINE_LINUX_MUSL_RUSTFLAGS="${CARGO_TARGET_AARCH64_ALPINE_LINUX_MUSL_RUSTFLAGS:--C target-feature=+crt-static}"

_cargo_target_arg=
_cargo_target_dir="target"
if [ -n "$CTARGET" ]; then
	_cargo_target_arg="--target=$CTARGET"
	_cargo_target_dir="target/$CTARGET"
fi

_host_cargo="${FASTBOOP_HOST_CARGO:-/usr/bin/cargo}"
_host_rustc="${FASTBOOP_HOST_RUSTC:-/usr/bin/rustc}"
_stage0_path="${FASTBOOP_STAGE0_PATH:-}"
_stage0_target="${FASTBOOP_STAGE0_TARGET:-aarch64-unknown-linux-musl}"
_stage0_cargo="${FASTBOOP_STAGE0_CARGO:-cargo}"
_stage0_target_dir="target/$_stage0_target"

prepare() {
	default_prepare
	RUSTC="$_host_rustc" "$_host_cargo" fetch --locked $_cargo_target_arg
	if [ -z "$_stage0_path" ]; then
		"$_stage0_cargo" fetch --locked --target "$_stage0_target"
	fi
}

build() {
	RUSTC="$_host_rustc" "$_host_cargo" build --release --locked --frozen \
		-p fastboop-cli \
		-p fastboop-desktop \
		$_cargo_target_arg
	if [ -z "$_stage0_path" ]; then
		"$_stage0_cargo" build --release --locked --frozen \
			--target "$_stage0_target" \
			-p fastboop-stage0
	fi
}

check() {
	RUSTC="$_host_rustc" "$_host_cargo" test --workspace --locked --frozen $_cargo_target_arg
}

package() {
	local target_dir="$_cargo_target_dir/release"
	local stage0_bin="${_stage0_path:-$_stage0_target_dir/release/fastboop-stage0}"

	install -Dm755 "$target_dir"/fastboop "$pkgdir"/usr/bin/fastboop
	install -Dm755 "$target_dir"/fastboop-desktop "$pkgdir"/usr/bin/fastboop-desktop
	install -Dm644 packages/desktop/assets/main.css "$pkgdir"/usr/bin/assets/main.css
	install -Dm644 packages/ui/assets/styling/hero.css \
		"$pkgdir"/usr/bin/assets/styling/hero.css
	install -Dm644 packages/ui/assets/styling/smoo_stats.css \
		"$pkgdir"/usr/bin/assets/styling/smoo_stats.css
	install -Dm644 assets/win.fastboop.fastboop.desktop \
		"$pkgdir"/usr/share/applications/win.fastboop.fastboop.desktop
	install -Dm644 assets/win.fastboop.fastboop.metainfo.xml \
		"$pkgdir"/usr/share/metainfo/win.fastboop.fastboop.metainfo.xml
	install -Dm644 assets/win.fastboop.fastboop.svg \
		"$pkgdir"/usr/share/icons/hicolor/scalable/apps/win.fastboop.fastboop.svg
	install -Dm755 "$stage0_bin" "$pkgdir"/usr/lib/fastboop/stage0/stage0-aarch64

	if readelf -l "$pkgdir"/usr/lib/fastboop/stage0/stage0-aarch64 | grep -q INTERP; then
		msg "fastboop-stage0 sidecar must be statically linked"
		return 1
	fi
}

stage0() {
	pkgdesc="fastboop stage0 sidecar payload"
	depends=""
	amove usr/lib/fastboop/stage0/stage0-aarch64
}

cli() {
	pkgdesc="fastboop CLI"
	depends="$pkgname-stage0 libusb"
	amove usr/bin/fastboop
}

desktop() {
	pkgdesc="fastboop desktop app"
	depends="$pkgname-stage0 desktop-file-utils hicolor-icon-theme libusb shared-mime-info"
	amove usr/bin/fastboop-desktop
	amove usr/bin/assets
	amove usr/share/applications/win.fastboop.fastboop.desktop
	amove usr/share/metainfo/win.fastboop.fastboop.metainfo.xml
	amove usr/share/icons/hicolor/scalable/apps/win.fastboop.fastboop.svg
}

sha512sums=""
