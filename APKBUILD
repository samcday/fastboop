# Maintainer: Sam Day <me@samcday.com>
pkgname=fastboop
pkgver=0.0.1_rc21_git
pkgrel=0
pkgdesc="Ephemeral Linux boot tool for USB-enabled pocket computers"
url=https://github.com/samcday/fastboop
arch="x86_64 aarch64"
license="GPL-3.0-only"
depends="$pkgname-cli"
makedepends="
	binutils
	cargo
	clang-dev
	libusb-dev
	linux-headers
	pkgconf
	rust"

_gitrev=main
source="https://github.com/samcday/fastboop/archive/$_gitrev/fastboop-$_gitrev.tar.gz"
builddir="$srcdir/fastboop-${_gitrev#v}"
subpackages="$pkgname-stage0 $pkgname-cli"
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

_stage0_target="${FASTBOOP_STAGE0_TARGET:-aarch64-unknown-linux-musl}"
_stage0_cargo="${FASTBOOP_STAGE0_CARGO:-cargo}"
_stage0_target_dir="target/$_stage0_target"

prepare() {
	default_prepare
	cargo fetch --locked $_cargo_target_arg
	"$_stage0_cargo" fetch --locked --target "$_stage0_target"
}

build() {
	cargo build --release --locked --frozen -p fastboop-cli $_cargo_target_arg
	"$_stage0_cargo" build --release --locked --frozen \
		--target "$_stage0_target" \
		-p fastboop-stage0
}

check() {
	cargo test --workspace --locked --frozen $_cargo_target_arg
}

package() {
	local target_dir="$_cargo_target_dir/release"
	local stage0_bin="$_stage0_target_dir/release/fastboop-stage0"

	install -Dm755 "$target_dir"/fastboop "$pkgdir"/usr/bin/fastboop
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

sha512sums=""
