# Maintainer: Sam Day <me@samcday.com>
pkgname=fastboop
pkgver=0.0.1_git
pkgrel=0
pkgdesc="Ephemeral Linux boot tool for USB-enabled pocket computers"
url=https://github.com/samcday/fastboop
arch="x86_64 aarch64"
license="GPL-3.0-only"
makedepends="
	cargo
	clang-dev
	libusb-dev
	linux-headers
	pkgconf
	rust"

_gitrev=main
source="https://github.com/samcday/fastboop/archive/$_gitrev/fastboop-$_gitrev.tar.gz"
builddir="$srcdir/fastboop-$_gitrev"
options="net"

export RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$builddir=/build/"

_cargo_target_arg=
_cargo_target_dir="target"
if [ -n "$CTARGET" ]; then
	_cargo_target_arg="--target=$CTARGET"
	_cargo_target_dir="target/$CTARGET"
fi

prepare() {
	default_prepare
	cargo fetch --locked $_cargo_target_arg
}

build() {
	cargo build --release --locked --frozen -p fastboop-cli $_cargo_target_arg
}

check() {
	cargo test --workspace --locked --frozen $_cargo_target_arg
}

package() {
	local target_dir="$_cargo_target_dir/release"

	install -Dm755 "$target_dir"/fastboop-cli "$pkgdir"/usr/bin/fastboop
}

sha512sums=""
