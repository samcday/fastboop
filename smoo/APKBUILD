# Maintainer: Sam Day <me@samcday.com>
pkgname=smoo
pkgver=0.0.1_git
pkgrel=0
pkgdesc="Inverted USB mass-storage utilities (host + gadget)"
url=https://github.com/samcday/smoo
arch="x86_64 aarch64 armv7"
license="GPL-3.0-only"
depends="$pkgname-gadget $pkgname-host"
makedepends="
	cargo
	clang-dev
	libusb-dev
	openssl-dev
	linux-headers
	llvm-dev
	pkgconf
	rust"

_gitrev=main
source="https://github.com/samcday/smoo/archive/$_gitrev/smoo-$_gitrev.tar.gz"
builddir="$srcdir/smoo-$_gitrev"
subpackages="$pkgname-gadget $pkgname-host"
options="net"

export RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$builddir=/build/"

_cargo_target_arg=
_cargo_target_dir="target"
if [ -n "$CTARGET" ]; then
	_cargo_target_arg="--target=$CTARGET"
	_cargo_target_dir="target/$CTARGET"
fi

_cargo_features="smoo-gadget-cli/apkbuild"

prepare() {
	default_prepare
	cargo fetch --locked $_cargo_target_arg
}

build() {
	cargo build --release --locked --frozen --bins $_cargo_target_arg --features "$_cargo_features"
}

check() {
	cargo test --workspace --locked --frozen $_cargo_target_arg --features "$_cargo_features"
}

package() {
	local target_dir="$_cargo_target_dir/release"

	install -Dm755 "$target_dir"/smoo-gadget-cli "$pkgdir"/usr/bin/smoo-gadget
	install -Dm755 "$target_dir"/smoo-host-cli "$pkgdir"/usr/bin/smoo-host
}

gadget() {
	pkgdesc="smoo gadget CLI"
	depends=""
	amove usr/bin/smoo-gadget
}

host() {
	pkgdesc="smoo host CLI"
	depends="libusb"
	amove usr/bin/smoo-host
}

sha512sums="
46664313fed5b6a3210741f8696981a8ae340cdf88f4f4e6206b327c88f4448d97d0ea83a6f853d6cf2c1e9b09a4b95034632b9bcf06e281e162ed5f82958ee2  smoo-main.tar.gz
"
