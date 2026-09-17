# Maintainer: Sam Day <me@samcday.com>
pkgname=fastboop
pkgver=0.0.1_rc21_git
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
# Pinned to the gibblox/smoo submodule revisions recorded in git.
_gibbloxrev=777a8781547a6d1941e880022a61feb1f4ea5dfe
_smoorev=3fdcc7b9fa1585d3a725e20bb777113b302ed5eb
source="https://github.com/samcday/fastboop/archive/$_gitrev/fastboop-$_gitrev.tar.gz
	https://github.com/samcday/gibblox/archive/$_gibbloxrev/gibblox-$_gibbloxrev.tar.gz
	https://github.com/samcday/smoo/archive/$_smoorev/smoo-$_smoorev.tar.gz"
builddir="$srcdir/fastboop-${_gitrev#v}"
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

	# Archive tarballs carry empty placeholders for the gibblox/smoo submodules,
	# which [patch.crates-io] resolves as path dependencies. Fill them in.
	rm -rf "$builddir"/gibblox "$builddir"/smoo
	mv "$srcdir"/gibblox-"$_gibbloxrev" "$builddir"/gibblox
	mv "$srcdir"/smoo-"$_smoorev" "$builddir"/smoo

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

	install -Dm755 "$target_dir"/fastboop "$pkgdir"/usr/bin/fastboop
}

sha512sums=""
