%bcond_without check
%bcond_without vendor
%global cargo_install_lib 0
%if %{with vendor}
%global _cargo_generate_buildrequires 0
%endif

Name:           fastboop
Version:        0.0.1
Release:        %autorelease
Summary:        Ephemeral Linux boot tool for USB-enabled pocket computers
License:        GPL-3.0-only
URL:            https://github.com/samcday/fastboop
Source:         %{url}/archive/v%{version}/%{name}-v%{version}.tar.gz

BuildRequires:  cargo-rpm-macros >= 24
BuildRequires:  clang-devel
BuildRequires:  pkgconfig(libusb-1.0)

# Optional prebuilt stage0 artifact path (release asset flow):
#   rpmbuild --define 'fastboop_stage0_embed_path /path/to/fastboop-stage0-aarch64-unknown-linux-musl' ...
# If the define is omitted, %{_sourcedir}/fastboop-stage0-aarch64-unknown-linux-musl
# is used when present.
%global stage0_embed_asset fastboop-stage0-aarch64-unknown-linux-musl
%global stage0_embed_default %{_sourcedir}/%{stage0_embed_asset}

%description
fastboop ephemerally boots Linux installations on pocket computers that expose
a non-mutating USB-enabled bootloader interface (i.e. fastboot), without
flashing or permanently modifying the device.

%prep
%autosetup -n %{name}-v%{version} -p1
%if %{with vendor}
%{__cargo} vendor --locked --versioned-dirs vendor
%cargo_prep -v vendor
%else
%cargo_prep
%generate_buildrequires
%cargo_generate_buildrequires
%endif

%build
stage0_embed_path="%{?fastboop_stage0_embed_path}"
if [ -z "$stage0_embed_path" ] && [ -f "%{stage0_embed_default}" ]; then
  stage0_embed_path="%{stage0_embed_default}"
fi
if [ -n "$stage0_embed_path" ]; then
  if [ ! -f "$stage0_embed_path" ]; then
    echo "FASTBOOP stage0 embed artifact not found: $stage0_embed_path" >&2
    exit 1
  fi
  export FASTBOOP_STAGE0_EMBED_PATH="$stage0_embed_path"
fi
%cargo_build
%cargo_vendor_manifest
%{cargo_license_summary}
%{cargo_license} > LICENSE.dependencies

%install
install -Dpm0755 target/rpm/fastboop-cli \
    %{buildroot}%{_bindir}/fastboop

%if %{with check}
%check
%cargo_test
%endif

%files
%license LICENSE
%license LICENSE.dependencies
%license cargo-vendor.txt
%doc README.md
%{_bindir}/fastboop

%changelog
%autochangelog
