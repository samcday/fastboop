%bcond_without check
%bcond_without vendor
%global cargo_install_lib 0
%if %{with vendor}
%global _cargo_generate_buildrequires 0
%endif

Name:           smoo
Version:        0.0.1
Release:        %autorelease
Summary:        Inverted USB mass-storage host/gadget utilities
License:        GPL-3.0-only
URL:            https://github.com/samcday/smoo
Source:         %{url}/archive/%{version}/%{name}-%{version}.tar.gz

BuildRequires:  cargo-rpm-macros >= 24
BuildRequires:  clang-devel
BuildRequires:  pkgconfig(openssl)

%description
smoo provides both sides of an inverted USB mass-storage protocol: a gadget
implementation that serves block data over FunctionFS + ublk, and a host
implementation that drives it over USB.

%package gadget
Summary:        smoo gadget CLI
Requires:       %{name}%{?_isa}

%description gadget
Device-side CLI that exposes a smoo gadget backed by FunctionFS + ublk.

%package host
Summary:        smoo host CLI
Requires:       %{name}%{?_isa}

%description host
Host-side CLI that speaks the smoo USB protocol over rusb.

%prep
%autosetup -n %{name}-%{version} -p1
%if %{with vendor}
%{__cargo} vendor --locked --versioned-dirs vendor
%cargo_prep -v vendor
%else
%cargo_prep
%generate_buildrequires
%cargo_generate_buildrequires
%endif

%build
%cargo_build
%cargo_vendor_manifest
%{cargo_license_summary}
%{cargo_license} > LICENSE.dependencies

%install
install -Dpm0755 target/rpm/smoo-gadget-cli \
    %{buildroot}%{_bindir}/smoo-gadget
install -Dpm0755 target/rpm/smoo-host-cli \
    %{buildroot}%{_bindir}/smoo-host

%if %{with check}
%check
%cargo_test
%endif

%files
%license LICENSE
%license LICENSE.dependencies
%license cargo-vendor.txt
%license crates/smoo-proto/LICENSE-MIT
%doc README.md

%files gadget
%{_bindir}/smoo-gadget

%files host
%{_bindir}/smoo-host

%changelog
%autochangelog
