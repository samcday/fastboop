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
%{__cargo_to_rpm} --path cli/Cargo.toml buildrequires %{?with_check:--with-check}
%endif

%build
%cargo_build -- -p fastboop-cli
%cargo_vendor_manifest
%{cargo_license_summary}
%{cargo_license} > LICENSE.dependencies

%install
install -Dpm0755 target/rpm/fastboop-cli \
    %{buildroot}%{_bindir}/fastboop

%if %{with check}
%check
%cargo_test -- -p fastboop-cli
%endif

%files
%license LICENSE
%license LICENSE.dependencies
%license cargo-vendor.txt
%doc README.md
%{_bindir}/fastboop

%changelog
%autochangelog
