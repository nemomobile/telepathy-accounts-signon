Name: telepathy-accounts-signon
Version: 0.0.5
Release: 1
Summary: Telepathy providers for libaccounts/libsignon
Group: System/Libraries
License: GPLv2
URL: https://github.com/nemomobile/telepathy-accounts-signon
Source0: %{name}-%{version}.tar.bz2

BuildRequires: qt5-qmake
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(gobject-2.0)
BuildRequires: pkgconfig(libsignon-glib)
BuildRequires: pkgconfig(telepathy-glib)
BuildRequires: pkgconfig(libaccounts-glib)
BuildRequires: pkgconfig(mission-control-plugins)
BuildRequires: pkgconfig(libsailfishkeyprovider)

Requires: mapplauncherd

%description
%{summary}.

%files
%defattr(-,root,root,-)
%{_libexecdir}/telepathy-sasl-signon
%{_datadir}/dbus-1/services/org.freedesktop.Telepathy.Client.SaslSignonAuth.service
%{_datadir}/telepathy/clients/SaslSignonAuth.client
%{_libdir}/mission-control-plugins.0/mcp-account-manager-uoa.so

%prep
%setup -q -n %{name}-%{version}

%build
%qmake5
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

