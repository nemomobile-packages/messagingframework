Name: qmf-qt5
Summary:    Qt Messaging Framework (QMF) Qt5
Version:    4.0.4+git15
Release:    1
Group:      System/Libraries
License:    LGPLv2.1 with exception or GPLv3
URL:        http://qt.gitorious.org/qt-labs/messagingframework
Source0:    %{name}-%{version}.tar.bz2
Requires:   systemd-user-session-targets
BuildRequires:  pkgconfig(zlib)
BuildRequires:  pkgconfig(icu-i18n)
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5Gui)
BuildRequires:  pkgconfig(Qt5Widgets)
BuildRequires:  pkgconfig(Qt5Test)
BuildRequires: 	pkgconfig(Qt5Network)
#BuildRequires: pkgconfig(Qt5Webkit)
BuildRequires:  pkgconfig(Qt5Sql)
BuildRequires:  pkgconfig(accounts-qt5)
BuildRequires:  pkgconfig(libsignon-qt5)
#Needed for qhelpgenerator
BuildRequires:  qt5-qttools-qthelp-devel
BuildRequires:  qt5-plugin-platform-minimal
BuildRequires:  qt5-plugin-sqldriver-sqlite
BuildRequires:  fdupes

%description
The Qt Messaging Framework, QMF, consists of a C++ library and daemon server
process that can be used to build email clients, and more generally software
that interacts with email and mail servers.


%package devel
Summary:    Qt Messaging Framework (QMF) Qt5 - development files
Group:      Development/Libraries
Requires:   libqmfmessageserver1-qt5 = %{version}
Requires:   libqmfutil1-qt5 = %{version}
Requires:   libqmfclient1-qt5 = %{version}

%description devel
The Qt Messaging Framework, QMF, consists of a C++ library and daemon server
process that can be used to build email clients, and more generally software
that interacts with email and mail servers.

This package contains the development files needed to build Qt applications
using Qt Messaging Framework libraries.


%package -n libqmfmessageserver1-qt5
Summary:    Qt Messaging Framework (QMF) message server support library
Group:      System/Libraries
Requires:   qt5-qtsql
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libqmfmessageserver1-qt5
The Qt Messaging Framework, QMF, consists of a C++ library and daemon server
process that can be used to build email clients, and more generally software
that interacts with email and mail servers.

The MessageServer application is a daemon, designed to run continuously while
providing services to client applications. It provides messaging transport
functionality, communicating with external servers on behalf of Messaging
Framework client applications. New types of messaging (such as Instant
Messages or video messages) can be handled by the server application without
modification to existing client applications.

This package contains:
 - the message server support library. It provides assistance in developing GUI
   clients that access messaging data.
 - a server application supporting multiple messaging transport mechanisms.


%package -n libqmfutil1-qt5
Summary:    Qt Messaging Framework (QMF) messaging client utility library
Group:      System/Libraries
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libqmfutil1-qt5
The Qt Messaging Framework, QMF, consists of a C++ library and daemon server
process that can be used to build email clients, and more generally software
that interacts with email and mail servers.

This package contains the messaging client utility library. It provides
assistance in developing plugins for the Message Server daemon.


%package -n libqmfclient1-qt5
Summary:    Qt Messaging Framework (QMF) client library
Group:      System/Libraries
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libqmfclient1-qt5
The Qt Messaging Framework, QMF, consists of a C++ library and daemon server
process that can be used to build email clients, and more generally software
that interacts with email and mail servers.

The Client library provides classes giving access to all messages stored on
the device, via a uniform interface. It simplifies the task of creating
messaging client applications, and permits other Messaging Framework
applications to interact with messaging data where appropriate. New types of
messages can be supported by the library without modification to existing
client applications.

This package contains a library for developing applications that work with
messages.


%package examples
Summary:    Qt Messaging Framework (QMF) examples
Group:      System/X11

%description examples
The Qt Messaging Framework, QMF, consists of a C++ library and daemon server
process that can be used to build email clients, and more generally software
that interacts with email and mail servers.

The Messages example client application provides an implementation of standard
functionality for creating and viewing messages.

This package contains an example client application supporting common
messaging functionality.


%package tests
Summary:    Qt Messaging Framework (QMF) tests
Group:      System/X11

%description tests
The Qt Messaging Framework, QMF, consists of a C++ library and daemon server
process that can be used to build email clients, and more generally software
that interacts with email and mail servers.

This package contains the tests for Qt Messaging Framework (QMF).


%package doc
Summary:    Qt Messaging Framework (QMF) - documentation
Group:      Documentation
BuildArch:    noarch

%description doc
The Qt Messaging Framework, QMF, consists of a C++ library and daemon server
process that can be used to build email clients, and more generally software
that interacts with email and mail servers.

This package contains the documentation for Qt Messaging Framework (QMF).

%prep
%setup -q -n %{name}-%{version}/qmf
# >> setup
# << setup

%build
# >> build pre
# << build pre

%qmake5  \
    QMF_INSTALL_ROOT=%{_prefix} \
    DEFINES+=QMF_ENABLE_LOGGING \
    DEFINES+=MESSAGESERVER_PLUGINS \
    CONFIG+=syslog

make %{?jobs:-j%jobs}

# >> build post
# << build post

%install
rm -rf %{buildroot}
# >> install pre
# << install pre
%qmake5_install
UNIT_DIR=%{buildroot}%{_libdir}/systemd/user/user-session.target.wants
mkdir -p "$UNIT_DIR"
ln -sf ../messageserver5.service "$UNIT_DIR/messageserver5.service"

# >> install post
# << install post

%fdupes  %{buildroot}/%{_includedir}

%post -n libqmfmessageserver1-qt5 -p /sbin/ldconfig

%postun -n libqmfmessageserver1-qt5 -p /sbin/ldconfig

%post -n libqmfutil1-qt5 -p /sbin/ldconfig

%postun -n libqmfutil1-qt5 -p /sbin/ldconfig

%post -n libqmfclient1-qt5 -p /sbin/ldconfig

%postun -n libqmfclient1-qt5 -p /sbin/ldconfig

%files devel
%defattr(-,root,root,-)
# >> files devel
%{_includedir}/qmfmessageserver5/qmail*.h
%{_includedir}/qmfclient5/qloggers.h
%{_includedir}/qmfclient5/qlogsystem.h
%{_includedir}/qmfclient5/qmail*.h
%{_includedir}/qmfclient5/qprivateimplementation.h
%{_includedir}/qmfclient5/qprivateimplementationdef.h
%{_includedir}/qmfclient5/sso*.h
%{_libdir}/libqmfmessageserver5.prl
%{_libdir}/libqmfmessageserver5.so
%{_libdir}/libqmfutil5.so
%{_libdir}/libqmfclient5.prl
%{_libdir}/libqmfclient5.so
%{_libdir}/pkgconfig/qmfmessageserver5.pc
%{_libdir}/pkgconfig/qmfclient5.pc
# << files devel

%files -n libqmfmessageserver1-qt5
%defattr(-,root,root,-)
# >> files libqmfmessageserver1-qt5
%{_bindir}/messageserver5
%{_bindir}/qmf-accountscheck
%{_libdir}/libqmfmessageserver5.so.*
%{_libdir}/qmf/plugins5/messageservices/libimap.so
%{_libdir}/qmf/plugins5/messageservices/libpop.so
%{_libdir}/qmf/plugins5/messageservices/libqmfsettings.so
%{_libdir}/qmf/plugins5/messageservices/libsmtp.so
%{_libdir}/systemd/user/messageserver5.service
%{_libdir}/systemd/user/user-session.target.wants/messageserver5.service
# << files libqmfmessageserver1-qt5

%files -n libqmfutil1-qt5
%defattr(-,root,root,-)
# >> files libqmfutil1-qt5
%{_libdir}/libqmfutil5.so.*
# << files libqmfutil1-qt5

%files -n libqmfclient1-qt5
%defattr(-,root,root,-)
# >> files libqmfclient1-qt5
%{_libdir}/libqmfclient5.so.*
%{_libdir}/qmf/plugins5/contentmanagers/libqmfstoragemanager.so
%{_libdir}/qmf/plugins5/ssoauth/libpasswordplugin.so
# << files libqmfclient1-qt5

%files examples
%defattr(-,root,root,-)
# >> files examples
%{_bindir}/messagingaccounts5
%{_bindir}/qtmail5
%{_bindir}/serverobserver5
%{_libdir}/qmf/plugins5/composers/libemailcomposer.so
%{_libdir}/qmf/plugins5/viewers/libgenericviewer.so
# << files examples

%files tests
%defattr(-,root,root,-)
# >> files tests
%{_datadir}/accounts/*
/opt/tests/qmf-qt5/*
# << files tests

%files doc
%defattr(-,root,root,-)
# >> files doc
%doc %{_docdir}/qmf-qt5/qch/qmf.qch
# << files doc
