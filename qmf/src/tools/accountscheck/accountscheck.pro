
TEMPLATE = app
TARGET = qmf-accountscheck
QT -= gui

target.path += /usr/bin

CONFIG += link_pkgconfig
PKGCONFIG += accounts-qt5
LIBS += -lqmfclient5

SOURCES += accountscheck.cpp

# Target to install systemd service file
systemd.files = ../systemd/messageserver5.service
systemd.path= /usr/lib/systemd/user/

# Target to install script file
script.files = ../systemd/messageserver5.sh
script.path = /usr/bin

INSTALLS+= target systemd script
