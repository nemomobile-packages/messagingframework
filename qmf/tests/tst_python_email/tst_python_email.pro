TEMPLATE = app
CONFIG += qmfclient
TARGET = tst_python_email

DEFINES += SRCDIR=\\\"$$_PRO_FILE_PWD_\\\"

equals(QT_MAJOR_VERSION, 4): testdata.path = /opt/tests/qmf/testdata
equals(QT_MAJOR_VERSION, 5): testdata.path = /opt/tests/qmf-qt5/testdata

testdata.files = testdata/*

INSTALLS += testdata

SOURCES += tst_python_email.cpp

include(../tests.pri)
