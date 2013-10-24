TEMPLATE = subdirs
SUBDIRS = messageserver
equals(QT_MAJOR_VERSION, 5): SUBDIRS += accountscheck
