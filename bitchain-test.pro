TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp 

LIBS += -lcrypto

HEADERS += \
    byte_order.h \
    varint.h \
    base58.h \
    hash.h

DISTFILES += \
    test.py
