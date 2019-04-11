#-------------------------------------------------
#
# Project created by QtCreator 2019-01-22T12:51:32
#
#-------------------------------------------------

QT       += core gui
QT += network

TARGET = SecureFileTransferClient
TEMPLATE = app
LIBS += -lcrypto


SOURCES += main.cpp\
        mainwindow.cpp \
    SM3.c \
    SM4_CBC.c \
    SESSION_FUNCS.c

HEADERS  += mainwindow.h \
    SM3.h \
    SM4_CBC.h \
    SESSION_FUNCS.h

FORMS    += mainwindow.ui
