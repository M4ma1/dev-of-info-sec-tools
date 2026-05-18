QT -= gui
QT += core

CONFIG += c++17 console
CONFIG -= app_bundle

TARGET = FileEncryptor

SOURCES += \
    main.cpp \
    cryptomanager.cpp \
    filewalker.cpp

HEADERS += \
    cryptomanager.h \
    filewalker.h

unix:macx {
    OPENSSL_PATH = /opt/homebrew/opt/openssl@3

    INCLUDEPATH += $$OPENSSL_PATH/include

    # Qt 5.15.2 on Apple Silicon may run under Rosetta (x86_64).
    # Use the static library to avoid dynamic arch mismatch.
    LIBS += $$OPENSSL_PATH/lib/libssl.a
    LIBS += $$OPENSSL_PATH/lib/libcrypto.a

    # macOS system frameworks required by OpenSSL static build
    LIBS += -framework CoreFoundation -framework Security
}

unix:!macx {
    # Linux — OpenSSL is in the standard system paths
    LIBS += -lssl -lcrypto
}

win32 {
    INCLUDEPATH += "C:/OpenSSL-Win64/include"
    LIBS += -L"C:/OpenSSL-Win64/lib" -lssl -lcrypto
}
