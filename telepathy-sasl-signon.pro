TEMPLATE = app

CONFIG += link_pkgconfig
PKGCONFIG += libsignon-glib telepathy-glib libaccounts-glib libsoup-2.4

INCLUDEPATH += src
DEFINES += HAVE_UOA \
    EMPATHY_UOA_PROVIDER=\\\"im.telepathy.Account.Storage.UOA\\\"

SOURCES += src/empathy-auth-client.c \
    src/empathy-auth-factory.c \
    src/empathy-server-sasl-handler.c \
    src/empathy-server-tls-handler.c \
    src/empathy-keyring.c \
    src/empathy-uoa-utils.c \
    src/empathy-sasl-mechanisms.c \
    src/empathy-uoa-auth-handler.c

HEADERS += src/empathy-auth-factory.h \
    src/empathy-debug.h \
    src/empathy-keyring.h \
    src/empathy-sasl-mechanisms.h \
    src/empathy-server-sasl-handler.h \
    src/empathy-server-tls-handler.h \
    src/empathy-uoa-utils.h \
    src/empathy-utils.h \
    src/empathy-uoa-auth-handler.h

OTHER_FILES += org.freedesktop.Telepathy.Client.SaslSignonAuth.service \
    SaslSignonAuth.client

target.path = /usr/libexec/

service.files = org.freedesktop.Telepathy.Client.SaslSignonAuth.service
service.path = /usr/share/dbus-1/services/

client.files = SaslSignonAuth.client
client.path = /usr/share/telepathy/clients/

INSTALLS += target service client

