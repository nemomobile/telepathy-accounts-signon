TEMPLATE = app
CONFIG -= qt

CONFIG += link_pkgconfig
PKGCONFIG += libsignon-glib telepathy-glib libaccounts-glib libsoup-2.4

DEFINES += HAVE_UOA \
    EMPATHY_UOA_PROVIDER=\\\"im.telepathy.Account.Storage.UOA\\\"

SOURCES += empathy-auth-client.c \
    empathy-auth-factory.c \
    empathy-server-sasl-handler.c \
    empathy-server-tls-handler.c \
    empathy-keyring.c \
    empathy-uoa-utils.c \
    empathy-sasl-mechanisms.c \
    empathy-uoa-auth-handler.c

HEADERS += empathy-auth-factory.h \
    empathy-debug.h \
    empathy-keyring.h \
    empathy-sasl-mechanisms.h \
    empathy-server-sasl-handler.h \
    empathy-server-tls-handler.h \
    empathy-uoa-utils.h \
    empathy-utils.h \
    empathy-uoa-auth-handler.h

OTHER_FILES += org.freedesktop.Telepathy.Client.SaslSignonAuth.service \
    SaslSignonAuth.client

target.path = /usr/libexec/

service.files = org.freedesktop.Telepathy.Client.SaslSignonAuth.service
service.path = /usr/share/dbus-1/services/

client.files = SaslSignonAuth.client
client.path = /usr/share/telepathy/clients/

INSTALLS += target service client

