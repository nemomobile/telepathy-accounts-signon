TEMPLATE = app

CONFIG += link_pkgconfig
PKGCONFIG += libsignon-glib telepathy-glib libaccounts-glib libsoup-2.4

SOURCES += empathy-auth-client.c \
    empathy-auth-factory.c \
    empathy-server-sasl-handler.c \
    empathy-server-tls-handler.c \
    empathy-keyring.c \
    empathy-uoa-utils.c \
    empathy-sasl-mechanisms.c

target.path = /usr/libexec/

service.files = org.freedesktop.Telepathy.Client.SaslSignonAuth.service
service.path = /usr/share/dbus-1/services/

client.files = SaslSignonAuth.client
client.path = /usr/share/telepathy/clients/

INSTALLS += target service client

