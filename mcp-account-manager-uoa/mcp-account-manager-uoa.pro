TEMPLATE = lib
TARGET = mcp-account-manager-uoa

CONFIG  += link_pkgconfig use_c_linker plugin no_plugin_name_prefix
CONFIG -= qt
PKGCONFIG += mission-control-plugins libaccounts-glib

SOURCES = empathy-webcredentials-monitor.c \
        mcp-account-manager-uoa.c \
        mission-control-plugin.c

HEADERS = mcp-account-manager-uoa.h\
        empathy-webcredentials-monitor.h

target.path = $$system(pkg-config --variable=plugindir mission-control-plugins)
INSTALLS += target
