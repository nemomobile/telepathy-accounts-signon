/*
 * empathy-server-tls-handler.h - Header for EmpathyServerTLSHandler
 * Copyright (C) 2010 Collabora Ltd.
 * @author Cosimo Cecchi <cosimo.cecchi@collabora.co.uk>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __EMPATHY_SERVER_TLS_HANDLER_H__
#define __EMPATHY_SERVER_TLS_HANDLER_H__

#include <glib-object.h>
#include <gio/gio.h>

#include <telepathy-glib/telepathy-glib.h>

G_BEGIN_DECLS

typedef struct _EmpathyServerTLSHandler EmpathyServerTLSHandler;
typedef struct _EmpathyServerTLSHandlerClass EmpathyServerTLSHandlerClass;

struct _EmpathyServerTLSHandlerClass {
    GObjectClass parent_class;
};

struct _EmpathyServerTLSHandler {
    GObject parent;
    gpointer priv;
};

GType empathy_server_tls_handler_get_type (void);

#define EMPATHY_TYPE_SERVER_TLS_HANDLER \
  (empathy_server_tls_handler_get_type ())
#define EMPATHY_SERVER_TLS_HANDLER(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), EMPATHY_TYPE_SERVER_TLS_HANDLER, \
    EmpathyServerTLSHandler))
#define EMPATHY_SERVER_TLS_HANDLER_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass), EMPATHY_TYPE_SERVER_TLS_HANDLER, \
  EmpathyServerTLSHandlerClass))
#define EMPATHY_IS_SERVER_TLS_HANDLER(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj), EMPATHY_TYPE_SERVER_TLS_HANDLER))
#define EMPATHY_IS_SERVER_TLS_HANDLER_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass), EMPATHY_TYPE_SERVER_TLS_HANDLER))
#define EMPATHY_SERVER_TLS_HANDLER_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), EMPATHY_TYPE_SERVER_TLS_HANDLER, \
  EmpathyServerTLSHandlerClass))

void empathy_server_tls_handler_new_async (TpChannel *channel,
    GAsyncReadyCallback callback, gpointer user_data);
EmpathyServerTLSHandler * empathy_server_tls_handler_new_finish (
    GAsyncResult *result, GError **error);

TpTLSCertificate * empathy_server_tls_handler_get_certificate (
    EmpathyServerTLSHandler *self);

G_END_DECLS

#endif /* #ifndef __EMPATHY_SERVER_TLS_HANDLER_H__*/
