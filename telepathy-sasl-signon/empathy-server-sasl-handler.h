/*
 * empathy-server-sasl-handler.h - Header for EmpathyServerSASLHandler
 * Copyright (C) 2010 Collabora Ltd.
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

#ifndef __EMPATHY_SERVER_SASL_HANDLER_H__
#define __EMPATHY_SERVER_SASL_HANDLER_H__

#include <glib-object.h>
#include <gio/gio.h>

#include <telepathy-glib/telepathy-glib.h>

G_BEGIN_DECLS

typedef struct _EmpathyServerSASLHandler EmpathyServerSASLHandler;
typedef struct _EmpathyServerSASLHandlerClass EmpathyServerSASLHandlerClass;

struct _EmpathyServerSASLHandlerClass {
    GObjectClass parent_class;
};

struct _EmpathyServerSASLHandler {
    GObject parent;
    gpointer priv;
};

GType empathy_server_sasl_handler_get_type (void);

#define EMPATHY_TYPE_SERVER_SASL_HANDLER \
  (empathy_server_sasl_handler_get_type ())
#define EMPATHY_SERVER_SASL_HANDLER(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), EMPATHY_TYPE_SERVER_SASL_HANDLER, \
    EmpathyServerSASLHandler))
#define EMPATHY_SERVER_SASL_HANDLER_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass), EMPATHY_TYPE_SERVER_SASL_HANDLER, \
  EmpathyServerSASLHandlerClass))
#define EMPATHY_IS_SERVER_SASL_HANDLER(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj), EMPATHY_TYPE_SERVER_SASL_HANDLER))
#define EMPATHY_IS_SERVER_SASL_HANDLER_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass), EMPATHY_TYPE_SERVER_SASL_HANDLER))
#define EMPATHY_SERVER_SASL_HANDLER_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), EMPATHY_TYPE_SERVER_SASL_HANDLER, \
  EmpathyServerSASLHandlerClass))

void empathy_server_sasl_handler_new_async (
    TpAccount *account, TpChannel *channel,
    GAsyncReadyCallback callback, gpointer user_data);

EmpathyServerSASLHandler * empathy_server_sasl_handler_new_finish (
    GAsyncResult *result, GError **error);

void empathy_server_sasl_handler_provide_password (
    EmpathyServerSASLHandler *handler, const gchar *password,
    gboolean remember);

void empathy_server_sasl_handler_cancel (EmpathyServerSASLHandler *handler);

TpAccount * empathy_server_sasl_handler_get_account (
    EmpathyServerSASLHandler *handler);

TpChannel * empathy_server_sasl_handler_get_channel (
    EmpathyServerSASLHandler *handler);

gboolean empathy_server_sasl_handler_has_password (
    EmpathyServerSASLHandler *handler);

gboolean empathy_server_sasl_handler_can_save_response_somewhere (
    EmpathyServerSASLHandler *self);

G_END_DECLS

#endif /* #ifndef __EMPATHY_SERVER_SASL_HANDLER_H__*/
