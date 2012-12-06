/*
 * empathy-server-sasl-handler.c - Source for EmpathyServerSASLHandler
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

#include "empathy-server-sasl-handler.h"

#include <string.h>

#include "empathy-debug.h"
//#include "empathy-keyring.h"
//#include "empathy-sasl-mechanisms.h"

enum {
  PROP_CHANNEL = 1,
  PROP_ACCOUNT,
  LAST_PROPERTY,
};

/* signal enum */
enum {
  AUTH_PASSWORD_FAILED,
  INVALIDATED,
  LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

typedef struct {
  TpChannel *channel;
  TpAccount *account;

  GSimpleAsyncResult *result;

  gchar *password;
  gboolean save_password;

  GSimpleAsyncResult *async_init_res;
} EmpathyServerSASLHandlerPriv;

static void async_initable_iface_init (GAsyncInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (EmpathyServerSASLHandler, empathy_server_sasl_handler,
    G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, async_initable_iface_init));

static void
empathy_server_sasl_handler_set_password_cb (GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  GError *error = NULL;

  if (!empathy_keyring_set_account_password_finish (TP_ACCOUNT (source), result,
          &error))
    {
      DEBUG ("Failed to set password: %s", error->message);
      g_clear_error (&error);
    }
  else
    {
      DEBUG ("Password set successfully.");
    }
}

static gboolean
empathy_server_sasl_handler_give_password (gpointer data)
{
  EmpathyServerSASLHandler *self = data;
  EmpathyServerSASLHandlerPriv *priv = self->priv;

  empathy_server_sasl_handler_provide_password (self,
      priv->password, FALSE);

  return FALSE;
}

static void
empathy_server_sasl_handler_get_password_async_cb (GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  EmpathyServerSASLHandlerPriv *priv;
  const gchar *password;
  GError *error = NULL;

  priv = EMPATHY_SERVER_SASL_HANDLER (user_data)->priv;

  password = empathy_keyring_get_account_password_finish (TP_ACCOUNT (source),
      result, &error);

  if (password != NULL)
    {
      priv->password = g_strdup (password);

      /* Do this in an idle so the async result will get there
       * first. */
      g_idle_add (empathy_server_sasl_handler_give_password, user_data);
    }

  g_simple_async_result_complete (priv->async_init_res);
  tp_clear_object (&priv->async_init_res);
}

static void
empathy_server_sasl_handler_init_async (GAsyncInitable *initable,
    gint io_priority,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data)
{
  EmpathyServerSASLHandler *self = EMPATHY_SERVER_SASL_HANDLER (initable);
  EmpathyServerSASLHandlerPriv *priv = self->priv;

  g_assert (priv->account != NULL);

  priv->async_init_res = g_simple_async_result_new (G_OBJECT (self),
      callback, user_data, empathy_server_sasl_handler_new_async);

  empathy_keyring_get_account_password_async (priv->account,
      empathy_server_sasl_handler_get_password_async_cb, self);
}

static gboolean
empathy_server_sasl_handler_init_finish (GAsyncInitable *initable,
    GAsyncResult *res,
    GError **error)
{
  if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res),
          error))
    return FALSE;

  return TRUE;
}

static void
async_initable_iface_init (GAsyncInitableIface *iface)
{
  iface->init_async = empathy_server_sasl_handler_init_async;
  iface->init_finish = empathy_server_sasl_handler_init_finish;
}

static void
channel_invalidated_cb (TpProxy *proxy,
    guint domain,
    gint code,
    gchar *message,
    EmpathyServerSASLHandler *self)
{
  g_signal_emit (self, signals[INVALIDATED], 0);
}

static void
empathy_server_sasl_handler_constructed (GObject *object)
{
  EmpathyServerSASLHandlerPriv *priv = EMPATHY_SERVER_SASL_HANDLER (object)->priv;
  GError *error = NULL;

  if (error != NULL)
    {
      DEBUG ("Failed to connect to SASLStatusChanged: %s", error->message);
      g_clear_error (&error);
    }

  tp_g_signal_connect_object (priv->channel, "invalidated",
      G_CALLBACK (channel_invalidated_cb), object, 0);
}

static void
empathy_server_sasl_handler_get_property (GObject *object,
    guint property_id,
    GValue *value,
    GParamSpec *pspec)
{
  EmpathyServerSASLHandlerPriv *priv = EMPATHY_SERVER_SASL_HANDLER (object)->priv;

  switch (property_id)
    {
    case PROP_CHANNEL:
      g_value_set_object (value, priv->channel);
      break;
    case PROP_ACCOUNT:
      g_value_set_object (value, priv->account);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
    }
}

static void
empathy_server_sasl_handler_set_property (GObject *object,
    guint property_id,
    const GValue *value,
    GParamSpec *pspec)
{
  EmpathyServerSASLHandlerPriv *priv = EMPATHY_SERVER_SASL_HANDLER (object)->priv;

  switch (property_id)
    {
    case PROP_CHANNEL:
      priv->channel = g_value_dup_object (value);
      break;
    case PROP_ACCOUNT:
      priv->account = g_value_dup_object (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
    }
}

static void
empathy_server_sasl_handler_dispose (GObject *object)
{
  EmpathyServerSASLHandlerPriv *priv = EMPATHY_SERVER_SASL_HANDLER (object)->priv;

  DEBUG ("%p", object);

  tp_clear_object (&priv->channel);
  tp_clear_object (&priv->account);

  G_OBJECT_CLASS (empathy_server_sasl_handler_parent_class)->dispose (object);
}

static void
empathy_server_sasl_handler_finalize (GObject *object)
{
  EmpathyServerSASLHandlerPriv *priv = EMPATHY_SERVER_SASL_HANDLER (object)->priv;

  DEBUG ("%p", object);

  tp_clear_pointer (&priv->password, g_free);

  G_OBJECT_CLASS (empathy_server_sasl_handler_parent_class)->finalize (object);
}

static void
empathy_server_sasl_handler_class_init (EmpathyServerSASLHandlerClass *klass)
{
  GObjectClass *oclass = G_OBJECT_CLASS (klass);
  GParamSpec *pspec;

  oclass->constructed = empathy_server_sasl_handler_constructed;
  oclass->get_property = empathy_server_sasl_handler_get_property;
  oclass->set_property = empathy_server_sasl_handler_set_property;
  oclass->dispose = empathy_server_sasl_handler_dispose;
  oclass->finalize = empathy_server_sasl_handler_finalize;

  g_type_class_add_private (klass, sizeof (EmpathyServerSASLHandlerPriv));

  pspec = g_param_spec_object ("channel", "The TpChannel",
      "The TpChannel this handler is supposed to handle.",
      TP_TYPE_CHANNEL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (oclass, PROP_CHANNEL, pspec);

  pspec = g_param_spec_object ("account", "The TpAccount",
      "The TpAccount this channel belongs to.",
      TP_TYPE_ACCOUNT,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (oclass, PROP_ACCOUNT, pspec);

  signals[AUTH_PASSWORD_FAILED] = g_signal_new ("auth-password-failed",
      G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 0,
      NULL, NULL,
      g_cclosure_marshal_generic,
      G_TYPE_NONE, 1, G_TYPE_STRING);

  signals[INVALIDATED] = g_signal_new ("invalidated",
      G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 0,
      NULL, NULL,
      g_cclosure_marshal_generic,
      G_TYPE_NONE, 0);
}

static void
empathy_server_sasl_handler_init (EmpathyServerSASLHandler *self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      EMPATHY_TYPE_SERVER_SASL_HANDLER, EmpathyServerSASLHandlerPriv);
}

EmpathyServerSASLHandler *
empathy_server_sasl_handler_new_finish (GAsyncResult *result,
    GError **error)
{
  GObject *object, *source_object;

  source_object = g_async_result_get_source_object (result);

  object = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object),
      result, error);
  g_object_unref (source_object);

  if (object != NULL)
    return EMPATHY_SERVER_SASL_HANDLER (object);
  else
    return NULL;
}

void
empathy_server_sasl_handler_new_async (TpAccount *account,
    TpChannel *channel,
    GAsyncReadyCallback callback,
    gpointer user_data)
{
  g_return_if_fail (TP_IS_ACCOUNT (account));
  g_return_if_fail (TP_IS_CHANNEL (channel));
  g_return_if_fail (callback != NULL);

  g_async_initable_new_async (EMPATHY_TYPE_SERVER_SASL_HANDLER,
      G_PRIORITY_DEFAULT, NULL, callback, user_data,
      "account", account,
      "channel", channel,
      NULL);
}

static void
auth_cb (GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  EmpathyServerSASLHandler *self = user_data;
  EmpathyServerSASLHandlerPriv *priv = self->priv;
  GError *error = NULL;

  if (!empathy_sasl_auth_finish (priv->channel, result, &error))
    {
      if (g_error_matches (error, TP_ERROR, TP_ERROR_AUTHENTICATION_FAILED))
        {
          g_signal_emit (self, signals[AUTH_PASSWORD_FAILED], 0, priv->password);
        }
      g_clear_error (&error);
    }
  else
    {
      DEBUG ("Saving password in keyring");
      empathy_keyring_set_account_password_async (priv->account,
          priv->password, priv->save_password,
          empathy_server_sasl_handler_set_password_cb,
          NULL);
    }

  tp_channel_close_async (priv->channel, NULL, NULL);
  g_object_unref (self);
}

static gboolean
channel_has_may_save_response (TpChannel *channel)
{
  /* determine if we are permitted to save the password locally */
  GVariant *props;
  gboolean may_save_response;

  props = tp_channel_dup_immutable_properties (channel);

  if (!g_variant_lookup (props,
        TP_PROP_CHANNEL_INTERFACE_SASL_AUTHENTICATION_MAY_SAVE_RESPONSE,
        "b", &may_save_response))
    {
      DEBUG ("MaySaveResponse unknown, assuming TRUE");
      may_save_response = TRUE;
    }

  g_variant_unref (props);
  return may_save_response;
}

void
empathy_server_sasl_handler_provide_password (
    EmpathyServerSASLHandler *handler,
    const gchar *password,
    gboolean remember)
{
  EmpathyServerSASLHandlerPriv *priv;
  gboolean may_save_response;

  g_return_if_fail (EMPATHY_IS_SERVER_SASL_HANDLER (handler));

  priv = handler->priv;

  empathy_sasl_auth_password_async (priv->channel, password,
      auth_cb, g_object_ref (handler));

  DEBUG ("%sremembering the password", remember ? "" : "not ");

  may_save_response = channel_has_may_save_response (priv->channel);

  if (remember)
    {
      if (may_save_response)
        {
          g_free (priv->password);

          /* We'll save the password if we manage to connect */
          priv->password = g_strdup (password);
          priv->save_password = TRUE;
        }
      else if (//tp_proxy_has_interface_by_id (priv->channel,
            //EMP_IFACE_QUARK_CHANNEL_INTERFACE_CREDENTIALS_STORAGE))
            FALSE)
        {
          DEBUG ("Channel implements Ch.I.CredentialsStorage");
        }
      else
        {
          DEBUG ("Asked to remember password, but doing so is not permitted");
        }
    }

  if (!may_save_response)
    {
      /* delete any password present, it shouldn't be there */
      empathy_keyring_delete_account_password_async (priv->account, NULL, NULL);
    }

#if 0
  /* Additionally, if we implement Ch.I.CredentialsStorage, inform that
   * whether we want to remember the password */
  if (tp_proxy_has_interface_by_id (priv->channel,
        EMP_IFACE_QUARK_CHANNEL_INTERFACE_CREDENTIALS_STORAGE))
    {
      emp_cli_channel_interface_credentials_storage_call_store_credentials (
          TP_PROXY (priv->channel), -1, remember, NULL, NULL, NULL, NULL);
    }
#endif
}

void
empathy_server_sasl_handler_cancel (EmpathyServerSASLHandler *handler)
{
  EmpathyServerSASLHandlerPriv *priv;

  g_return_if_fail (EMPATHY_IS_SERVER_SASL_HANDLER (handler));

  priv = handler->priv;

  DEBUG ("Cancelling SASL mechanism...");

  tp_cli_channel_interface_sasl_authentication_call_abort_sasl (
      priv->channel, -1, TP_SASL_ABORT_REASON_USER_ABORT,
      "User cancelled the authentication",
      NULL, NULL, NULL, NULL);
}

TpAccount *
empathy_server_sasl_handler_get_account (EmpathyServerSASLHandler *handler)
{
  EmpathyServerSASLHandlerPriv *priv;

  g_return_val_if_fail (EMPATHY_IS_SERVER_SASL_HANDLER (handler), NULL);

  priv = handler->priv;

  return priv->account;
}

TpChannel *
empathy_server_sasl_handler_get_channel (EmpathyServerSASLHandler *handler)
{
  EmpathyServerSASLHandlerPriv *priv;

  g_return_val_if_fail (EMPATHY_IS_SERVER_SASL_HANDLER (handler), NULL);

  priv = handler->priv;

  return priv->channel;
}

gboolean
empathy_server_sasl_handler_has_password (EmpathyServerSASLHandler *handler)
{
  EmpathyServerSASLHandlerPriv *priv;

  g_return_val_if_fail (EMPATHY_IS_SERVER_SASL_HANDLER (handler), FALSE);

  priv = handler->priv;

  return (priv->password != NULL);
}

/**
 * empathy_server_sasl_handler_can_save_response_somewhere:
 * @self:
 *
 * Returns: %TRUE if the response can be saved somewhere, either the keyring
 *   or via Ch.I.CredentialsStorage
 */
gboolean
empathy_server_sasl_handler_can_save_response_somewhere (
    EmpathyServerSASLHandler *self)
{
  EmpathyServerSASLHandlerPriv *priv;
  gboolean may_save_response;
  gboolean has_storage_iface;

  g_return_val_if_fail (EMPATHY_IS_SERVER_SASL_HANDLER (self), FALSE);

  priv = self->priv;

  may_save_response = channel_has_may_save_response (priv->channel);

  // XXX
  has_storage_iface = FALSE; //tp_proxy_has_interface_by_id (priv->channel,
      //EMP_IFACE_QUARK_CHANNEL_INTERFACE_CREDENTIALS_STORAGE);

  return may_save_response || has_storage_iface;
}
