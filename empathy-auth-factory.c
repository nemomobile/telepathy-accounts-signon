/*
 * empathy-auth-factory.c - Source for EmpathyAuthFactory
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

#include "empathy-auth-factory.h"
#include "empathy-debug.h"
#include "empathy-utils.h"

//#include "empathy-keyring.h"
//#include "empathy-sasl-mechanisms.h"
#include "empathy-server-sasl-handler.h"
#include "empathy-server-tls-handler.h"
//#include "empathy-utils.h"

// XXX
#ifdef HAVE_UOA
#include "empathy-uoa-auth-handler.h"
#endif /* HAVE_UOA */

G_DEFINE_TYPE (EmpathyAuthFactory, empathy_auth_factory, TP_TYPE_BASE_CLIENT);

struct _EmpathyAuthFactoryPriv {
  /* Keep a ref here so the auth client doesn't have to mess with
   * refs. It will be cleared when the channel (and so the handler)
   * gets invalidated.
   *
   * The channel path of the handler's channel (borrowed gchar *) ->
   * reffed (EmpathyServerSASLHandler *)
   * */
  GHashTable *sasl_handlers;

#ifdef HAVE_GOA
  EmpathyGoaAuthHandler *goa_handler;
#endif /* HAVE_GOA */

#ifdef HAVE_UOA
  EmpathyUoaAuthHandler *uoa_handler;
#endif /* HAVE_UOA */

  /* If an account failed to connect and user enters a new password to try, we
   * store it in this hash table and will try to use it next time the account
   * attemps to connect.
   *
   * reffed TpAccount -> owned password (gchar *) */
  GHashTable *retry_passwords;

  gboolean dispose_run;
};

enum {
  NEW_SERVER_TLS_HANDLER,
  NEW_SERVER_SASL_HANDLER,
  AUTH_PASSWORD_FAILED,
  LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0, };

#define GET_PRIV(obj) EMPATHY_GET_PRIV (obj, EmpathyAuthFactory)

static EmpathyAuthFactory *auth_factory_singleton = NULL;

typedef struct {
  TpHandleChannelsContext *context;
  EmpathyAuthFactory *self;
} HandlerContextData;

static void
handler_context_data_free (HandlerContextData *data)
{
  tp_clear_object (&data->self);
  tp_clear_object (&data->context);

  g_slice_free (HandlerContextData, data);
}

static HandlerContextData *
handler_context_data_new (EmpathyAuthFactory *self,
    TpHandleChannelsContext *context)
{
  HandlerContextData *data;

  data = g_slice_new0 (HandlerContextData);
  data->self = g_object_ref (self);

  if (context != NULL)
    data->context = g_object_ref (context);

  return data;
}

static void
server_tls_handler_ready_cb (GObject *source,
    GAsyncResult *res,
    gpointer user_data)
{
  EmpathyServerTLSHandler *handler;
  GError *error = NULL;
  HandlerContextData *data = user_data;

  handler = empathy_server_tls_handler_new_finish (res, &error);

  if (error != NULL)
    {
      DEBUG ("Failed to create a server TLS handler; error %s",
          error->message);
      tp_handle_channels_context_fail (data->context, error);

      g_error_free (error);
    }
  else
    {
      tp_handle_channels_context_accept (data->context);
      g_signal_emit (data->self, signals[NEW_SERVER_TLS_HANDLER], 0,
          handler);

      g_object_unref (handler);
    }

  handler_context_data_free (data);
}

static void
sasl_handler_invalidated_cb (EmpathyServerSASLHandler *handler,
    gpointer user_data)
{
  EmpathyAuthFactory *self = user_data;
  EmpathyAuthFactoryPriv *priv = GET_PRIV (self);
  TpChannel * channel;

  channel = empathy_server_sasl_handler_get_channel (handler);
  g_assert (channel != NULL);

  DEBUG ("SASL handler for channel %s is invalidated, unref it",
      tp_proxy_get_object_path (channel));

  g_hash_table_remove (priv->sasl_handlers, tp_proxy_get_object_path (channel));
}

static void
sasl_handler_auth_password_failed_cb (EmpathyServerSASLHandler *handler,
    const gchar *password,
    EmpathyAuthFactory *self)
{
  TpAccount *account;

  account = empathy_server_sasl_handler_get_account (handler);

  g_signal_emit (self, signals[AUTH_PASSWORD_FAILED], 0, account, password);
}

static void
server_sasl_handler_ready_cb (GObject *source,
    GAsyncResult *res,
    gpointer user_data)
{
  EmpathyAuthFactoryPriv *priv;
  GError *error = NULL;
  HandlerContextData *data = user_data;
  EmpathyServerSASLHandler *handler;

  priv = GET_PRIV (data->self);
  handler = empathy_server_sasl_handler_new_finish (res, &error);

  if (error != NULL)
    {
      DEBUG ("Failed to create a server SASL handler; error %s",
          error->message);

      if (data->context != NULL)
        tp_handle_channels_context_fail (data->context, error);

      g_error_free (error);
    }
  else
    {
      TpChannel *channel;
      const gchar *password;
      TpAccount *account;

      if (data->context != NULL)
        tp_handle_channels_context_accept (data->context);

      channel = empathy_server_sasl_handler_get_channel (handler);
      g_assert (channel != NULL);

      /* Pass the ref to the hash table */
      g_hash_table_insert (priv->sasl_handlers,
          (gpointer) tp_proxy_get_object_path (channel), handler);

      tp_g_signal_connect_object (handler, "invalidated",
          G_CALLBACK (sasl_handler_invalidated_cb), data->self, 0);

      tp_g_signal_connect_object (handler, "auth-password-failed",
          G_CALLBACK (sasl_handler_auth_password_failed_cb), data->self, 0);

      /* Is there a retry password? */
      account = empathy_server_sasl_handler_get_account (handler);

      password = g_hash_table_lookup (data->self->priv->retry_passwords,
          account);
      if (password != NULL)
        {
          gboolean save;

          DEBUG ("Use retry password");

          /* We want to save this new password only if there is another
           * (wrong) password saved. The SASL handler will only save it if it
           * manages to connect. */
          save = empathy_server_sasl_handler_has_password (handler);

          empathy_server_sasl_handler_provide_password (handler,
              password, save);

          /* We only want to try this password once */
          g_hash_table_remove (data->self->priv->retry_passwords, account);
        }

      g_signal_emit (data->self, signals[NEW_SERVER_SASL_HANDLER], 0,
          handler);
    }

  handler_context_data_free (data);
}

static gboolean
common_checks (EmpathyAuthFactory *self,
    GList *channels,
    gboolean observe,
    GError **error)
{
  EmpathyAuthFactoryPriv *priv = GET_PRIV (self);
  TpChannel *channel;
  const GError *dbus_error;
  EmpathyServerSASLHandler *handler;

  /* there can't be more than one ServerTLSConnection or
   * ServerAuthentication channels at the same time, for the same
   * connection/account.
   */
  if (g_list_length (channels) != 1)
    {
      g_set_error (error, TP_ERROR, TP_ERROR_INVALID_ARGUMENT,
          "Can't %s more than one ServerTLSConnection or ServerAuthentication "
          "channel for the same connection.", observe ? "observe" : "handle");

      return FALSE;
    }

  channel = channels->data;

  if (tp_channel_get_channel_type_id (channel) !=
      TP_IFACE_QUARK_CHANNEL_TYPE_SERVER_AUTHENTICATION)
    {
      /* If we are observing we care only about ServerAuthentication channels.
       * If we are handling we care about ServerAuthentication and
       * ServerTLSConnection channels. */
      if (observe
          || tp_channel_get_channel_type_id (channel) !=
          TP_IFACE_QUARK_CHANNEL_TYPE_SERVER_TLS_CONNECTION)
        {
          g_set_error (error, TP_ERROR, TP_ERROR_INVALID_ARGUMENT,
              "Can only %s ServerTLSConnection or ServerAuthentication channels, "
              "this was a %s channel", observe ? "observe" : "handle",
              tp_channel_get_channel_type (channel));

          return FALSE;
        }
    }

  handler = g_hash_table_lookup (priv->sasl_handlers,
          tp_proxy_get_object_path (channel));

  if (tp_channel_get_channel_type_id (channel) ==
      TP_IFACE_QUARK_CHANNEL_TYPE_SERVER_AUTHENTICATION
      && handler != NULL &&
      !observe)
    {
      g_set_error (error, TP_ERROR, TP_ERROR_INVALID_ARGUMENT,
          "We are already handling this channel: %s",
          tp_proxy_get_object_path (channel));

      return FALSE;
    }

  dbus_error = tp_proxy_get_invalidated (channel);
  if (dbus_error != NULL)
    {
      *error = g_error_copy (dbus_error);
      return FALSE;
    }

  return TRUE;
}

static void
handle_channels (TpBaseClient *handler,
    TpAccount *account,
    TpConnection *connection,
    GList *channels,
    GList *requests_satisfied,
    gint64 user_action_time,
    TpHandleChannelsContext *context)
{
  TpChannel *channel;
  GError *error = NULL;
  EmpathyAuthFactory *self = EMPATHY_AUTH_FACTORY (handler);
  HandlerContextData *data;

  DEBUG ("Handle TLS or SASL carrier channels.");

  if (!common_checks (self, channels, FALSE, &error))
    {
      DEBUG ("Failed checks: %s", error->message);
      tp_handle_channels_context_fail (context, error);
      g_clear_error (&error);
      return;
    }

  /* The common checks above have checked this is fine. */
  channel = channels->data;

  /* Only password authentication is supported from here */
  if (tp_channel_get_channel_type_id (channel) ==
      TP_IFACE_QUARK_CHANNEL_TYPE_SERVER_AUTHENTICATION &&
      !empathy_sasl_channel_supports_mechanism (channel,
          "X-TELEPATHY-PASSWORD"))
    {
      g_set_error_literal (&error, TP_ERROR, TP_ERROR_INVALID_ARGUMENT,
          "Only the X-TELEPATHY-PASSWORD SASL mechanism is supported");
      DEBUG ("%s", error->message);
      tp_handle_channels_context_fail (context, error);
      g_clear_error (&error);
      return;
    }

  data = handler_context_data_new (self, context);
  tp_handle_channels_context_delay (context);

  /* create a handler */
  if (tp_channel_get_channel_type_id (channel) ==
      TP_IFACE_QUARK_CHANNEL_TYPE_SERVER_TLS_CONNECTION)
    {
      empathy_server_tls_handler_new_async (channel, server_tls_handler_ready_cb,
          data);
    }
  else if (tp_channel_get_channel_type_id (channel) ==
      TP_IFACE_QUARK_CHANNEL_TYPE_SERVER_AUTHENTICATION)
    {
      empathy_server_sasl_handler_new_async (account, channel,
          server_sasl_handler_ready_cb, data);
    }
}

typedef struct
{
  EmpathyAuthFactory *self;
  TpObserveChannelsContext *context;
  TpChannelDispatchOperation *dispatch_operation;
  TpAccount *account;
  TpChannel *channel;
} ObserveChannelsData;

static void
observe_channels_data_free (ObserveChannelsData *data)
{
  g_object_unref (data->context);
  g_object_unref (data->account);
  g_object_unref (data->channel);
  g_object_unref (data->dispatch_operation);
  g_slice_free (ObserveChannelsData, data);
}

static void
password_claim_cb (GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  ObserveChannelsData *data = user_data;
  GError *error = NULL;

  if (!tp_channel_dispatch_operation_claim_with_finish (
          TP_CHANNEL_DISPATCH_OPERATION (source), result, &error))
    {
      DEBUG ("Failed to call Claim: %s", error->message);
      g_clear_error (&error);
    }
  else
    {
      HandlerContextData *h_data;

      DEBUG ("Claim called successfully");

      h_data = handler_context_data_new (data->self, NULL);

      empathy_server_sasl_handler_new_async (TP_ACCOUNT (data->account),
          data->channel, server_sasl_handler_ready_cb, h_data);
    }

  observe_channels_data_free (data);
}

static void
get_password_cb (GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  ObserveChannelsData *data = user_data;

  if (empathy_keyring_get_account_password_finish (TP_ACCOUNT (source), result, NULL) == NULL)
    {
      /* We don't actually mind if this fails, just let the approver
       * go ahead and take the channel. */

      DEBUG ("We don't have a password for account %s, letting the event "
          "manager approver take it", tp_proxy_get_object_path (source));

      tp_observe_channels_context_accept (data->context);
      observe_channels_data_free (data);
    }
  else
    {
      DEBUG ("We have a password for account %s, calling Claim",
          tp_proxy_get_object_path (source));

      tp_channel_dispatch_operation_claim_with_async (data->dispatch_operation,
          TP_BASE_CLIENT (data->self), password_claim_cb, data);

      tp_observe_channels_context_accept (data->context);
    }
}

#ifdef HAVE_GOA
static void
goa_claim_cb (GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  ObserveChannelsData *data = user_data;
  EmpathyAuthFactory *self = data->self;
  GError *error = NULL;

  if (!tp_channel_dispatch_operation_claim_with_finish (data->dispatch_operation,
          result, &error))
    {
      DEBUG ("Failed to claim: %s", error->message);
      g_clear_error (&error);
    }
  else
    {
      empathy_goa_auth_handler_start (self->priv->goa_handler,
          data->channel, data->account);
    }

  observe_channels_data_free (data);
}
#endif /* HAVE_GOA */

#ifdef HAVE_UOA
static void
uoa_claim_cb (GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  ObserveChannelsData *data = user_data;
  EmpathyAuthFactory *self = data->self;
  GError *error = NULL;

  if (!tp_channel_dispatch_operation_claim_with_finish (data->dispatch_operation,
          result, &error))
    {
      DEBUG ("Failed to claim: %s", error->message);
      g_clear_error (&error);
    }
  else
    {
      empathy_uoa_auth_handler_start (self->priv->uoa_handler,
          data->channel, data->account);
    }

  observe_channels_data_free (data);
}
#endif /* HAVE_UOA */

static void
observe_channels (TpBaseClient *client,
    TpAccount *account,
    TpConnection *connection,
    GList *channels,
    TpChannelDispatchOperation *dispatch_operation,
    GList *requests,
    TpObserveChannelsContext *context)
{
  EmpathyAuthFactory *self = EMPATHY_AUTH_FACTORY (client);
  TpChannel *channel;
  GError *error = NULL;
  ObserveChannelsData *data;

  DEBUG ("New auth channel to observe");

  if (!common_checks (self, channels, TRUE, &error))
    {
      DEBUG ("Failed checks: %s", error->message);
      tp_observe_channels_context_fail (context, error);
      g_clear_error (&error);
      return;
    }

  /* The common checks above have checked this is fine. */
  channel = channels->data;

  data = g_slice_new0 (ObserveChannelsData);
  data->self = self;
  data->context = g_object_ref (context);
  data->dispatch_operation = g_object_ref (dispatch_operation);
  data->account = g_object_ref (account);
  data->channel = g_object_ref (channel);

#ifdef HAVE_GOA
  /* GOA auth? */
  if (empathy_goa_auth_handler_supports (self->priv->goa_handler, channel, account))
    {
      DEBUG ("Supported GOA account (%s), claim SASL channel",
          tp_proxy_get_object_path (account));

      tp_channel_dispatch_operation_claim_with_async (dispatch_operation,
          client, goa_claim_cb, data);
      tp_observe_channels_context_accept (context);
      return;
    }
#endif /* HAVE_GOA */

#ifdef HAVE_UOA
  /* UOA auth? */
  if (empathy_uoa_auth_handler_supports (self->priv->uoa_handler, channel, account))
    {
      DEBUG ("Supported UOA account (%s), claim SASL channel",
          tp_proxy_get_object_path (account));

      tp_channel_dispatch_operation_claim_with_async (dispatch_operation,
          client, uoa_claim_cb, data);
      tp_observe_channels_context_accept (context);
      return;
    }
#endif /* HAVE_UOA */

  /* Password auth? */
  if (empathy_sasl_channel_supports_mechanism (data->channel,
          "X-TELEPATHY-PASSWORD"))
    {
      if (g_hash_table_lookup (self->priv->retry_passwords, account) != NULL)
        {
          DEBUG ("We have a retry password for account %s, calling Claim",
              tp_account_get_path_suffix (account));

          tp_channel_dispatch_operation_claim_with_async (dispatch_operation,
              client, password_claim_cb, data);

          tp_observe_channels_context_accept (context);
          return;
        }

      empathy_keyring_get_account_password_async (data->account,
          get_password_cb, data);
      tp_observe_channels_context_delay (context);
      return;
    }

  /* Unknown auth */
  error = g_error_new_literal (TP_ERROR, TP_ERROR_INVALID_ARGUMENT,
      "Unknown auth mechanism");
  tp_observe_channels_context_fail (context, error);
  g_clear_error (&error);

  observe_channels_data_free (data);
}

static GObject *
empathy_auth_factory_constructor (GType type,
    guint n_params,
    GObjectConstructParam *params)
{
  GObject *retval;

  if (auth_factory_singleton != NULL)
    {
      retval = g_object_ref (auth_factory_singleton);
    }
  else
    {
      retval = G_OBJECT_CLASS (empathy_auth_factory_parent_class)->constructor
        (type, n_params, params);

      auth_factory_singleton = EMPATHY_AUTH_FACTORY (retval);
      g_object_add_weak_pointer (retval, (gpointer *) &auth_factory_singleton);
    }

  return retval;
}

static void
empathy_auth_factory_init (EmpathyAuthFactory *self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      EMPATHY_TYPE_AUTH_FACTORY, EmpathyAuthFactoryPriv);

  self->priv->sasl_handlers = g_hash_table_new_full (g_str_hash, g_str_equal,
      NULL, g_object_unref);

#ifdef HAVE_GOA
  self->priv->goa_handler = empathy_goa_auth_handler_new ();
#endif /* HAVE_GOA */

#ifdef HAVE_UOA
  self->priv->uoa_handler = empathy_uoa_auth_handler_new ();
#endif /* HAVE_UOA */

  self->priv->retry_passwords = g_hash_table_new_full (NULL, NULL,
      g_object_unref, g_free);
}

static void
empathy_auth_factory_constructed (GObject *obj)
{
  EmpathyAuthFactory *self = EMPATHY_AUTH_FACTORY (obj);
  TpBaseClient *client = TP_BASE_CLIENT (self);

  /* chain up to TpBaseClient first */
  G_OBJECT_CLASS (empathy_auth_factory_parent_class)->constructed (obj);

  tp_base_client_set_handler_bypass_approval (client, FALSE);

  /* Handle ServerTLSConnection and ServerAuthentication channels */
  tp_base_client_take_handler_filter (client, tp_asv_new (
          /* ChannelType */
          TP_PROP_CHANNEL_CHANNEL_TYPE, G_TYPE_STRING,
          TP_IFACE_CHANNEL_TYPE_SERVER_TLS_CONNECTION,
          /* AuthenticationMethod */
          TP_PROP_CHANNEL_TARGET_HANDLE_TYPE, G_TYPE_UINT,
          TP_HANDLE_TYPE_NONE, NULL));

  tp_base_client_take_handler_filter (client, tp_asv_new (
          /* ChannelType */
          TP_PROP_CHANNEL_CHANNEL_TYPE, G_TYPE_STRING,
          TP_IFACE_CHANNEL_TYPE_SERVER_AUTHENTICATION,
          /* AuthenticationMethod */
          TP_PROP_CHANNEL_TYPE_SERVER_AUTHENTICATION_AUTHENTICATION_METHOD,
          G_TYPE_STRING, TP_IFACE_CHANNEL_INTERFACE_SASL_AUTHENTICATION,
          NULL));

  /* We are also an observer so that we can see new auth channels
   * popping up and if we have the password already saved to one
   * account where an auth channel has just appeared we can call
   * Claim() on the CDO so the approver won't get it, which makes
   * sense. */

  /* Observe ServerAuthentication channels */
  tp_base_client_take_observer_filter (client, tp_asv_new (
          /* ChannelType */
          TP_PROP_CHANNEL_CHANNEL_TYPE, G_TYPE_STRING,
          TP_IFACE_CHANNEL_TYPE_SERVER_AUTHENTICATION,
          /* AuthenticationMethod */
          TP_PROP_CHANNEL_TYPE_SERVER_AUTHENTICATION_AUTHENTICATION_METHOD,
          G_TYPE_STRING, TP_IFACE_CHANNEL_INTERFACE_SASL_AUTHENTICATION,
          NULL));

  tp_base_client_set_observer_delay_approvers (client, TRUE);
}

static void
empathy_auth_factory_dispose (GObject *object)
{
  EmpathyAuthFactoryPriv *priv = GET_PRIV (object);

  if (priv->dispose_run)
    return;

  priv->dispose_run = TRUE;

  g_hash_table_unref (priv->sasl_handlers);

#ifdef HAVE_GOA
  g_object_unref (priv->goa_handler);
#endif /* HAVE_GOA */

#ifdef HAVE_UOA
  g_object_unref (priv->uoa_handler);
#endif /* HAVE_UOA */

  g_hash_table_unref (priv->retry_passwords);

  G_OBJECT_CLASS (empathy_auth_factory_parent_class)->dispose (object);
}

static void
empathy_auth_factory_class_init (EmpathyAuthFactoryClass *klass)
{
  GObjectClass *oclass = G_OBJECT_CLASS (klass);
  TpBaseClientClass *base_client_cls = TP_BASE_CLIENT_CLASS (klass);

  oclass->constructor = empathy_auth_factory_constructor;
  oclass->constructed = empathy_auth_factory_constructed;
  oclass->dispose = empathy_auth_factory_dispose;

  base_client_cls->handle_channels = handle_channels;
  base_client_cls->observe_channels = observe_channels;

  g_type_class_add_private (klass, sizeof (EmpathyAuthFactoryPriv));

  signals[NEW_SERVER_TLS_HANDLER] =
    g_signal_new ("new-server-tls-handler",
      G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 0,
      NULL, NULL,
      g_cclosure_marshal_generic,
      G_TYPE_NONE,
      1, EMPATHY_TYPE_SERVER_TLS_HANDLER);

  signals[NEW_SERVER_SASL_HANDLER] =
    g_signal_new ("new-server-sasl-handler",
      G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 0,
      NULL, NULL,
      g_cclosure_marshal_generic,
      G_TYPE_NONE,
      1, EMPATHY_TYPE_SERVER_SASL_HANDLER);

  signals[AUTH_PASSWORD_FAILED] =
    g_signal_new ("auth-password-failed",
      G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 0,
      NULL, NULL,
      g_cclosure_marshal_generic,
      G_TYPE_NONE,
      2, TP_TYPE_ACCOUNT, G_TYPE_STRING);
}

EmpathyAuthFactory *
empathy_auth_factory_new (TpSimpleClientFactory *factory)
{
  return g_object_new (EMPATHY_TYPE_AUTH_FACTORY,
      "factory", factory,
      "name", "Empathy.Auth",
      NULL);
}

gboolean
empathy_auth_factory_register (EmpathyAuthFactory *self,
    GError **error)
{
  return tp_base_client_register (TP_BASE_CLIENT (self), error);
}

void
empathy_auth_factory_save_retry_password (EmpathyAuthFactory *self,
    TpAccount *account,
    const gchar *password)
{
  g_hash_table_insert (self->priv->retry_passwords,
      g_object_ref (account), g_strdup (password));
}
