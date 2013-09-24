/*
 * empathy-auth-uoa.c - Source for Uoa SASL authentication
 * Copyright (C) 2012 Collabora Ltd.
 * @author Xavier Claessens <xavier.claessens@collabora.co.uk>
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

#include <libaccounts-glib/ag-account.h>
#include <libaccounts-glib/ag-account-service.h>
#include <libaccounts-glib/ag-auth-data.h>
#include <libaccounts-glib/ag-manager.h>
#include <libaccounts-glib/ag-service.h>

#include <libsignon-glib/signon-identity.h>
#include <libsignon-glib/signon-auth-session.h>
#include <libsignon-glib/signon-errors.h>

#include <sailfishkeyprovider.h>

#define DEBUG_FLAG EMPATHY_DEBUG_SASL
#include "empathy-debug.h"
#include "empathy-keyring.h"
#include "empathy-utils.h"
#include "empathy-uoa-auth-handler.h"
#include "empathy-uoa-utils.h"
#include "empathy-sasl-mechanisms.h"

struct _EmpathyUoaAuthHandlerPriv
{
  AgManager *manager;
};

G_DEFINE_TYPE (EmpathyUoaAuthHandler, empathy_uoa_auth_handler, G_TYPE_OBJECT);

static void
empathy_uoa_auth_handler_init (EmpathyUoaAuthHandler *self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      EMPATHY_TYPE_UOA_AUTH_HANDLER, EmpathyUoaAuthHandlerPriv);

  self->priv->manager = empathy_uoa_manager_dup ();
}

static void
empathy_uoa_auth_handler_dispose (GObject *object)
{
  EmpathyUoaAuthHandler *self = (EmpathyUoaAuthHandler *) object;

  tp_clear_object (&self->priv->manager);

  G_OBJECT_CLASS (empathy_uoa_auth_handler_parent_class)->dispose (object);
}

static void
empathy_uoa_auth_handler_class_init (EmpathyUoaAuthHandlerClass *klass)
{
  GObjectClass *oclass = G_OBJECT_CLASS (klass);

  oclass->dispose = empathy_uoa_auth_handler_dispose;

  g_type_class_add_private (klass, sizeof (EmpathyUoaAuthHandlerPriv));
}

EmpathyUoaAuthHandler *
empathy_uoa_auth_handler_new (void)
{
  return g_object_new (EMPATHY_TYPE_UOA_AUTH_HANDLER, NULL);
}

typedef struct
{
  TpChannel *channel;
  AgAccountService *service;
  AgAuthData *auth_data;
  SignonIdentity *identity;
  SignonAuthSession *session;

  gchar *username;
  gchar *client_id;
} AuthContext;

static AuthContext *
auth_context_new (TpChannel *channel,
    AgAccountService *service)
{
  AuthContext *ctx;
  guint cred_id;

  ctx = g_slice_new0 (AuthContext);
  ctx->channel = g_object_ref (channel);
  ctx->service = g_object_ref (service);

  ctx->auth_data = ag_account_service_get_auth_data (service);
  if (ctx->auth_data == NULL)
    goto out;

  cred_id = ag_auth_data_get_credentials_id (ctx->auth_data);
  if (cred_id == 0)
    goto out;

  ctx->identity = signon_identity_new_from_db (cred_id);
  if (ctx->identity == NULL)
    goto out;

  ctx->session = signon_identity_create_session (ctx->identity,
      ag_auth_data_get_method (ctx->auth_data), NULL);
  if (ctx->session == NULL)
    goto out;

  ctx->username = 0;
  ctx->client_id = 0;

out:
  return ctx;
}

static void
auth_context_free (AuthContext *ctx)
{
  g_clear_object (&ctx->channel);
  g_clear_object (&ctx->service);
  tp_clear_pointer (&ctx->auth_data, ag_auth_data_unref);
  g_clear_object (&ctx->session);
  g_clear_object (&ctx->identity);
  g_free (ctx->username);
  g_free (ctx->client_id);

  g_slice_free (AuthContext, ctx);
}

static void
auth_context_done (AuthContext *ctx)
{
  tp_channel_close_async (ctx->channel, NULL, NULL);
  auth_context_free (ctx);
}

static void
request_password_account_store_cb (AgAccount *account,
    const GError *error,
    gpointer user_data)
{
  AuthContext *ctx = user_data;

  if (error != NULL)
    {
      DEBUG ("Error setting CredentialsNeedUpdate on account: %s",
             error->message);
    }

  ag_account_select_service (account, ag_account_service_get_service (ctx->service));
  auth_context_done(ctx);
}

static void
request_password (AuthContext *ctx)
{
  DEBUG ("Invalid credentials, request user action");

  AgAccount *account = ag_account_service_get_account (ctx->service);

  GValue value = G_VALUE_INIT;
  g_value_init (&value, G_TYPE_BOOLEAN);
  g_value_set_boolean (&value, TRUE);

  ag_account_select_service (account, NULL);
  ag_account_set_value (account, "CredentialsNeedUpdate", &value);

  ag_account_store (account, request_password_account_store_cb, ctx);
}

static void
auth_cb (GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  TpChannel *channel = (TpChannel *) source;
  AuthContext *ctx = user_data;
  GError *error = NULL;

  if (!empathy_sasl_auth_finish (channel, result, &error))
    {
      DEBUG ("SASL Mechanism error: %s", error->message);
      g_clear_error (&error);

      request_password (ctx);
    }
  else
    {
      DEBUG ("Auth on %s suceeded", tp_proxy_get_object_path (channel));
      auth_context_done (ctx);
    }
}

static void
session_process_cb (SignonAuthSession *session,
    GHashTable *session_data,
    const GError *error,
    gpointer user_data)
{
  AuthContext *ctx = user_data;
  const gchar *access_token;
  const gchar *client_id;
  const gchar *auth_method;

  if (error != NULL)
    {
      DEBUG ("Error processing the session: %s", error->message);
      if (g_error_matches(error, SIGNON_ERROR, SIGNON_ERROR_CREDENTIALS_NOT_AVAILABLE) ||
          g_error_matches(error, SIGNON_ERROR, SIGNON_ERROR_INVALID_CREDENTIALS) ||
          g_error_matches(error, SIGNON_ERROR, SIGNON_ERROR_MISSING_DATA) ||
          g_error_matches(error, SIGNON_ERROR, SIGNON_ERROR_USER_INTERACTION) ||
          g_error_matches(error, SIGNON_ERROR, SIGNON_ERROR_OPERATION_FAILED))
        {
          request_password(ctx);
        } 
      else
        {
          auth_context_done (ctx);
        }
      return;
    }

  access_token = tp_asv_get_string (session_data, "AccessToken");
  auth_method = signon_auth_session_get_method (session);

  switch (empathy_sasl_channel_select_mechanism (ctx->channel, auth_method))
    {
      case EMPATHY_SASL_MECHANISM_FACEBOOK:
        empathy_sasl_auth_facebook_async (ctx->channel,
            ctx->client_id, access_token,
            auth_cb, ctx);
        break;

      case EMPATHY_SASL_MECHANISM_WLM:
        empathy_sasl_auth_wlm_async (ctx->channel,
            access_token,
            auth_cb, ctx);
        break;

      case EMPATHY_SASL_MECHANISM_GOOGLE:
        empathy_sasl_auth_google_async (ctx->channel,
            ctx->username, access_token,
            auth_cb, ctx);
        break;

      case EMPATHY_SASL_MECHANISM_PASSWORD:
        empathy_sasl_auth_password_async (ctx->channel,
            tp_asv_get_string (session_data, "Secret"),
            auth_cb, ctx);
        break;

      default:
        g_assert_not_reached ();
    }
}

static void
identity_query_info_cb (SignonIdentity *identity,
    const SignonIdentityInfo *info,
    const GError *error,
    gpointer user_data)
{
  AuthContext *ctx = user_data;

  if (error != NULL)
    {
      DEBUG ("Error querying info from identity: %s", error->message);
      auth_context_done (ctx);
      return;
    }

  ctx->username = g_strdup (signon_identity_info_get_username (info));
  if (!ctx->username || !*ctx->username)
    {
      GVariant *v;
      AgAccount *account = ag_account_service_get_account (ctx->service);
      AgService *old_service = ag_account_get_selected_service (account);
      ag_account_select_service (account, NULL);

      g_free (ctx->username);
      v = ag_account_get_variant (account, "default_credentials_username", NULL);
      if (v)
        ctx->username = g_variant_dup_string (v, NULL);
      else
        ctx->username = NULL;

      ag_account_select_service (account, old_service);

      DEBUG ("No username in signon data, falling back to default_credentials_username '%s'", ctx->username);
    }

  GHashTable *params = ag_auth_data_get_parameters (ctx->auth_data);
  AgService *service = ag_account_service_get_service (ctx->service);

  SailfishKeyProvider_storedKey (ag_service_get_provider (service),
      ag_service_get_name (service), "client_id", &ctx->client_id);
  if (ctx->client_id)
      tp_asv_set_string (params, "ClientId", ctx->client_id);

  tp_asv_set_int32 (params, SIGNON_SESSION_DATA_UI_POLICY, SIGNON_POLICY_NO_USER_INTERACTION);

  signon_auth_session_process (ctx->session,
      params,
      ag_auth_data_get_mechanism (ctx->auth_data),
      session_process_cb,
      ctx);
}

static void
set_account_password_cb (GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  TpAccount *tp_account = (TpAccount *) source;
  AuthContext *ctx = user_data;
  AuthContext *new_ctx;
  GError *error = NULL;

  if (!empathy_keyring_set_account_password_finish (tp_account, result, &error))
    {
      DEBUG ("Failed to set empty password on UOA account: %s", error->message);
      auth_context_done (ctx);
      return;
    }

  new_ctx = auth_context_new (ctx->channel, ctx->service);
  auth_context_free (ctx);

  if (new_ctx->session != NULL)
    {
      /* The trick worked! */
      request_password (new_ctx);
      return;
    }

  DEBUG ("Still can't get a signon session, even after setting empty pwd");
  auth_context_done (new_ctx);
}

void
empathy_uoa_auth_handler_start (EmpathyUoaAuthHandler *self,
    TpChannel *channel,
    TpAccount *tp_account)
{
  const GValue *id_value;
  AgAccountId id;
  AgAccount *account;
  GList *l = NULL;
  AgAccountService *service;
  AuthContext *ctx;

  g_return_if_fail (TP_IS_CHANNEL (channel));
  g_return_if_fail (TP_IS_ACCOUNT (tp_account));
  g_return_if_fail (empathy_uoa_auth_handler_supports (self, channel,
      tp_account));

  DEBUG ("Start UOA auth for account: %s",
      tp_proxy_get_object_path (tp_account));

  id_value = tp_account_get_storage_identifier (tp_account);
  id = g_value_get_uint (id_value);

  account = ag_manager_get_account (self->priv->manager, id);
  if (account != NULL)
    l = ag_account_list_services_by_type (account, EMPATHY_UOA_SERVICE_TYPE);
  if (l == NULL)
    {
      DEBUG ("Couldn't find IM service for AgAccountId %u", id);
      g_object_unref (account);
      tp_channel_close_async (channel, NULL, NULL);
      return;
    }

  /* Assume there is only one IM service */
  service = ag_account_service_new (account, l->data);
  ag_service_list_free (l);
  g_object_unref (account);

  ctx = auth_context_new (channel, service);
  if (ctx->session == NULL)
    {
      /* This (usually?) means we never stored credentials for this account.
       * To ask user to type his password SSO needs a SignonIdentity bound to
       * our account. Let's store an empty password. */
      DEBUG ("Couldn't create a signon session");
      empathy_keyring_set_account_password_async (tp_account, "", FALSE,
          set_account_password_cb, ctx);
    }
  else
    {
      /* All is fine! Query UOA for more info */
      signon_identity_query_info (ctx->identity,
          identity_query_info_cb, ctx);
    }

  g_object_unref (service);
}

gboolean
empathy_uoa_auth_handler_supports (EmpathyUoaAuthHandler *self,
    TpChannel *channel,
    TpAccount *account)
{
  const gchar *provider;
  EmpathySaslMechanism mech;

  g_return_val_if_fail (TP_IS_CHANNEL (channel), FALSE);
  g_return_val_if_fail (TP_IS_ACCOUNT (account), FALSE);

  provider = tp_account_get_storage_provider (account);

  if (tp_strdiff (provider, EMPATHY_UOA_PROVIDER))
    return FALSE;

  return TRUE;
}
