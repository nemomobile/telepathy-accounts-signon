/*
 * empathy-sasl-mechanisms.h - Header for SASL authentication mechanisms
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

#include <string.h>

#include "empathy-debug.h"
#include "empathy-utils.h"
#include "empathy-sasl-mechanisms.h"

#define MECH_FACEBOOK "X-FACEBOOK-PLATFORM"
#define MECH_WLM "X-MESSENGER-OAUTH2"
#define MECH_GOOGLE "X-OAUTH2"
#define MECH_PASSWORD "X-TELEPATHY-PASSWORD"

static void
generic_cb (TpChannel *proxy,
    const GError *error,
    gpointer user_data,
    GObject *weak_object)
{
  GSimpleAsyncResult *result = user_data;

  if (error != NULL)
    {
      g_simple_async_result_set_from_error (result, error);
      g_simple_async_result_complete (result);
    }
}

static void
sasl_status_changed_cb (TpChannel *channel,
    guint status,
    const gchar *dbus_error,
    GHashTable *details,
    gpointer user_data,
    GObject *self)
{
  GSimpleAsyncResult *result = user_data;

  switch (status)
    {
      case TP_SASL_STATUS_SERVER_SUCCEEDED:
        tp_cli_channel_interface_sasl_authentication_call_accept_sasl (channel,
            -1, generic_cb, g_object_ref (result), g_object_unref, NULL);
        break;

      case TP_SASL_STATUS_SERVER_FAILED:
      case TP_SASL_STATUS_CLIENT_FAILED:
        {
          GError *error = NULL;

          tp_proxy_dbus_error_to_gerror (channel, dbus_error,
              tp_asv_get_string (details, "debug-message"), &error);

          DEBUG ("SASL failed: %s", error->message);

          g_simple_async_result_take_error (result, error);
          g_simple_async_result_complete (result);
        }
        break;

      case TP_SASL_STATUS_SUCCEEDED:
        DEBUG ("SASL succeeded");

        g_simple_async_result_complete (result);
        break;

      default:
        break;
    }
}

static GSimpleAsyncResult *
empathy_sasl_auth_common_async (TpChannel *channel,
    GAsyncReadyCallback callback,
    gpointer user_data)
{
  GSimpleAsyncResult *result;
  GError *error = NULL;

  g_return_val_if_fail (TP_IS_CHANNEL (channel), NULL);
  g_return_val_if_fail (tp_proxy_has_interface_by_id (channel,
      TP_IFACE_QUARK_CHANNEL_INTERFACE_SASL_AUTHENTICATION), NULL);

  result = g_simple_async_result_new ((GObject *) channel,
      callback, user_data, empathy_sasl_auth_common_async);

  tp_cli_channel_interface_sasl_authentication_connect_to_sasl_status_changed (
      channel, sasl_status_changed_cb,
      g_object_ref (result), g_object_unref, NULL, &error);
  g_assert_no_error (error);

  return result;
}

typedef struct
{
  TpChannel *channel;
  gchar *client_id;
  gchar *access_token;
} FacebookData;

static void
facebook_data_free (FacebookData *data)
{
  g_object_unref (data->channel);
  g_free (data->client_id);
  g_free (data->access_token);
  g_slice_free (FacebookData, data);
}

static void
facebook_new_challenge_cb (TpChannel *channel,
    const GArray *challenge,
    gpointer user_data,
    GObject *weak_object)
{
  GSimpleAsyncResult *result = user_data;
  FacebookData *data;
  gchar *response;
  GArray *response_array;
  gchar **challenge_data;
  GString *response_string;
  gchar **d;

  DEBUG ("new challenge: %s", challenge->data);

  data = g_simple_async_result_get_op_res_gpointer (result);

  /* See https://developers.facebook.com/docs/chat/#platauth */
  response_string = g_string_new ("v=1.0&call_id=0");
  g_string_append_printf (response_string, "&access_token=%s&api_key=%s", data->access_token, data->client_id);

  challenge_data = g_strsplit (challenge->data, "&", 0);
  for (d = challenge_data; *d; d++) {
      if (strncmp (*d, "method=", 7) == 0 || strncmp (*d, "nonce=", 6) == 0) {
          g_string_append_c (response_string, '&');
          g_string_append (response_string, *d);
      }
  }

  DEBUG ("Response: %s", response_string->str);

  response_array = g_array_new (FALSE, FALSE, sizeof (gchar));
  g_array_append_vals (response_array, response_string->str, response_string->len);

  tp_cli_channel_interface_sasl_authentication_call_respond (data->channel, -1,
      response_array, generic_cb, g_object_ref (result), g_object_unref, NULL);

  g_string_free (response_string, TRUE);
  g_strfreev (challenge_data);
  g_array_unref (response_array);
}

void
empathy_sasl_auth_facebook_async (TpChannel *channel,
    const gchar *client_id,
    const gchar *access_token,
    GAsyncReadyCallback callback,
    gpointer user_data)
{
  GSimpleAsyncResult *result;
  FacebookData *data;
  GError *error = NULL;

  result = empathy_sasl_auth_common_async (channel, callback, user_data);

  g_return_if_fail (result != NULL);
  g_return_if_fail (empathy_sasl_channel_supports_mechanism (channel,
      MECH_FACEBOOK));
  g_return_if_fail (!tp_str_empty (client_id));
  g_return_if_fail (!tp_str_empty (access_token));

  DEBUG ("Start %s mechanism", MECH_FACEBOOK);

  data = g_slice_new0 (FacebookData);
  data->channel = g_object_ref (channel);
  data->client_id = g_strdup (client_id);
  data->access_token = g_strdup (access_token);

  g_simple_async_result_set_op_res_gpointer (result, data,
      (GDestroyNotify) facebook_data_free);

  tp_cli_channel_interface_sasl_authentication_connect_to_new_challenge (
      channel, facebook_new_challenge_cb,
      g_object_ref (result), g_object_unref,
      NULL, &error);
  g_assert_no_error (error);

  tp_cli_channel_interface_sasl_authentication_call_start_mechanism (
      channel, -1, MECH_FACEBOOK, generic_cb,
      g_object_ref (result), g_object_unref, NULL);

  g_object_unref (result);
}

void
empathy_sasl_auth_wlm_async (TpChannel *channel,
    const gchar *access_token,
    GAsyncReadyCallback callback,
    gpointer user_data)
{
  GSimpleAsyncResult *result;
  guchar *token_decoded;
  gsize token_decoded_len;
  GArray *token_decoded_array;

  result = empathy_sasl_auth_common_async (channel, callback, user_data);

  g_return_if_fail (result != NULL);
  g_return_if_fail (empathy_sasl_channel_supports_mechanism (channel,
      MECH_WLM));
  g_return_if_fail (!tp_str_empty (access_token));

  DEBUG ("Start %s mechanism", MECH_WLM);

  /* Wocky will base64 encode, but token actually already is base64, so we
   * decode now and it will be re-encoded. */
  token_decoded = g_base64_decode (access_token, &token_decoded_len);
  token_decoded_array = g_array_new (FALSE, FALSE, sizeof (guchar));
  g_array_append_vals (token_decoded_array, token_decoded, token_decoded_len);

  tp_cli_channel_interface_sasl_authentication_call_start_mechanism_with_data (
      channel, -1, MECH_WLM, token_decoded_array,
      generic_cb, g_object_ref (result), g_object_unref, NULL);

  g_array_unref (token_decoded_array);
  g_free (token_decoded);
  g_object_unref (result);
}

void
empathy_sasl_auth_google_async (TpChannel *channel,
    const gchar *username,
    const gchar *access_token,
    GAsyncReadyCallback callback,
    gpointer user_data)
{
  GSimpleAsyncResult *result;
  GArray *credential;

  result = empathy_sasl_auth_common_async (channel, callback, user_data);

  g_return_if_fail (result != NULL);
  g_return_if_fail (empathy_sasl_channel_supports_mechanism (channel,
      MECH_GOOGLE));
  g_return_if_fail (!tp_str_empty (username));
  g_return_if_fail (!tp_str_empty (access_token));

  DEBUG ("Start %s mechanism", MECH_GOOGLE);

  credential = g_array_sized_new (FALSE, FALSE, sizeof (gchar),
      strlen (access_token) + strlen (username) + 2);

  g_array_append_val (credential, "\0");
  g_array_append_vals (credential, username, strlen (username));
  g_array_append_val (credential, "\0");
  g_array_append_vals (credential, access_token, strlen (access_token));

  tp_cli_channel_interface_sasl_authentication_call_start_mechanism_with_data (
      channel, -1, MECH_GOOGLE, credential,
      generic_cb, g_object_ref (result), g_object_unref, NULL);

  g_array_unref (credential);
  g_object_unref (result);
}

void
empathy_sasl_auth_password_async (TpChannel *channel,
    const gchar *password,
    GAsyncReadyCallback callback,
    gpointer user_data)
{
  GSimpleAsyncResult *result;
  GArray *password_array;

  result = empathy_sasl_auth_common_async (channel, callback, user_data);

  g_return_if_fail (result != NULL);
  g_return_if_fail (empathy_sasl_channel_supports_mechanism (channel,
      MECH_PASSWORD));
  g_return_if_fail (!tp_str_empty (password));

  DEBUG ("Start %s mechanism", MECH_PASSWORD);

  password_array = g_array_sized_new (FALSE, FALSE, sizeof (gchar),
      strlen (password));
  g_array_append_vals (password_array, password, strlen (password));

  tp_cli_channel_interface_sasl_authentication_call_start_mechanism_with_data (
      channel, -1, MECH_PASSWORD, password_array,
      generic_cb, g_object_ref (result), g_object_unref, NULL);

  g_array_unref (password_array);
  g_object_unref (result);
}

gboolean
empathy_sasl_auth_finish (TpChannel *channel,
    GAsyncResult *result,
    GError **error)
{
  empathy_implement_finish_void (channel, empathy_sasl_auth_common_async);
}

gboolean
empathy_sasl_channel_supports_mechanism (TpChannel *channel,
    const gchar *mechanism)
{
  GVariant *props;
  GStrv available_mechanisms;
  gboolean result;

  props = tp_channel_dup_immutable_properties (channel);

  g_variant_lookup (props,
      TP_PROP_CHANNEL_INTERFACE_SASL_AUTHENTICATION_AVAILABLE_MECHANISMS,
      "^as", &available_mechanisms);

  result = tp_strv_contains ((const gchar * const *) available_mechanisms,
      mechanism);

  g_variant_unref (props);
  g_strfreev (available_mechanisms);
  return result;
}

EmpathySaslMechanism
empathy_sasl_channel_select_mechanism (TpChannel *channel,
    const gchar *credential_type)
{
  guint i;

  if (g_strcmp0 (credential_type, "password") == 0) {
    if (empathy_sasl_channel_supports_mechanism (channel,
          MECH_PASSWORD))
      return EMPATHY_SASL_MECHANISM_PASSWORD;
  } else if (g_strcmp0 (credential_type, "oauth2") == 0) {
    if (empathy_sasl_channel_supports_mechanism (channel,
          MECH_FACEBOOK))
      return EMPATHY_SASL_MECHANISM_FACEBOOK;
    else if (empathy_sasl_channel_supports_mechanism (channel,
          MECH_WLM))
      return EMPATHY_SASL_MECHANISM_WLM;
    else if (empathy_sasl_channel_supports_mechanism (channel,
          MECH_GOOGLE))
      return EMPATHY_SASL_MECHANISM_GOOGLE;
  }

  return EMPATHY_SASL_MECHANISM_UNSUPPORTED;
}
