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

#ifndef __EMPATHY_SASL_MECHANISMS_H__
#define __EMPATHY_SASL_MECHANISMS_H__

#include <telepathy-glib/telepathy-glib.h>

G_BEGIN_DECLS

typedef enum
{
  EMPATHY_SASL_MECHANISM_UNSUPPORTED,
  EMPATHY_SASL_MECHANISM_FACEBOOK,
  EMPATHY_SASL_MECHANISM_WLM,
  EMPATHY_SASL_MECHANISM_GOOGLE,
  EMPATHY_SASL_MECHANISM_PASSWORD,
} EmpathySaslMechanism;

void empathy_sasl_auth_facebook_async (TpChannel *channel,
    const gchar *client_id,
    const gchar *access_token,
    GAsyncReadyCallback callback,
    gpointer user_data);

void empathy_sasl_auth_wlm_async (TpChannel *channel,
    const gchar *access_token,
    GAsyncReadyCallback callback,
    gpointer user_data);

void empathy_sasl_auth_google_async (TpChannel *channel,
    const gchar *username,
    const gchar *access_token,
    GAsyncReadyCallback callback,
    gpointer user_data);

void empathy_sasl_auth_password_async (TpChannel *channel,
    const gchar *password,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean empathy_sasl_auth_finish (TpChannel *channel,
    GAsyncResult *result,
    GError **error);

gboolean empathy_sasl_channel_supports_mechanism (TpChannel *channel,
    const gchar *mechanism);

EmpathySaslMechanism empathy_sasl_channel_select_mechanism (TpChannel *channel);

G_END_DECLS

#endif /* #ifndef __EMPATHY_SASL_MECHANISMS_H__*/
