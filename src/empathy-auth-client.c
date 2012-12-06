/*
 * Copyright (C) 2012 Jolla Ltd.
 * Contact: John Brooks <john.brooks@jollamobile.com>
 *
 * Based on Empathy,
 * Copyright (C) 2010 Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301  USA
 *
 * Authors: Cosimo Cecchi <cosimo.cecchi@collabora.co.uk>
 */

#include <stdlib.h>
#include <glib.h>

#include <telepathy-glib/telepathy-glib.h>

#include "empathy-debug.h"
#include "empathy-utils.h"
#include <empathy-auth-factory.h>
#include <empathy-server-sasl-handler.h>
#include <empathy-server-tls-handler.h>

#define TIMEOUT 60

static gboolean use_timer = TRUE;
static guint timeout_id = 0;
static guint num_windows = 0;
static GMainLoop *main_loop = 0;

static gboolean
timeout_cb (gpointer p)
{
  DEBUG ("Timeout reached; exiting...");

  g_main_loop_quit(main_loop);
  return FALSE;
}

static void
start_timer (void)
{
  if (!use_timer)
    return;

  if (timeout_id != 0)
    return;

  DEBUG ("Start timer");

  timeout_id = g_timeout_add_seconds (TIMEOUT, timeout_cb, NULL);
}

static void
stop_timer (void)
{
  if (timeout_id == 0)
    return;

  DEBUG ("Stop timer");

  g_source_remove (timeout_id);
  timeout_id = 0;
}

#if 0
static void
tls_dialog_response_cb (GtkDialog *dialog,
    gint response_id,
    gpointer user_data)
{
  TpTLSCertificate *certificate = NULL;
  TpTLSCertificateRejectReason reason = 0;
  GHashTable *details = NULL;
  gboolean remember = FALSE;
  EmpathyTLSVerifier *verifier = EMPATHY_TLS_VERIFIER (user_data);

  g_object_get (tls_dialog,
      "certificate", &certificate,
      "reason", &reason,
      "remember", &remember,
      "details", &details,
      NULL);

  DEBUG ("Response %d (remember: %d)", response_id, remember);

  gtk_widget_destroy (GTK_WIDGET (dialog));

  if (response_id == GTK_RESPONSE_YES)
    {
      tp_tls_certificate_accept_async (certificate, NULL, NULL);
    }
  else
    {
      tp_asv_set_boolean (details, "user-requested", TRUE);
      tp_tls_certificate_add_rejection (certificate, reason, NULL,
          g_variant_new_parsed ("{ 'user-requested': <%b> }", TRUE));

      tp_tls_certificate_reject_async (certificate, NULL, NULL);
    }

  if (remember)
    empathy_tls_verifier_store_exception (verifier);

  g_object_unref (certificate);
  g_hash_table_unref (details);

  /* restart the timeout */
  num_windows--;

  if (num_windows > 0)
    return;

  start_timer ();
}
#endif

#if 0
static void
verifier_verify_cb (GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  TpTLSCertificateRejectReason reason;
  GError *error = NULL;
  TpTLSCertificate *certificate = NULL;
  GHashTable *details = NULL;
  gchar *hostname = NULL;

  g_object_get (source,
      "certificate", &certificate,
      NULL);

  empathy_tls_verifier_verify_finish (EMPATHY_TLS_VERIFIER (source),
      result, &reason, &details, &error);

  if (error != NULL)
    {
      DEBUG ("Error: %s", error->message);

      g_error_free (error);
    }
  else
    {
      tp_tls_certificate_accept_async (certificate, NULL, NULL);
    }

  g_free (hostname);
  g_object_unref (certificate);
}
#endif

#if 0
static void
auth_factory_new_tls_handler_cb (EmpathyAuthFactory *factory,
    EmpathyServerTLSHandler *handler,
    gpointer user_data)
{
  TpTLSCertificate *certificate = NULL;
  gchar *hostname = NULL;
  gchar **reference_identities = NULL;
  EmpathyTLSVerifier *verifier;

  DEBUG ("New TLS server handler received from the factory");

  g_object_get (handler,
      "certificate", &certificate,
      "hostname", &hostname,
      "reference-identities", &reference_identities,
      NULL);

  verifier = empathy_tls_verifier_new (certificate, hostname,
      (const gchar **) reference_identities);
  empathy_tls_verifier_verify_async (verifier,
      verifier_verify_cb, NULL);

  g_object_unref (verifier);
  g_object_unref (certificate);
  g_free (hostname);
  g_strfreev (reference_identities);
}
#endif

static void
auth_factory_new_sasl_handler_cb (EmpathyAuthFactory *factory,
    EmpathyServerSASLHandler *handler,
    gpointer user_data)
{
  DEBUG ("New SASL server handler received from the factory");

  /* If the handler has the password it will deal with it itself. */
  if (!empathy_server_sasl_handler_has_password (handler))
    {
      DEBUG ("SASL handler doesn't have a password, prompt for one");
    }
}

#if 0
static void
retry_account_cb (GtkWidget *dialog,
    TpAccount *account,
    const gchar *password,
    EmpathyAuthFactory *factory)
{
  DEBUG ("Try reconnecting to %s", tp_account_get_path_suffix (account));

  empathy_auth_factory_save_retry_password (factory, account, password);

  tp_account_reconnect_async (account, NULL, NULL);
}
#endif

static void
auth_factory_auth_passsword_failed (EmpathyAuthFactory *factory,
    TpAccount *account,
    const gchar *password,
    gpointer user_data)
{
  DEBUG ("Authentication on %s failed, popup password dialog",
      tp_account_get_path_suffix (account));
}

static void
sanity_cb (GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  start_timer ();
}

int
main (int argc,
    char **argv)
{
  GOptionContext *context;
  GError *error = NULL;
  EmpathyAuthFactory *factory;
  TpDebugSender *debug_sender;
  TpSimpleClientFactory *tp_factory;
  TpDBusDaemon *dbus;

  //gnutls_global_init ();
  g_type_init();
  main_loop = g_main_loop_new(NULL, FALSE);

#ifdef ENABLE_DEBUG
  /* Set up debug sender */
  debug_sender = tp_debug_sender_dup ();
  g_log_set_default_handler (tp_debug_sender_log_handler, G_LOG_DOMAIN);
#endif

  dbus = tp_dbus_daemon_dup (NULL);
  tp_factory = tp_simple_client_factory_new (dbus);
  tp_simple_client_factory_add_account_features_varargs (tp_factory,
      TP_ACCOUNT_FEATURE_STORAGE,
      0);

  factory = empathy_auth_factory_new (tp_factory);
  g_object_unref (tp_factory);
  g_object_unref (dbus);

  //g_signal_connect (factory, "new-server-tls-handler",
  //    G_CALLBACK (auth_factory_new_tls_handler_cb), NULL);

  g_signal_connect (factory, "new-server-sasl-handler",
      G_CALLBACK (auth_factory_new_sasl_handler_cb), NULL);

  g_signal_connect (factory, "auth-password-failed",
      G_CALLBACK (auth_factory_auth_passsword_failed), NULL);

  if (!empathy_auth_factory_register (factory, &error))
    {
      g_critical ("Failed to register the auth factory: %s\n", error->message);
      g_error_free (error);
      g_object_unref (factory);

      return EXIT_FAILURE;
    }

  DEBUG ("SASL signon auth client started.");

  if (g_getenv ("SASL_SIGNON_PERSIST") != NULL)
    {
      DEBUG ("Timed-exit disabled");

      use_timer = FALSE;
    }

  g_main_loop_run(main_loop);

  g_object_unref (factory);
  g_object_unref (debug_sender);

  return EXIT_SUCCESS;
}
