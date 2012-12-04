/*
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

#ifndef __EMPATHY_KEYRING_H__
#define __EMPATHY_KEYRING_H__

#include <gio/gio.h>

#include <telepathy-glib/telepathy-glib.h>

G_BEGIN_DECLS

gboolean empathy_keyring_is_available (void);

void empathy_keyring_get_account_password_async (TpAccount *account,
    GAsyncReadyCallback callback, gpointer user_data);

const gchar * empathy_keyring_get_account_password_finish (TpAccount *account,
    GAsyncResult *result, GError **error);

void empathy_keyring_get_room_password_async (TpAccount *account,
    const gchar *id,
    GAsyncReadyCallback callback, gpointer user_data);

const gchar * empathy_keyring_get_room_password_finish (TpAccount *account,
    GAsyncResult *result, GError **error);

void empathy_keyring_set_account_password_async (TpAccount *account,
    const gchar *password, gboolean remember, GAsyncReadyCallback callback,
    gpointer user_data);

gboolean empathy_keyring_set_account_password_finish (TpAccount *account,
    GAsyncResult *result, GError **error);

void empathy_keyring_set_room_password_async (TpAccount *account,
    const gchar *id, const gchar *password, GAsyncReadyCallback callback,
    gpointer user_data);

gboolean empathy_keyring_set_room_password_finish (TpAccount *account,
    GAsyncResult *result, GError **error);

void empathy_keyring_delete_account_password_async (TpAccount *account,
    GAsyncReadyCallback callback, gpointer user_data);

gboolean empathy_keyring_delete_account_password_finish (TpAccount *account,
    GAsyncResult *result, GError **error);

G_END_DECLS

#endif /* __EMPATHY_KEYRING_H__ */

