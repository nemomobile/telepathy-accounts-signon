/*
 * empathy-auth-uoa.h - Header for Uoa SASL authentication
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

#ifndef __EMPATHY_UOA_AUTH_HANDLER_H__
#define __EMPATHY_UOA_AUTH_HANDLER_H__

#include <telepathy-glib/telepathy-glib.h>

G_BEGIN_DECLS

typedef struct _EmpathyUoaAuthHandler EmpathyUoaAuthHandler;
typedef struct _EmpathyUoaAuthHandlerClass EmpathyUoaAuthHandlerClass;
typedef struct _EmpathyUoaAuthHandlerPriv EmpathyUoaAuthHandlerPriv;

struct _EmpathyUoaAuthHandlerClass {
    GObjectClass parent_class;
};

struct _EmpathyUoaAuthHandler {
    GObject parent;
    EmpathyUoaAuthHandlerPriv *priv;
};

GType empathy_uoa_auth_handler_get_type (void);

/* TYPE MACROS */
#define EMPATHY_TYPE_UOA_AUTH_HANDLER \
  (empathy_uoa_auth_handler_get_type ())
#define EMPATHY_UOA_AUTH_HANDLER(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), EMPATHY_TYPE_UOA_AUTH_HANDLER, \
    EmpathyUoaAuthHandler))
#define EMPATHY_UOA_AUTH_HANDLER_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass), EMPATHY_TYPE_UOA_AUTH_HANDLER, \
    EmpathyUoaAuthHandlerClass))
#define EMPATHY_IS_UOA_AUTH_HANDLER(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj), EMPATHY_TYPE_UOA_AUTH_HANDLER))
#define EMPATHY_IS_UOA_AUTH_HANDLER_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass), EMPATHY_TYPE_UOA_AUTH_HANDLER))
#define EMPATHY_UOA_AUTH_HANDLER_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), EMPATHY_TYPE_UOA_AUTH_HANDLER, \
    EmpathyUoaAuthHandlerClass))

EmpathyUoaAuthHandler *empathy_uoa_auth_handler_new (void);

void empathy_uoa_auth_handler_start (EmpathyUoaAuthHandler *self,
    TpChannel *channel,
    TpAccount *account);

gboolean empathy_uoa_auth_handler_supports (EmpathyUoaAuthHandler *self,
    TpChannel *channel,
    TpAccount *account);

G_END_DECLS

#endif /* #ifndef __EMPATHY_UOA_AUTH_HANDLER_H__*/
