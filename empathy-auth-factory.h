/*
 * empathy-auth-factory.h - Header for EmpathyAuthFactory
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

#ifndef __EMPATHY_AUTH_FACTORY_H__
#define __EMPATHY_AUTH_FACTORY_H__

#include <glib-object.h>

#include <telepathy-glib/telepathy-glib.h>

G_BEGIN_DECLS

typedef struct _EmpathyAuthFactory EmpathyAuthFactory;
typedef struct _EmpathyAuthFactoryClass EmpathyAuthFactoryClass;
typedef struct _EmpathyAuthFactoryPriv EmpathyAuthFactoryPriv;

struct _EmpathyAuthFactoryClass {
    TpBaseClientClass parent_class;
};

struct _EmpathyAuthFactory {
    TpBaseClient parent;
    EmpathyAuthFactoryPriv *priv;
};

GType empathy_auth_factory_get_type (void);

/* TYPE MACROS */
#define EMPATHY_TYPE_AUTH_FACTORY \
  (empathy_auth_factory_get_type ())
#define EMPATHY_AUTH_FACTORY(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), EMPATHY_TYPE_AUTH_FACTORY, \
    EmpathyAuthFactory))
#define EMPATHY_AUTH_FACTORY_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass), EMPATHY_TYPE_AUTH_FACTORY, \
    EmpathyAuthFactoryClass))
#define EMPATHY_IS_AUTH_FACTORY(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj), EMPATHY_TYPE_AUTH_FACTORY))
#define EMPATHY_IS_AUTH_FACTORY_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass), EMPATHY_TYPE_AUTH_FACTORY))
#define EMPATHY_AUTH_FACTORY_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), EMPATHY_TYPE_AUTH_FACTORY, \
    EmpathyAuthFactoryClass))

EmpathyAuthFactory * empathy_auth_factory_new (TpSimpleClientFactory *factory);

gboolean empathy_auth_factory_register (EmpathyAuthFactory *self,
    GError **error);

void empathy_auth_factory_save_retry_password (EmpathyAuthFactory *self,
    TpAccount *account,
    const gchar *password);

G_END_DECLS

#endif /* #ifndef __EMPATHY_AUTH_FACTORY_H__*/
