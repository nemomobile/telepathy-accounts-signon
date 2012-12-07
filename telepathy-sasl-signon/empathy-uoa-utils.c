/*
 * empathy-uoa-utils.c - Source for UOA utilities
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

#include "empathy-debug.h"
#include "empathy-uoa-utils.h"

static AgManager *singleton = NULL;

void
empathy_uoa_manager_set_default (AgManager *manager)
{
  if (singleton != NULL)
    return;

  singleton = manager;
  g_object_add_weak_pointer ((GObject *) singleton, (gpointer) &singleton);
}

AgManager *
empathy_uoa_manager_dup (void)
{
  if (singleton != NULL)
    return g_object_ref (singleton);

  singleton = ag_manager_new_for_service_type (EMPATHY_UOA_SERVICE_TYPE);
  g_object_add_weak_pointer ((GObject *) singleton, (gpointer) &singleton);

  return singleton;
}
