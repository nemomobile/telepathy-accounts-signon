/*
 * empathy-utils.h - Header for UOA utilities
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

#ifndef __EMPATHY_UOA_UTILS_H__
#define __EMPATHY_UOA_UTILS_H__

#include <libaccounts-glib/ag-manager.h>

#define EMPATHY_UOA_SERVICE_TYPE "IM"

G_BEGIN_DECLS

void empathy_uoa_manager_set_default (AgManager *manager);
AgManager *empathy_uoa_manager_dup (void);

G_END_DECLS

#endif /* #ifndef __EMPATHY_UOA_UTILS_H__*/
