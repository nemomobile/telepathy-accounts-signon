/*
 * mission-control-plugin.c
 *
 * A Mission Control plugin to expose Ubuntu Online Accounts with chat
 * capabilities (e.g. Facebook) to Mission Control
 *
 * Copyright (C) 2012 Collabora Ltd.
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
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 * Authors: Xavier Claessens <xavier.claessens@collabora.co.uk>
 */

#include <mission-control-plugins/mission-control-plugins.h>

#include "mcp-account-manager-uoa.h"

GObject *
mcp_plugin_ref_nth_object (guint n)
{
  static void *plugin_0 = NULL;

  switch (n)
    {
      case 0:
        if (plugin_0 == NULL)
          plugin_0 = g_object_new (MCP_TYPE_ACCOUNT_MANAGER_UOA, NULL);
        else
          g_object_ref (plugin_0);

        return plugin_0;

      default:
        return NULL;
    }
}
