/*
 * Copyright © 2012 Collabora Ltd.
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

#include <mission-control-plugins/mission-control-plugins.h>

#ifndef __MCP_ACCOUNT_MANAGER_UOA_H__
#define __MCP_ACCOUNT_MANAGER_UOA_H__

G_BEGIN_DECLS

#define MCP_TYPE_ACCOUNT_MANAGER_UOA \
  (mcp_account_manager_uoa_get_type ())

#define MCP_ACCOUNT_MANAGER_UOA(o) \
  (G_TYPE_CHECK_INSTANCE_CAST ((o), MCP_TYPE_ACCOUNT_MANAGER_UOA,   \
      McpAccountManagerUoa))

#define MCP_ACCOUNT_MANAGER_UOA_CLASS(k)     \
    (G_TYPE_CHECK_CLASS_CAST((k), MCP_TYPE_ACCOUNT_MANAGER_UOA, \
        McpAccountManagerUoaClass))

#define MCP_IS_ACCOUNT_MANAGER_UOA(o) \
  (G_TYPE_CHECK_INSTANCE_TYPE ((o), MCP_TYPE_ACCOUNT_MANAGER_UOA))

#define MCP_IS_ACCOUNT_MANAGER_UOA_CLASS(k)  \
  (G_TYPE_CHECK_CLASS_TYPE ((k), MCP_TYPE_ACCOUNT_MANAGER_UOA))

#define MCP_ACCOUNT_MANAGER_UOA_GET_CLASS(o) \
    (G_TYPE_INSTANCE_GET_CLASS ((o), MCP_TYPE_ACCOUNT_MANAGER_UOA, \
        McpAccountManagerUoaClass))

typedef struct _McpAccountManagerUoaPrivate McpAccountManagerUoaPrivate;

typedef struct {
  GObject parent;

  McpAccountManagerUoaPrivate *priv;
} _McpAccountManagerUoa;

typedef struct {
  GObjectClass parent_class;
} _McpAccountManagerUoaClass;

typedef _McpAccountManagerUoa McpAccountManagerUoa;
typedef _McpAccountManagerUoaClass McpAccountManagerUoaClass;

GType mcp_account_manager_uoa_get_type (void) G_GNUC_CONST;

McpAccountManagerUoa *mcp_account_manager_uoa_new (void);

G_END_DECLS

#endif
