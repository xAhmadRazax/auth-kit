import { relations } from "drizzle-orm";
import { z } from "zod";
import {
  integer,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  date,
  uuid,
  boolean,
  type AnyPgColumn,
  primaryKey,
} from "drizzle-orm/pg-core";

import {
  createInsertSchema,
  createSelectSchema,
  createUpdateSchema,
} from "drizzle-zod";
import { timestamps } from "../../utils/drizzleTimeStamps.util";
import { users } from "./users.schema";
import { roles } from "./roles.schema";
import { permissions } from "./permissions.schema";

export const rolePermissions = pgTable(
  "role_permissions",
  {
    roleId: uuid("role_id").references((): AnyPgColumn => roles.id, {
      onDelete: "cascade",
    }),
    permissionId: uuid("permission_id").references(
      (): AnyPgColumn => permissions.id,
    ),
    assigned_at: timestamp("assigned_at", { withTimezone: true, mode: "date" }),
    ...timestamps,
  },
  (table) => [
    // Here is how you name the composite primary key
    primaryKey({
      name: "roles_permissions_pk",
      columns: [table.roleId, table.permissionId],
    }),
  ],
);

export const rolePermissionsInsertSchema = createInsertSchema(rolePermissions);
export const rolePermissionsSelectSchema = createSelectSchema(rolePermissions);
export const rolePermissionsDeleteSchema = createUpdateSchema(rolePermissions);

export const rolePermissionsRelations = relations(
  rolePermissions,
  ({ one }) => ({
    role: one(roles, {
      fields: [rolePermissions.roleId],
      references: [roles.id],
    }),
    permission: one(permissions, {
      fields: [rolePermissions.permissionId],
      references: [permissions.id],
    }),
  }),
);
