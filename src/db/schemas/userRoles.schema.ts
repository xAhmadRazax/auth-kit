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

export const userRoles = pgTable(
  "user_roles",
  {
    userId: uuid("user_id").references((): AnyPgColumn => users.id, {
      onDelete: "cascade",
    }),
    roleId: uuid("role_id").references((): AnyPgColumn => roles.id),
    assigned_at: timestamp("assigned_at", { withTimezone: true, mode: "date" }),
    ...timestamps,
  },
  (table) => [
    // Here is how you name the composite primary key
    primaryKey({
      name: "user_roles_pk",
      columns: [table.userId, table.roleId],
    }),
  ],
);

export const userRolesInsertSchema = createInsertSchema(userRoles);
export const userRolesSelectSchema = createSelectSchema(userRoles);
export const userRolesDeleteSchema = createUpdateSchema(userRoles);

export const userRolesRelations = relations(userRoles, ({ one }) => ({
  user: one(users, {
    fields: [userRoles.userId],
    references: [users.id],
  }),
  role: one(roles, {
    fields: [userRoles.roleId],
    references: [roles.id],
  }),
}));
