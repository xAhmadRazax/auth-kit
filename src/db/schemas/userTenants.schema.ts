import {
  pgTable,
  uuid,
  varchar,
  timestamp,
  boolean,
  unique,
  index,
} from "drizzle-orm/pg-core";
import { users } from "./users.schema";
import { tenants } from "./tenants.schema";

export const userTenants = pgTable(
  "user_tenants",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    role: varchar("role", { length: 50 }).default("member"),
    joinedAt: timestamp("joined_at").defaultNow(),
    isActive: boolean("is_active").default(true),
  },
  (table) => {
    return {
      // 1. The UNIQUE constraint preventing duplicate memberships
      userTenantUnique: unique().on(table.userId, table.tenantId),

      // 2. Index for finding all tenants a user belongs to
      userIdIdx: index("idx_user_tenants_user_id").on(table.userId),

      // 3. Index for finding all users in a specific tenant
      tenantIdIdx: index("idx_user_tenants_tenant_id").on(table.tenantId),
    };
  },
);
