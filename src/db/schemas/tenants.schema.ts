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
  index,
} from "drizzle-orm/pg-core";

import {
  createInsertSchema,
  createSelectSchema,
  createUpdateSchema,
} from "drizzle-zod";

import { timestamps } from "../../utils/drizzleTimeStamps.util";
export const tenants = pgTable(
  "tenants",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    name: text("name").notNull(),
    slug: text("slug").notNull().unique(),
    description: text("description"),
    logoUrl: text("logo_url"),
    isActive: boolean("is_active").default(false),
    ...timestamps,
  },
  (table) => {
    return {
      // Indexing for performance as per your SQL
      slugIdx: index("idx_tenants_slug").on(table.slug),
      isActiveIdx: index("idx_tenants_is_active").on(table.isActive),
    };
  },
);

export const tenantsInsertSchema = createInsertSchema(tenants);
export const tenantsSelectSchema = createSelectSchema(tenants);
export const tenantsDeleteSchema = createUpdateSchema(tenants);
