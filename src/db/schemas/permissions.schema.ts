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
} from "drizzle-orm/pg-core";

import {
  createInsertSchema,
  createSelectSchema,
  createUpdateSchema,
} from "drizzle-zod";
import { timestamps } from "../../utils/drizzleTimeStamps.util";

export const permissions = pgTable("permissions", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").unique().notNull(),
  description: text("description"),
  resource: text("resource").notNull(),
  action: text("action").notNull(),
  ...timestamps,
});

export const permissionsInsertSchema = createInsertSchema(permissions);
export const permissionsSelectSchema = createSelectSchema(permissions);
export const permissionsDeleteSchema = createUpdateSchema(permissions);
