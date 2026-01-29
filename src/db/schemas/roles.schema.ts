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

export const roles = pgTable("roles", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").unique().notNull(),
  description: text("description"),
  ...timestamps,
});

export const rolesInsertSchema = createInsertSchema(roles);
export const rolesSelectSchema = createSelectSchema(roles);
export const rolesDeleteSchema = createUpdateSchema(roles);
