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
import { users } from "./users.schema";

export const passwordResets = pgTable("password_resets", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id")
    .references((): AnyPgColumn => users.id, {
      onDelete: "cascade",
    })
    .notNull(),
  token: text("token").notNull(),
  expires_at: timestamp("expires_at", { withTimezone: true, mode: "date" }),
  usedAT: timestamp("used_at", {
    withTimezone: true,
    mode: "date",
  }),
  ...timestamps,
});

export const passwordResetInsertSchema = createInsertSchema(passwordResets);
export const passwordResetSelectSchema = createSelectSchema(passwordResets);
export const passwordResetDeleteSchema = createUpdateSchema(passwordResets);

export const passwordResetRelations = relations(passwordResets, ({ one }) => ({
  user: one(users, {
    fields: [passwordResets.userId],
    references: [users.id],
  }),
}));
