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

export const emailVerifications = pgTable("email_verifications", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id")
    .references((): AnyPgColumn => users.id, {
      onDelete: "cascade",
    })
    .notNull(),
  token: text("token").notNull(),
  expires_at: timestamp("expires_at", { withTimezone: true, mode: "date" }),
  verified_at: timestamp("verified_at", { withTimezone: true, mode: "date" }),
  ...timestamps,
});

export const emailVerificationsInsertSchema =
  createInsertSchema(emailVerifications);
export const emailVerificationsSelectSchema =
  createSelectSchema(emailVerifications);
export const emailVerificationsDeleteSchema =
  createUpdateSchema(emailVerifications);

export const userRelation = relations(emailVerifications, ({ one }) => ({
  user: one(users, {
    fields: [emailVerifications.userId],
    references: [users.id],
  }),
}));
