import {} from "date-fns";
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
  index,
} from "drizzle-orm/pg-core";

import {
  createInsertSchema,
  createSelectSchema,
  createUpdateSchema,
} from "drizzle-zod";

import { timestamps } from "../../utils/drizzleTimeStamps.util";
import { users } from "./users.schema";

// timeStamps utilty

//  old model before using selector and verifier
// export const sessions = pgTable("sessions", {
//   id: uuid("id").primaryKey().defaultRandom(),
//   refreshToken: text("refresh_token").notNull(),
//   tokenExpiry: timestamp("token_expiry", {
//     withTimezone: true,
//     mode: "date",
//   }),
//   device: text("device_info").notNull(),
//   ipAddress: text("ip_address").notNull(),
//   userId: uuid("user_id")
//     .references(() => users.id, { onDelete: "cascade" })
//     .notNull(),
//   ...timestamps,
// });
export const sessions = pgTable(
  "sessions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    // hashed token
    tokenHash: text("token_hash").notNull(),
    tokenFamily: uuid("token_family").notNull(),

    // detect if token is used is reused.
    isRevoked: boolean("is_revoked").default(false).notNull(),
    isUsed: boolean("is_used").default(false).notNull(),
    replacedBy: uuid("replaced_by").references((): AnyPgColumn => sessions.id, {
      onDelete: "cascade",
    }),

    tokenExpiry: timestamp("token_expiry", {
      withTimezone: true,
      mode: "date",
    }),
    //
    device: text("device_info").notNull(),
    ipAddress: text("ip_address").notNull(),
    userId: uuid("user_id")
      .references(() => users.id, { onDelete: "cascade" })
      .notNull(),
    ...timestamps,
  },
  (table) => [
    // This replaces "CREATE INDEX idx_refresh_tokens_user_id..."
    index("idx_sessions_user_id").on(table.userId),

    // This replaces "CREATE INDEX idx_refresh_tokens_token_family..."
    index("idx_sessions_token_family").on(table.tokenFamily),
  ],
);

// -----------------------------------------------------------
// Sessions schemas
export const sessionCreateSchema = createInsertSchema(sessions);
export const sessionSelectSchema = createSelectSchema(sessions);
export const sessionUpdateSchema = createUpdateSchema(sessions);

// -----------------------------------------------------------
// Sessions Relations
export const sessionRelation = relations(sessions, ({ one }) => ({
  user: one(users, {
    fields: [sessions.userId],
    references: [users.id],
  }),
}));
