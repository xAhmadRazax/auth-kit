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
} from "drizzle-orm/pg-core";

import {
  createInsertSchema,
  createSelectSchema,
  createUpdateSchema,
} from "drizzle-zod";
import { sessions } from "./sessions.schema";
import { timestamps } from "../../utils/drizzleTimeStamps.util";

// // timeStamps utilty

// export const timestamps = {
//   createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
//     .defaultNow()
//     .notNull(),
//   updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
//     .defaultNow()
//     .notNull()
//     .$onUpdate(() => new Date()),
// };

export const genderEnum = pgEnum("gender", ["male", "female", "others"]);

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  avatar: text("avatar"),
  // Consistent naming: TS is dateOfBirth, Postgres is date_of_birth
  dateOfBirth: date("date_of_birth", { mode: "date" }).notNull(),
  isVerified: boolean("is_verified").default(false).notNull(),
  verifyingToken: text("verified_token"),
  gender: genderEnum("gender").notNull(),
  verifyingTokenExpiry: timestamp("verifying_token_expiry", {
    withTimezone: true,
    mode: "date",
  }),
  refreshToken: text("refresh_token"),
  passwordResetToken: text("password_reset_token"),
  passwordResetExpiry: timestamp("password_reset_expiry", {
    withTimezone: true,
    mode: "date",
  }),
  passwordChangedAt: timestamp("password_changed_at", {
    withTimezone: true,
    mode: "date",
  }),
  ...timestamps,
});

//---------------------------------------------------------
// zod-schemas
export const userInsertSchema = createInsertSchema(users, {
  email: z
    .email("invalid Email address")
    .trim()
    .min(1, "Please enter an email address"),
  name: z.string("Please enter a user name").trim(),
  dateOfBirth: z.coerce.date(),
  password: z
    .string()
    .min(8, "invalid Password, password must have at least 8 character"),
})
  .extend({
    confirmPassword: z
      .string()
      .min(
        8,
        "invalid confirm Password, confirm password must have at least 8 character",
      ),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Password do not match",
    path: ["confirmPassword"],
  });

export const userSelectSchema = createSelectSchema(users);
export const userUpdateSchema = createUpdateSchema(users);

// ----------------------------------------
// user relations
export const userRelation = relations(users, ({ many }) => ({
  sessions: many(sessions),
}));
