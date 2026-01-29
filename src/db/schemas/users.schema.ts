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
import { emailVerifications } from "./emailVerifications.schema";
import { userRoles } from "./userRoles.schema";
import { passwordResets } from "./passwordResets.schema";

export const genderEnum = pgEnum("gender", ["male", "female", "others"]);

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  avatar: text("avatar"),
  dateOfBirth: date("date_of_birth", { mode: "date" }).notNull(),
  isVerified: boolean("is_verified").default(false).notNull(),
  gender: genderEnum("gender").notNull(),
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
export const userRelations = relations(users, ({ many }) => ({
  sessions: many(sessions),
  passwordResets: many(passwordResets),
  emailVerifications: many(emailVerifications),
  userRoles: many(userRoles),
}));
