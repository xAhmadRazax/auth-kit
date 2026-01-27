import type { InferInsertModel, InferSelectModel } from "drizzle-orm";
import { users } from "../db/schemas/users.schema";

export type User = InferSelectModel<typeof users>;
export type PublicUser = InferInsertModel<typeof users>;
