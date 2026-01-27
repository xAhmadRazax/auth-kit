import { ZodType } from "zod";
import type { Request, Response, NextFunction } from "express";
import { asyncHandler } from "../utils/asyncHandler.util";

export function zodSyncSchemaValidator(schema: ZodType) {
  return asyncHandler(
    async (req: Request, res: Response, next: NextFunction) => {
      schema.parse(req?.body || {});
      return next();
    },
  );
}
