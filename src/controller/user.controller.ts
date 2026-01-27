import type { NextFunction, Request, Response } from "express";
import { StatusCodes } from "http-status-codes";

import { asyncHandler } from "../utils/asyncHandler.util";
import { ApiResponse } from "../utils/apiResponse.util";

export const getMe = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    console.log(req.user);
    ApiResponse.sendJSON(
      res,
      StatusCodes.OK,
      "Password Reset Successfully",
      {},
    );
  },
);
