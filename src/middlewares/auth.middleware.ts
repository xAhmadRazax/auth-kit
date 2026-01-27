import type { Request, Response, NextFunction } from "express";
import { AppError } from "../utils/apiError.util";
import { StatusCodes } from "http-status-codes";
import { verifyJwtToken } from "../utils/jwt.util";
import { getUser } from "../services/user.service";
import { asyncHandler } from "../utils/asyncHandler.util";

export const protect = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    // 01 check if the authorization header exist
    const accessToken = req.headers["authorization"]?.startsWith("Bearer")
      ? req.headers["authorization"]?.split(" ")?.[1]
      : undefined;

    if (!accessToken) {
      throw new AppError(
        StatusCodes.UNAUTHORIZED,
        "Please login to access this resource",
        {
          errorCode: "ERR_MISSING_ACCESS_TOKEN",
        },
      );
    }

    const decodedAccessJwt = verifyJwtToken(accessToken);

    // 03 check if token exist or user's id exist in token
    if (!decodedAccessJwt || !decodedAccessJwt.id || !decodedAccessJwt.iat) {
      throw new AppError(StatusCodes.UNAUTHORIZED, "Token expire/invalid.", {
        errorCode: "ERR_JWT_INVALID",
      });
    }

    // 04 from the decoded token check if user exists
    const user = await getUser(decodedAccessJwt.id);
    if (!user)
      throw new AppError(StatusCodes.UNAUTHORIZED, "User no longer exists");

    // 05 check if the user's password has been change after the token was issued

    if (
      user?.passwordChangedAt &&
      new Date(user.passwordChangedAt).getTime() > decodedAccessJwt.iat * 1000
    ) {
      throw new AppError(
        StatusCodes.UNAUTHORIZED,
        "Session Expired. Please login again to access this resource.",
        {
          errorCode: "ERR_SESSION_EXPIRE",
        },
      );
    }

    const { password, ...publicUser } = user;
    req.user = publicUser;
    next();
  },
);
