import { StatusCodes } from "http-status-codes";
import { AppError } from "./apiError.util.js";
import jwt, { type JwtPayload } from "jsonwebtoken";
import type { User } from "../types/user.type.js";
import { email } from "zod";

// export const generateAccessAndRefreshToken = async (userId: string) => {
//   try {
//     const user = await User.findById(userId);
//     const accessToken = user?.generateAccessToken?.();
//     const refreshToken = user?.generateRefreshToken?.();

//     if (user && typeof refreshToken === "string") {
//       user.refreshTokens = [...user.refreshTokens, refreshToken];
//       await user.save({ validateBeforeSave: false });
//     }
//     return {
//       accessToken,
//       refreshToken,
//     };
//   } catch (error) {
//     throw new AppError(
//       StatusCodes.INTERNAL_SERVER_ERROR,
//       "Internal Server Error",
//     );
//   }
// };

export const generateAccessAndRefreshToken = (
  user: User,
):
  | {
      accessToken: string;
      refreshToken: string;
    }
  | never => {
  if (!user) {
    throw new AppError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      "Refresh token Expiry or access token Expiry not defined in .env",
      {
        errorCode: "ERR_JWT_EXPIRY",
      },
    );
  }

  const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
  const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;
  const accessTokenExpiry = process.env.ACCESS_TOKEN_EXPIRY;
  const refreshTokenExpiry = process.env.REFRESH_TOKEN_EXPIRY;

  if (!accessTokenSecret || !refreshTokenSecret) {
    throw new AppError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      "Refresh token or access token not defined in .env",
      {
        errorCode: "ERR_JWT_TOKEN_SECRET_NOT_FOUND",
      },
    );
  }

  if (!accessTokenExpiry || !refreshTokenExpiry) {
    throw new AppError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      "Refresh token Expiry or access token Expiry not defined in .env",
      {
        errorCode: "ERR_JWT_TOKEN_EXPIRY_NOT_FOUND",
      },
    );
  }

  const refreshToken = generateJwtToken(
    { id: user.id },
    refreshTokenSecret,
    refreshTokenExpiry,
  );
  const accessToken = generateJwtToken(
    { id: user.id, isVerified: user.isVerified },
    accessTokenSecret,
    accessTokenExpiry,
  );

  return {
    accessToken: accessToken,
    refreshToken: refreshToken,
  };
};

export const generateAccessToken = (user: User): string | never => {
  if (!user) {
    throw new AppError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      "Refresh token Expiry or access token Expiry not defined in .env",
      {
        errorCode: "ERR_JWT_EXPIRY",
      },
    );
  }

  const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
  const accessTokenExpiry = process.env.ACCESS_TOKEN_EXPIRY;

  if (!accessTokenSecret) {
    throw new AppError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      "Access token not defined in .env",
      {
        errorCode: "ERR_JWT_TOKEN_SECRET_NOT_FOUND",
      },
    );
  }

  if (!accessTokenExpiry) {
    throw new AppError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      "Access token Expiry not defined in .env",
      {
        errorCode: "ERR_JWT_TOKEN_EXPIRY_NOT_FOUND",
      },
    );
  }

  const accessToken = generateJwtToken(
    {
      id: user.id,
      isVerified: user.isVerified,
      email: user.email,
      roles: ["user", "admin"],
      permissions: ["read:posts", "write:posts"],
    },
    accessTokenSecret,
    accessTokenExpiry,
  );

  return accessToken;
};

export const verifyJwtToken = (
  token: string,
  isRefreshToken: boolean = false,
): JwtPayload => {
  const jwtSecret = isRefreshToken
    ? process?.env?.REFRESH_TOKEN_SECRET
    : process?.env?.ACCESS_TOKEN_SECRET;

  if (!jwtSecret) {
    throw new AppError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      `${isRefreshToken ? "Refresh" : "Access"}_TOKEN_SECRET variable is missing in environment.`,
      {
        errorCode: `ERR_JWT_${isRefreshToken ? "REFRESH_TOKEN" : "ACCESS_TOKEN"}_SECRET_NOT_FOUND`,
      },
    );
  }

  const decodedJWT = jwt.verify(token, jwtSecret) as JwtPayload;

  return decodedJWT;
};

function generateJwtToken(
  data: Record<string, any>,
  jwtSecret: string,
  jwtExpiry: string,
): string {
  const token = jwt.sign({ ...data }, jwtSecret as string, {
    expiresIn: jwtExpiry as jwt.SignOptions["expiresIn"],
  });
  return token;
}
