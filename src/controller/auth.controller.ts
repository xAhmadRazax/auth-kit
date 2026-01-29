import type { NextFunction, Request, Response } from "express";
import { StatusCodes } from "http-status-codes";

import { asyncHandler } from "../utils/asyncHandler.util";
import { ApiResponse } from "../utils/apiResponse.util";
import {
  // changePasswordService,
  // forgotPasswordService,
  loginService,
  // logoutService,
  refreshTokenService,
  // resetPasswordService,
  // verifyPasswordResetTokenService,
  checkIdentifierAvailabilityService,
  registerService,
  sendVerificationEmailService,
  verifyEmailService,
} from "../services/auth.service";
import { AppError } from "../utils/apiError.util";
import { getExpiryDate } from "../utils/date.util";
import { setAuthCookie } from "../utils/cookies.util";
import { ms } from "../utils/util";

export const checkIdentifierAvailability = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email } = req.body;

    const isIdentifierAvailable = await checkIdentifierAvailabilityService({
      email,
    });
    ApiResponse.sendJSON(
      res,
      isIdentifierAvailable ? StatusCodes.OK : StatusCodes.CONFLICT,
      `${isIdentifierAvailable ? `${email} is available` : `${email} is taken`}`,
      {
        email: email,
      },
    );
  },
);

export const register = asyncHandler(async (req: Request, res: Response) => {
  const { email, name, password, dateOfBirth, gender, avatar } = req.body;
  try {
    const baseUrl = `${req.protocol}://${req.get("host")}${req.baseUrl}`;

    const user = await registerService(
      baseUrl,

      {
        email,
        name,
        password,
        avatar,
        dateOfBirth,
        gender,
      },
    );

    ApiResponse.sendJSON(
      res,
      StatusCodes.CREATED,
      "created user successfully.",
      {
        ...user,
      },
    );
  } catch (error) {
    console.log(error);
  }
});

export const login = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email, password } = req.body;

    const ip =
      (Array.isArray(req.headers["x-forwarded-for"])
        ? req.headers["x-forwarded-for"][0]
        : req.headers["x-forwarded-for"]) || req.socket.remoteAddress;
    const device = req.headers["user-agent"];

    const { user, accessToken, refreshToken } = await loginService({
      email,
      password,
      ip: ip ?? "",
      device: device || "",
    });

    // create a new cookie with the access and refreshToken
    // setting cookies
    // const cookieOptions = {
    //   httpOnly: true,
    //   sameSite: true,
    //   secure: false,
    // };
    // if (process.env.NODE_ENV === "production") {
    //   cookieOptions.secure = true;
    // }

    // res
    //   // .cookie("accessToken", accessToken, cookieOptions)
    //   .cookie("refreshToken", refreshToken, {
    //     ...cookieOptions,
    //     expires: getExpiryDate(process.env.REFRESH_TOKEN_EXPIRY!),
    //   });

    setAuthCookie(
      res,
      "refreshToken",
      refreshToken,
      ms(process.env.REFRESH_TOKEN_EXPIRY!),
    );

    ApiResponse.sendJSON(res, StatusCodes.OK, "User login successfully", {
      user,
      accessToken,
    });
  },
);

// export const forgotPassword = asyncHandler(
//   async (req: Request, res: Response, next: NextFunction) => {
//     const { email } = req.body;
//     // console.log(req.protocol, req.baseUrl, req.get("host"));

//     const url = `${req.protocol}://${req.get("host")}${req.baseUrl}`;

//     const data = await forgotPasswordService(email, url);

//     ApiResponse.sendJSON(
//       res,
//       StatusCodes.OK,
//       "If an account with that email exists, we’ve sent a password reset link to it.",
//       {
//         resetToken: data?.token ?? "",
//         resetUrl: data?.url ?? "",
//       },
//     );
//   },
// );

// export const verifyPasswordToken = asyncHandler(
//   async (req: Request, res: Response, next: NextFunction) => {
//     const { token } = req.params;
//     if (!token) {
//       throw new AppError(StatusCodes.UNAUTHORIZED, "Token is missing", {
//         errorCode: "ERR_MISSING_PASSWORD_RESET_TOKEN",
//       });
//     }

//     await verifyPasswordResetTokenService(token as string);

//     ApiResponse.sendJSON(res, StatusCodes.OK, "Token is valid");
//   },
// );

// export const resetPassword = asyncHandler(
//   async (req: Request, res: Response, next: NextFunction) => {
//     const { token } = req.params;
//     const { password } = req.body;
//     if (!token) {
//       throw new AppError(StatusCodes.UNAUTHORIZED, "Token is missing", {
//         errorCode: "ERR_MISSING_PASSWORD_RESET_TOKEN",
//       });
//     }

//     const user = await resetPasswordService({
//       token: token as string,
//       password,
//     });

//     ApiResponse.sendJSON(res, StatusCodes.OK, "Password Reset Successfully", {
//       user,
//     });
//   },
// );

// export const changePassword = asyncHandler(
//   async (req: Request, res: Response, next: NextFunction) => {
//     const { currentPassword, newPassword } = req.body;
//     const { id } = req.user;

//     const ip =
//       (Array.isArray(req.headers["x-forwarded-for"])
//         ? req.headers["x-forwarded-for"][0]
//         : req.headers["x-forwarded-for"]) || req.socket.remoteAddress;
//     const device = req.headers["user-agent"];

//     const { user, accessToken, refreshToken } = await changePasswordService({
//       userId: id,
//       currentPassword,
//       newPassword,
//       ip: ip ?? "",
//       device: device || "",
//     });

//     setAuthCookie(
//       res,
//       "refreshToken",
//       refreshToken,
//       ms(process.env.REFRESH_TOKEN_EXPIRY!),
//     );

//     ApiResponse.sendJSON(
//       res,
//       StatusCodes.OK,
//       "user's password updated successfully.",
//       {
//         user,
//         accessToken,
//       },
//     );
//   },
// );

// export const updateUser = asyncHandler(
//   async (req: Request, res: Response, next: NextFunction) => {
//     const { currentPassword, newPassword } = req.body;
//     const { id } = req.user;

//     const ip =
//       (Array.isArray(req.headers["x-forwarded-for"])
//         ? req.headers["x-forwarded-for"][0]
//         : req.headers["x-forwarded-for"]) || req.socket.remoteAddress;
//     const device = req.headers["user-agent"];

//     const { user, accessToken, refreshToken } = await changePasswordService({
//       userId: id,
//       currentPassword,
//       newPassword,
//       ip: ip ?? "",
//       device: device || "",
//     });

//     setAuthCookie(
//       res,
//       "refreshToken",
//       refreshToken,
//       ms(process.env.REFRESH_TOKEN_EXPIRY!),
//     );

//     ApiResponse.sendJSON(
//       res,
//       StatusCodes.OK,
//       "user's password updated successfully.",
//       {
//         user,
//         accessToken,
//       },
//     );
//   },
// );

// export const logout = asyncHandler(
//   async (req: Request, res: Response, next: NextFunction) => {
//     const refreshToken = req.cookies.refreshToken;
//     if (!refreshToken) {
//       throw new AppError(
//         StatusCodes.INTERNAL_SERVER_ERROR,
//         "Refresh Token not found",
//       );
//     }

//     const token = refreshToken.split(".");
//     const { id } = req.user;

//     await logoutService({
//       userId: id,
//       token,
//     });

//     setAuthCookie(res, "refreshToken", "", 0);

//     ApiResponse.sendJSON(res, StatusCodes.OK, "logout user successfully", {
//       accessToken: "",
//     });
//   },
// );

export const refreshToken = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    //01-A get Refresh Token
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      throw new AppError(
        StatusCodes.UNAUTHORIZED,
        "Session expired. Please login again.",
        {
          errorCode: "ERR_REFRESH_TOKEN_MISSING",
        },
      );
    }

    const resetRefreshCookieHandler = setAuthCookie.bind(
      null,
      res,
      "refreshToken",
      "",
      0,
    );

    const ip =
      (Array.isArray(req.headers["x-forwarded-for"])
        ? req.headers["x-forwarded-for"][0]
        : req.headers["x-forwarded-for"]) || req.socket.remoteAddress;
    const device = req.headers["user-agent"];

    const { accessToken, refreshToken: newRefreshToken } =
      await refreshTokenService({
        refreshToken,
        device: device || "",
        ip: ip || "",
        resetRefreshCookieHandler,
      });

    setAuthCookie(
      res,
      "refreshToken",
      newRefreshToken,
      ms(process.env.REFRESH_TOKEN_EXPIRY!),
    );

    ApiResponse.sendJSON(res, StatusCodes.OK, "token refresh successfully", {
      accessToken,
    });
  },
);

export const sendVerificationEmail = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { token } = req.params;
    const { user } = req;

    if (!token) {
      throw new AppError(StatusCodes.UNAUTHORIZED, "Token is missing", {
        errorCode: "ERR_MISSING_PASSWORD_RESET_TOKEN",
      });
    }
    await sendVerificationEmailService(user, token as string);

    ApiResponse.sendJSON(
      res,
      StatusCodes.OK,
      "verifying email has been sent to your account.",
    );
  },
);

export const verifyEmail = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { token } = req.params;

    if (!token) {
      throw new AppError(StatusCodes.UNAUTHORIZED, "Token is missing", {
        errorCode: "ERR_MISSING_PASSWORD_RESET_TOKEN",
      });
    }
    await verifyEmailService(token as string);

    ApiResponse.sendJSON(res, StatusCodes.OK, "User verified successfully");
  },
);
