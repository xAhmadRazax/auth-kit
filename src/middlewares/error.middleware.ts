import type { Request, Response, NextFunction } from "express";
import { ZodError } from "zod";
import { StatusCodes, ReasonPhrases } from "http-status-codes";
import { AppError } from "../utils/apiError.util.js";
import type { AppErrorType } from "../utils/apiError.util.js";
// interface NormalizedError {
//   statusCode: number;
//   message: string;
//   errorCode: string;
//   stack?: string;
//   options?: {
//     errors?: any;
//   };
//   isOperational?: boolean;
//   toJSON: () => {};
// }

// TODO: SENIOR DEV REVIEW - CRITICAL ISSUES BLOCKING PRODUCTION:
// 🔴 FOUNDATION: Good architecture but needs critical fixes before production
// 🎯 ACTION ITEMS:
// 1. Fix Zod error handler - return structured errors properly ✓ (DONE - but need consistency)
// 2. Standardize all error responses - same shape every time ⚠️ (INCOMPLETE - see below)
// 3. Clean up commented code - commit or delete, no in-between ❌ (PENDING)
// 4. Add proper environment handling - stack traces only in dev ❌ (PENDING)
//
// Current architecture can be preserved, but these fixes are blocking production deployment.
// Let's pair program on these items.

// 🚨 STANDARDIZATION TARGETS - These functions return DIFFERENT shapes:

// TODO: add neonDB error handlers

// ✅ GOOD: Returns structured errors consistently
function handleZodError(err: ZodError): AppError {
  let errorMessage = "";
  const formattedErrors = (err as ZodError).issues.reduce(
    (acc, issue) => {
      const field = String(issue.path[0]);
      /* this convert he zod error
      // {
         fieldName:error message,
         fieldName2:error message
         } */

      console.log(issue.message, "error");
      errorMessage += issue.message + " ";
      return {
        ...acc,
        [field]: acc[field]
          ? // this append all errors msg related to one field to single message
            `${acc[field].endsWith(".") ? acc[field].slice(0, -1) : acc[field]}, ${issue.message}`
          : issue.message,
      };
    },
    {} as Record<string, string>,
  );

  return new AppError(
    StatusCodes?.BAD_REQUEST,
    errorMessage.trim() + " tery naam hum ny kiya hy " ||
      "Input Validation failed.",
    {
      errorCode: `ERR_ZOD_VALIDATION`,
      errors: formattedErrors,
      stack: err.stack,
    },
  );
}
// ❌ PROBLEM: JWT errors return NO structured errors object
function handleJWTError(err: Error): AppError {
  return new AppError(
    StatusCodes.UNAUTHORIZED,
    process.env.NODE_ENV === "production"
      ? "Unauthorized access. Please login."
      : "Invalid Token, Please Login again.",
    {
      errorCode: `ERR_JWT_INVALID`,
      stack: err?.stack,
    },
  );
}
// ❌ PROBLEM: Same issue - no structured errors
function handleJWTExpiredError(err: Error): AppError {
  return new AppError(
    StatusCodes.UNAUTHORIZED,
    process.env.NODE_ENV === "production"
      ? "Unauthorized access. Please login."
      : "Token Expire, Please Login again.",
    {
      errorCode: `ERR_JWT_EXPIRED`,
      stack: err?.stack,
    },
  );
}
// ❌ PROBLEM: No structured errors
function handleJWTNotBeforeError(err: Error): AppError {
  return new AppError(StatusCodes.UNAUTHORIZED, "Token not active yet.", {
    errorCode: `ERR_JWT_NOT_BEFORE`,
    stack: err?.stack,
  });
}

function clearJWTFromCookies(res: Response): void {
  const cookieOptions = {
    httpOnly: true,
    sameSite: true,
    secure: false,
  };
  if (process.env.NODE_ENV === "production") {
    cookieOptions.secure = true;
  }

  res
    .clearCookie("accessToken", cookieOptions)
    .clearCookie("refreshToken", cookieOptions);
}

function normalizedErrorHandler(err: unknown): AppErrorType {
  const normalizedError = {
    statusCode: StatusCodes.INTERNAL_SERVER_ERROR,
    message: ReasonPhrases.INTERNAL_SERVER_ERROR,
    errorCode: `ERR_${ReasonPhrases.INTERNAL_SERVER_ERROR}`,
  };
  if (err instanceof ZodError) {
    return handleZodError(err);
    // return Object.assign(normalizedError, {
    //   statusCode: StatusCodes.BAD_REQUEST,
    //   errorCode: `ERR_INVALID_INPUT`,
    //   message: "Input validation failed",
    //   errors: formattedErrors,
    //   stack: err.stack,
    // });
  }
  // handling jwt error cases
  if ((err as Error).name === "TokenExpiredError") {
    return handleJWTExpiredError(err as Error);
  }
  if ((err as Error).name === "JsonWebTokenError") {
    return handleJWTError(err as Error);
  }
  if ((err as Error).name === "NotBeforeError") {
    return handleJWTNotBeforeError(err as Error);
  }

  if (err instanceof AppError) {
    return err;
  }
  return new AppError(
    StatusCodes.INTERNAL_SERVER_ERROR,
    "Hiya! nephew u have to still write more code move ur ass",
  );
  // console.log(
  //   "hiya! nephew u have to write the code don't be a johnny oliver of coding..."
  // );
  // return new AppError(
  //   200,
  //   "Hiya! nephew u have to still write more code move ur ass"
  // );
}
// const sendDevErrors = (
//   errors: NormalizedError,
//   req: Request,
//   res: Response
// ) => {};

const globalErrorHandlerMiddleware = (
  err: unknown,
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  //   const normalizedError: NormalizedError = {
  //     statusCode: StatusCodes.INTERNAL_SERVER_ERROR,
  //     message: ReasonPhrases.INTERNAL_SERVER_ERROR,
  //     errorCode: `ERR_${ReasonPhrases.INTERNAL_SERVER_ERROR}`,
  //   };
  console.log(err);
  const normalizedError = normalizedErrorHandler(err);
  // handling Err where jwt token is blacklist and we need to remove cookies

  const jwtErrorCodes = [
    "ERR_JWT_BLACKLIST",
    "ERR_JWT_INVALID",
    "ERR_JWT_EXPIRED",
    "ERR_JWT_NOT_BEFORE",
    "ERR_JWT_REUSED",
    "ERR_JWT_USER_NOT_FOUND",
    "ERR_PASSWORD_CHANGED",
  ];
  if (jwtErrorCodes.includes(normalizedError.errorCode)) {
    clearJWTFromCookies(res);
  }
  //   if (process.env.NODE_ENV === "development") {
  //     // const errObj = Object.assign(normalizedError, {
  //     //   stack: err?.stack!,
  //     // });
  //   } else if (process.env.NODE_ENV === "production") {
  //   }

  res.status(normalizedError.statusCode).json(normalizedError.toJSON(true));
};
export default globalErrorHandlerMiddleware;
