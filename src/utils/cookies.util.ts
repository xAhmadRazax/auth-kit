import type { Response } from "express";
import { getExpiryDate } from "./date.util";

export function setAuthCookie(
  res: Response,
  cookieName: string,
  value: string,
  maxAge: number,
) {
  const cookieOptions = {
    httpOnly: true,
    // sameSite: ,
    secure: false,
  };
  if (process.env.NODE_ENV === "production") {
    cookieOptions.secure = true;
  }

  res
    // .cookie("accessToken", accessToken, cookieOptions)
    .cookie(cookieName, value, {
      ...cookieOptions,
      maxAge,
    });
}
