import { db } from "../db";
import { users } from "../db/schemas/users.schema";
import { defaultFemaleAvatar, defaultMaleAvatar } from "../settings";
import { and, eq, gt, isNull, lt } from "drizzle-orm";
import { comparePassword, hashPassword } from "../utils/bcrypt.util";
import { AppError } from "../utils/apiError.util";
import { StatusCodes } from "http-status-codes";
import { generateAccessToken } from "../utils/jwt.util";
import type { PublicUser, User } from "../types/user.type";
import { sessions } from "../db/schemas/sessions.schema";
import { getExpiryDate } from "../utils/date.util";
import {
  generateCryptoToken,
  encryptCryptoToken,
  generateRefreshTokenPair,
  generateVerifierAndHashedVerifier,
} from "../utils/crypto.util";
// import { password, SHA256 } from "bun";
import { createHash, randomBytes } from "node:crypto";
import { EmailService } from "../utils/Email";
import { emailVerifications } from "../db/schema";

export async function checkIdentifierAvailabilityService({
  email,
}: {
  email: string;
}): Promise<boolean> {
  // 01 check if the email exist in the db
  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.email, email.toLocaleLowerCase()))
    .limit(1);

  // it it does return false (as email is not available)
  if (user) return false;
  return true;
}

export async function registerService(
  baseUrl: string,
  {
    email,
    name,
    avatar,
    password,
    dateOfBirth,
    gender,
  }: {
    email: string;
    name: string;
    avatar: string;
    password: string;
    dateOfBirth: Date;
    gender: "male" | "female" | "others";
  },
) {
  ``;
  // 01 create encrypted password,
  const hashedPassword = await hashPassword(password);
  // check if the user have update the image on the front-end and
  // and has send its url in the backend

  let userAvatar;
  if (avatar) {
    userAvatar = avatar;
  } else {
    userAvatar =
      gender === "male"
        ? defaultMaleAvatar
        : gender === "female"
          ? defaultFemaleAvatar
          : defaultMaleAvatar;
  }

  // 02 generate the verifying email token ad verify it

  const { verifier, hashedVerifier } = generateVerifierAndHashedVerifier();

  // 02 save the user for now
  // 02A add email verification

  const user = await db.transaction(async (tx) => {
    const [user] = await tx
      .insert(users)
      .values({
        name,
        email: email.toLocaleLowerCase(),
        avatar: userAvatar,
        password: hashedPassword,
        gender,
        dateOfBirth: new Date(dateOfBirth),
      })
      .returning();

    if (!user) {
      throw new Error("Something went wrong whole trying to create a User");
    }

    await tx.insert(emailVerifications).values({
      userId: user.id,
      token: hashedVerifier,
      expires_at: getExpiryDate("15m"),
    });

    return user;
  });

  await EmailService.init().sendVerification(
    user.name,
    user.email,
    `${baseUrl}/email/verification/${verifier}`,
  );

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    avatar: user.avatar,
    dateOfBirth: user.dateOfBirth,
    createdAt: user.createdAt,
  };
}

export async function loginService({
  email,
  password,
  ip,
  device,
}: {
  email: string;
  password: string;
  ip: string;
  device: string;
}) {
  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.email, email.toLowerCase()));

  if (!user || !(await comparePassword(password, user.password))) {
    throw new AppError(
      StatusCodes.UNAUTHORIZED,
      "Invalid Email or Password, please try again.",
      {
        errorCode: "ERR_INVALID_CREDENTIALS",
      },
    );
  }

  // at this point i can return user but there are 2 things first of all i need to create a jwt token and access token

  const accessToken = generateAccessToken(user);

  if (!process.env.REFRESH_TOKEN_EXPIRY) {
    throw new AppError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      "Refresh token Expiry not defined in .env",
      {
        errorCode: "ERR_JWT_EXPIRY",
      },
    );
  }

  const { selector, verifier, hashedVerifier } = generateRefreshTokenPair();

  const tokenExpiry = getExpiryDate(process.env.REFRESH_TOKEN_EXPIRY);

  await db.insert(sessions).values({
    tokenFamily: selector,
    tokenHash: hashedVerifier,
    userId: user.id,
    ipAddress: ip,
    device,
    tokenExpiry: tokenExpiry,
  });

  const { password: userPassword, ...publicUser } = user as PublicUser;

  return {
    user: publicUser,
    accessToken,
    refreshToken: `${selector}.${verifier}`,
  };
}

// export async function forgotPasswordService(email: string, url: string) {
//   const [user] = await db
//     .select()
//     .from(users)
//     .where(eq(users.email, email.toLowerCase()));

//   if (!user) {
//     return;
//   }

//   // 01 generate passwordResetToken
//   const passwordResetToken = generateCryptoToken();

//   // 02 hash token
//   const hashedPasswordResetToken = encryptCryptoToken(
//     passwordResetToken,
//     "sha256",
//   );

//   const resetUrl = `${url}/verify-password-reset-token/${hashedPasswordResetToken}`;

//   // 03 save the hashed token onto db
//   const passwordResetExpiry = getExpiryDate("15m");

//   await db.update(users).set({
//     passwordResetToken: hashedPasswordResetToken,
//     passwordResetExpiry,
//   });

//   // TODO: create an email
//   // 04 send user email with raw token

//   return {
//     url: resetUrl,
//     token: passwordResetToken,
//   };
// }

// export async function verifyPasswordResetTokenService(token: string) {
//   const hashedPasswordRefreshToken = encryptCryptoToken(token, "sha256");

//   const [user] = await db
//     .select()
//     .from(users)
//     .where(
//       and(
//         eq(users.passwordResetToken, hashedPasswordRefreshToken),
//         gt(users.passwordResetExpiry, new Date()),
//       ),
//     );

//   if (!user) {
//     throw new AppError(
//       StatusCodes.UNAUTHORIZED,
//       "Token is invalid or has expired",
//       {
//         errorCode: "ERR_PASSWORD_RESET_TOKEN",
//       },
//     );
//   }
// }

// export async function resetPasswordService({
//   password,
//   token,
// }: {
//   token: string;
//   password: string;
// }) {
//   // 01 hashed the token
//   const hashedPasswordRefreshToken = encryptCryptoToken(token, "sha256");
//   // 02 find user
//   const [user] = await db
//     .select()
//     .from(users)
//     .where(
//       and(
//         eq(users.passwordResetToken, hashedPasswordRefreshToken),
//         gt(users.passwordResetExpiry, new Date()),
//       ),
//     );

//   if (!user) {
//     throw new AppError(
//       StatusCodes.UNAUTHORIZED,
//       "Token is invalid or has expired",
//       {
//         errorCode: "ERR_PASSWORD_RESET_TOKEN",
//       },
//     );
//   }

//   // 03 hash password
//   const hashedPassword = await hashPassword(password);

//   // 04 update user

//   const [updatedUser] = await db
//     .update(users)
//     .set({
//       password: hashedPassword,
//       passwordChangedAt: new Date(Date.now() - 1000),
//       passwordResetExpiry: null,
//       passwordResetToken: null,
//     })
//     .returning();

//   // 05 since we have reset the password we need to revoke all the
//   // session of the current user logging out user from all devices

//   await db
//     .update(sessions)
//     .set({ isRevoked: true })
//     .where(and(eq(sessions.userId, user.id), eq(sessions.isRevoked, false)));

//   const { password: userPassword, ...publicUser } = updatedUser as PublicUser;

//   return { user: publicUser };
// }

// export async function changePasswordService({
//   userId,
//   currentPassword,
//   newPassword,
//   device,
//   ip,
// }: {
//   userId: string;
//   newPassword: string;
//   currentPassword: string;
//   device: string;
//   ip: string;
// }) {
//   // 01 get the user based on its id
//   const [user] = await db.select().from(users).where(eq(users.id, userId));

//   if (!user || !(await comparePassword(currentPassword, user.password))) {
//     throw new AppError(
//       StatusCodes.UNAUTHORIZED,
//       "invalid password, please try again.",
//       {
//         errorCode: "ERR_INVALID_CREDENTIALS",
//       },
//     );
//   }

//   const hashedPassword = await hashPassword(newPassword);
//   const passwordChangedAt = new Date(Date.now() - 1000);

//   const accessToken = generateAccessToken(user);

//   const { selector, verifier, hashedVerifier } = generateRefreshTokenPair();

//   if (!process.env.REFRESH_TOKEN_EXPIRY) {
//     throw new AppError(
//       StatusCodes.INTERNAL_SERVER_ERROR,
//       "Refresh token Expiry not defined in .env",
//       {
//         errorCode: "ERR_JWT_EXPIRY",
//       },
//     );
//   }
//   const tokenExpiry = getExpiryDate(process.env.REFRESH_TOKEN_EXPIRY);

//   // 03 update the user
//   // 04 clear users session
//   const updatedUser = await db.transaction(async (tx) => {
//     // updating the user with new password
//     const updatedUser = await tx
//       .update(users)
//       .set({
//         passwordChangedAt,
//         password: hashedPassword,
//       })
//       .where(eq(users.id, userId))
//       .returning();

//     // deleting all session belonging to this user

//     await tx
//       .update(sessions)
//       .set({ isRevoked: true })
//       .where(and(eq(sessions.userId, userId), eq(sessions.isRevoked, false)));

//     // creating a new sessions of user
//     await tx.insert(sessions).values({
//       tokenFamily: selector,
//       tokenHash: verifier,
//       userId: user.id,
//       ipAddress: ip,
//       device,
//       tokenExpiry: tokenExpiry,
//     });

//     return updatedUser.at(0);
//   });

//   const { password: userPassword, ...publicUser } = updatedUser as PublicUser;

//   return {
//     user: publicUser,
//     accessToken,
//     refreshToken: `${selector}.${verifier}`,
//   };
// }

// export async function logoutService({
//   userId,
//   token,
// }: {
//   userId: string;
//   token: string;
// }) {
//   // const hashedToken = createHash("sha256").update(token).digest("hex");
//   const [selector, verifier] = token.split(".");
//   if (!selector || !verifier) return;
//   const hashedVerifier = createHash("sha256").update(verifier).digest("hex");
//   await db
//     .update(sessions)
//     .set({
//       isRevoked: true,
//     })
//     .where(
//       and(
//         eq(sessions.userId, userId),
//         eq(sessions.tokenFamily, selector),
//         eq(sessions.tokenHash, hashedVerifier),
//       ),
//     );
// }

export async function refreshTokenService({
  refreshToken,
  device,
  ip,
  resetRefreshCookieHandler,
}: {
  refreshToken: string;
  device: string;
  ip: string;
  resetRefreshCookieHandler: () => void;
}) {
  const [selector, verifier] = refreshToken.split(".");
  if (!selector || !verifier) {
    resetRefreshCookieHandler?.();

    throw new AppError(
      StatusCodes.UNAUTHORIZED,
      "Unauthorized access to the resource.",
      {
        errorCode: "ERR_INVALID_REFRESH_TOKEN",
      },
    );
  }

  const hashedVerifier = encryptCryptoToken(verifier, "sha256");

  //01 check if session exist in the db that has
  // same selector as the refreshToken
  // same verifierHash  as we have in the refreshToken
  // shouldn't be revoked,
  // shouldn't be used
  // should'nt be expire

  const [token] = await db
    .select()
    .from(sessions)
    .where(
      and(
        eq(sessions.tokenFamily, selector),
        eq(sessions.tokenHash, hashedVerifier),
        eq(sessions.isRevoked, false),
        eq(sessions.isUsed, false),
        gt(sessions.tokenExpiry, new Date()),
      ),
    );

  // check if token doesnt exist or token family is being reused

  if (!token) {
    resetRefreshCookieHandler?.();

    const [tokenFamily] = await db
      .select()
      .from(sessions)
      .where(
        and(
          eq(sessions.tokenFamily, selector),
          eq(sessions.tokenHash, hashedVerifier),
        ),
      );

    // if token family exist revoke all token that belongs to this family
    await db
      .update(sessions)
      .set({ isRevoked: true })
      .where(
        and(
          eq(sessions.tokenFamily, selector),
          eq(sessions.tokenHash, hashedVerifier),
        ),
      );

    if (tokenFamily) {
      throw new AppError(StatusCodes.UNAUTHORIZED, "Token reuse detected", {
        errorCode: "ERR_REFRESH_TOKEN_REUSED",
      });
    }

    throw new AppError(StatusCodes.UNAUTHORIZED, "invalid Token detection.", {
      errorCode: "ERR_INVALID_REFRESH_TOKEN",
    });
  }

  // get user

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, token.userId));

  console.log(user);

  // check if user exist in the db if it doesn't exist that mean user
  // has delete its account so we need to again revoke the token
  if (!user) {
    resetRefreshCookieHandler?.();

    await db
      .update(sessions)
      .set({ isRevoked: true })
      .where(
        and(
          eq(sessions.tokenFamily, selector),
          eq(sessions.tokenHash, hashedVerifier),
        ),
      );

    throw new AppError(
      StatusCodes.UNAUTHORIZED,
      "invalid access to the resource",
      {
        errorCode: "ERR_USER_MISSING",
      },
    );
  }

  // check if user has changed its password after token has been issued
  // if they have we will revoke the token family again
  if (
    user?.passwordChangedAt &&
    new Date(user.passwordChangedAt).getTime() >
      new Date(token.createdAt).getTime()
  ) {
    resetRefreshCookieHandler?.();

    await db
      .update(sessions)
      .set({ isRevoked: true })
      .where(
        and(
          eq(sessions.tokenFamily, selector),
          eq(sessions.tokenHash, hashedVerifier),
        ),
      );

    throw new AppError(
      StatusCodes.UNAUTHORIZED,
      "Session Expired. Please login again to access this resource.",
      {
        errorCode: "ERR_SESSION_EXPIRE",
      },
    );
  }

  const verifierPair = generateVerifierAndHashedVerifier();

  if (!process.env.REFRESH_TOKEN_EXPIRY) {
    throw new AppError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      "Refresh token Expiry not defined in .env",
      {
        errorCode: "ERR_JWT_EXPIRY",
      },
    );
  }

  const tokenExpiry = getExpiryDate(process.env.REFRESH_TOKEN_EXPIRY);

  // creating new user session and linking the old session with new one
  await db.transaction(async (tx) => {
    // creating new user session
    const [newSessionToken] = await tx
      .insert(sessions)
      .values({
        tokenFamily: token.tokenFamily,
        tokenHash: verifierPair.hashedVerifier,
        tokenExpiry,
        device,
        ipAddress: ip,
        userId: user.id,
      })
      .returning();

    // creating link between old session and new session

    await tx
      .update(sessions)
      .set({
        isUsed: true,
        replacedBy: newSessionToken!.id,
      })
      .where(eq(sessions.id, token.id));

    return {
      newSessionToken,
    };
  });

  // generating new access token

  const accessToken = generateAccessToken(user);
  return {
    accessToken,
    refreshToken: `${token.tokenFamily}.${verifierPair.verifier}`,
  };
}

export async function verifyEmailService(token: string) {
  const encryptToken = encryptCryptoToken(token, "sha256");

  const [result] = await db
    .select()
    .from(emailVerifications)
    .innerJoin(users, eq(users.id, emailVerifications.userId))
    .where(
      and(
        eq(emailVerifications.token, encryptToken),
        isNull(emailVerifications.verified_at),
        gt(emailVerifications.expires_at, new Date()),
      ),
    );

  if (!result?.email_verifications || !result?.users) {
    throw new AppError(
      StatusCodes.UNAUTHORIZED,
      "Token is invalid or has expired",
      {
        errorCode: "ERR_PASSWORD_RESET_TOKEN",
      },
    );
  }

  await db.transaction(async (tx) => {
    await tx
      .update(users)
      .set({
        isVerified: true,
      })
      .where(eq(users.id, result.users.id));

    await tx
      .update(emailVerifications)
      .set({
        verified_at: new Date(),
      })
      .where(eq(emailVerifications.id, result.email_verifications.id));
  });
}

export async function sendVerificationEmailService(
  user: User,
  baseUrl: string,
) {
  if (!user.isVerified) {
    throw new AppError(StatusCodes.UNAUTHORIZED, "user is already verified", {
      errorCode: "ERR_ALREADY_VERIFIED",
    });
  }

  const { verifier, hashedVerifier } = generateVerifierAndHashedVerifier();

  await db.insert(emailVerifications).values({
    userId: user.id,
    token: hashedVerifier,
    expires_at: getExpiryDate("15m"),
  });

  // send email verification
  await EmailService.init().sendVerification(
    user.name,
    user.email,
    `${baseUrl}/email/verification/${verifier}`,
  );
}
