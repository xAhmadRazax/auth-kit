import { Router } from "express";
import { zodSyncSchemaValidator } from "../middlewares/zodSyncschemaValidator.middleware";
import {
  checkIdentifierAvailability,
  forgotPassword,
  login,
  refreshToken,
  register,
  sendVerificationEmail,
  verifyEmail,
  resetPassword,
  // verifyPasswordToken,
} from "../controller/auth.controller";
import { userInsertSchema } from "../db/schemas/users.schema";
import {
  CheckIdentifierAvailabilitySchema,
  ForgotPasswordSchema,
  LoginUserSchema,
  ResetPasswordSchema,
} from "../zodSchemas/auth.schema";
import { protect } from "../middlewares/auth.middleware";

const router = Router();

router
  .route("/check-identifier-availability")
  .post(
    zodSyncSchemaValidator(CheckIdentifierAvailabilitySchema),
    checkIdentifierAvailability,
  );

router
  .route("/register")
  .post(zodSyncSchemaValidator(userInsertSchema), register);

router.route("/login").post(zodSyncSchemaValidator(LoginUserSchema), login);

router
  .route("/forgot-password")
  .post(zodSyncSchemaValidator(ForgotPasswordSchema), forgotPassword);

// router.route("/verify-password-reset-token/:token").get(verifyPasswordToken);

router
  .route("/reset-password/:token")
  .post(zodSyncSchemaValidator(ResetPasswordSchema), resetPassword);

router.route("/refresh-token").post(protect, refreshToken);

router.post("/email/verification", protect, sendVerificationEmail);
router.get("/email/verification/:token", verifyEmail);

export { router };
