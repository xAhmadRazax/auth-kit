import z, { email } from "zod";
export const CheckIdentifierAvailabilitySchema = z.object({
  email: z
    .email("invalid Email address")
    .trim()
    .min(1, "Please enter an email address"),
});

export const LoginUserSchema = z.object({
  email: z
    .email("invalid Email address")
    .trim()
    .min(1, "Please enter an email address"),
  password: z
    .string()
    .min(8, "invalid Password, password must have at least 8 character"),
});

export const ForgotPasswordSchema = z.object({
  email: z
    .email("invalid Email address")
    .trim()
    .min(1, "Please enter an email address"),
});

export const ResetPasswordSchema = z.object({
  password: z
    .string()
    .min(8, "invalid Password, password must have at least 8 character"),
});

export const ChangePasswordSchema = z
  .object({
    currentPassword: z
      .string()
      .min(
        8,
        "invalid Current Password, current password must have at least 8 character",
      ),

    newPassword: z
      .string()
      .min(
        8,
        "invalid New Password, New password must have at least 8 character",
      ),
  })
  .refine((data) => data.currentPassword === data.newPassword, {
    message: "New password cannot be same as current password",
    path: ["newPassword"],
  });
