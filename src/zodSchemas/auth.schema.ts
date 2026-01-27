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
