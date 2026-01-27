import { addDays, addHours, addMinutes } from "date-fns";

export function getExpiryDate(exp: string) {
  const value = parseInt(exp);

  if (exp.endsWith("d")) return addDays(new Date(), value);
  if (exp.endsWith("h")) return addHours(new Date(), value);
  if (exp.endsWith("m")) return addMinutes(new Date(), value);

  throw new Error("Invalid REFRESH_TOKEN_EXPIRES_IN format");
}
