import bcrypt from "bcryptjs";

export async function hashPassword(value: string) {
  const hashedValue = await bcrypt.hash(value, 12);

  return hashedValue;
}

export async function comparePassword(
  candidatePassword: string,
  password: string,
) {
  return await bcrypt.compare(candidatePassword, password);
}
