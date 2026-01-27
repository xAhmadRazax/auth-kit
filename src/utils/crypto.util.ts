import crypto from "crypto";
export function generateCryptoToken(uuid = false): string {
  if (uuid) return crypto.randomUUID();
  return crypto.randomBytes(32).toString("hex");
}
export function encryptCryptoToken(
  token: string,
  algo:
    | "md5"
    | "sha1"
    | "sha224"
    | "sha256"
    | "sha384"
    | "sha512"
    | "sha3-224"
    | "sha3-256"
    | "sha3-384"
    | "sha3-512"
    | "ripemd160"
    | "blake2b512"
    | "blake2s256" = "sha256",
) {
  return crypto.createHash(algo).update(token).digest("hex");
}

export function generateRefreshTokenPair(): {
  selector: string;
  verifier: string;
  hashedVerifier: string;
} {
  const selector = generateCryptoToken(true);
  const verifier = generateCryptoToken();
  const hashedVerifier = encryptCryptoToken(verifier, "sha256");

  return {
    selector,
    verifier,
    hashedVerifier,
  };
}

export function generateVerifierAndHashedVerifier(): {
  verifier: string;
  hashedVerifier: string;
} {
  const verifier = generateCryptoToken();
  const hashedVerifier = encryptCryptoToken(verifier, "sha256");

  return {
    verifier,
    hashedVerifier,
  };
}
