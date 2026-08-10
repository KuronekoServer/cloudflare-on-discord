import { jwtVerify, SignJWT, type JWTPayload } from "jose";

export interface AccessTokenClaims extends JWTPayload {
  sub: string;
  sid: string;
  kind: "user" | "bot";
  admin?: boolean;
}

export async function signAccessToken(
  claims: AccessTokenClaims,
  secret: string,
  expiresIn = "5m",
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(new TextEncoder().encode(secret));
}

export async function verifyAccessToken(
  token: string,
  secret: string,
): Promise<AccessTokenClaims> {
  const result = await jwtVerify(token, new TextEncoder().encode(secret), {
    algorithms: ["HS256"],
  });
  return result.payload as AccessTokenClaims;
}
