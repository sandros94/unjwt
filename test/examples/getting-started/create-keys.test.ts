import { describe, expect, it } from "vitest";
import { isPrivateJWK, isPublicJWK } from "unjwt/utils";
import { env } from "../../../examples/getting-started/create-keys.ts";

describe("examples/getting-started/create-keys", () => {
  it("prints each half of an ES256 pair as JWK JSON", () => {
    const privateKey: unknown = JSON.parse(env.TOKEN_PRIVATE_JWK);
    const publicKey: unknown = JSON.parse(env.TOKEN_PUBLIC_JWK);
    expect(isPrivateJWK(privateKey)).toBe(true);
    expect(isPublicJWK(publicKey)).toBe(true);
    expect(publicKey).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256", kid: "2026-10" });
  });
});
