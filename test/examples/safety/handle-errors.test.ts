import { describe, expect, it, vi } from "vitest";
import { isJWTError } from "unjwt/error";
import { generateJWK, type JWKSet } from "unjwt/jwk";
import { sign } from "unjwt/jws";
import { accountHandler, errorResponse } from "../../../examples/safety/handle-errors.ts";

const { privateKey, publicKey } = await generateJWK("ES256");
const handler = accountHandler({ keys: [publicKey] });
const claims = {
  iss: "https://auth.example.com",
  aud: "https://api.example.com",
  sub: "user_1a2b",
};

function request(token?: string): Request {
  const headers: HeadersInit = token ? { authorization: `Bearer ${token}` } : {};
  return new Request("https://api.example.com/account", { headers });
}

describe("examples/safety/handle-errors", () => {
  it("answers a valid token with the account", async () => {
    const response = await handler(request(await sign(claims, privateKey, { expiresIn: "5m" })));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ sub: "user_1a2b" });
  });

  it("asks for a token when there is none", async () => {
    const response = await handler(request());
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain('error="invalid_request"');
  });

  it("tells an expired token apart", async () => {
    const token = await sign({ ...claims, exp: 1_700_000_000 }, privateKey);
    const response = await handler(request(token));
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain("The token expired.");
  });

  it.each([
    ["a tampered signature", async () => `${(await sign(claims, privateKey)).slice(0, -6)}AAAAAA`],
    ["another audience", () => sign({ ...claims, aud: "https://admin.example.com" }, privateKey)],
    ["a missing issuer", () => sign({ sub: "user_1a2b", aud: claims.aud }, privateKey)],
    ["an HMAC token", async () => sign(claims, await generateJWK("HS256"))],
    ["text that is no token", async () => "not.a.token"],
    ["an unknown kid", async () => sign(claims, (await generateJWK("ES256")).privateKey)],
  ])("answers %s with invalid_token", async (_, mint) => {
    const response = await handler(request(await mint()));
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain('error="invalid_token"');
  });

  it("rethrows a server bug", async () => {
    const broken = accountHandler("not a key set" as unknown as JWKSet);
    const error = await broken(request(await sign(claims, privateKey))).catch((e: unknown) => e);
    expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    expect(errorResponse(error, vi.fn()).status).toBe(500);
  });

  it("logs anything else as it is", () => {
    const log = vi.fn();
    const response = errorResponse(new Error("boom"), log);
    expect(response.status).toBe(500);
    expect(log).toHaveBeenCalledWith({ error: expect.any(Error) });
  });
});
