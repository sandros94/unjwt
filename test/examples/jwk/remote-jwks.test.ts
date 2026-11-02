import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { sign } from "unjwt/jws";
import { forgetIssuerKeys, readIssuerToken } from "../../../examples/jwk/remote-jwks.ts";

const issuer = await generateJWK("RS256", { kid: "auth-2026-10" });
const claims = { iss: "https://auth.example.com", aud: "api.example.com", sub: "user_1a2b" };

function serve(body: unknown, status = 200) {
  const fetch = vi.fn(async () => Response.json(body, { status }));
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

beforeEach(() => {
  forgetIssuerKeys();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("examples/jwk/remote-jwks", () => {
  it("verifies against the fetched set and fetches it once per ten minutes", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const fetch = serve({ keys: [issuer.publicKey] });
    const token = await sign(claims, issuer.privateKey, { expiresIn: "1h" });
    expect((await readIssuerToken(token)).sub).toBe("user_1a2b");
    expect((await readIssuerToken(token)).sub).toBe("user_1a2b");
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith("https://auth.example.com/.well-known/jwks.json");
    vi.advanceTimersByTime(10 * 60 * 1000 + 1);
    await readIssuerToken(token);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("refuses an HS256 token even when the set carries an oct key", async () => {
    const secret = await generateJWK("HS256", { kid: "leaked" });
    serve({ keys: [issuer.publicKey, secret] });
    const forged = await sign(claims, secret);
    await expect(readIssuerToken(forged)).rejects.toMatchObject({
      code: "ERR_JWS_ALG_NOT_ALLOWED",
    });
  });

  it("reports a failed fetch as a missing key", async () => {
    serve({ error: "unavailable" }, 503);
    const token = await sign(claims, issuer.privateKey);
    await expect(readIssuerToken(token)).rejects.toMatchObject({ code: "ERR_JWK_KEY_NOT_FOUND" });
  });

  it("refuses a token for another audience", async () => {
    serve({ keys: [issuer.publicKey] });
    const token = await sign({ ...claims, aud: "billing.example.com" }, issuer.privateKey);
    await expect(readIssuerToken(token)).rejects.toMatchObject({ code: "ERR_JWT_CLAIM_INVALID" });
  });
});
