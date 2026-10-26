import { describe, expect, it } from "vitest";
import { isJWTError } from "unjwt/error";
import { sign, verify } from "unjwt/jws";
import { computeDurationInSeconds, validateJwtClaims } from "unjwt/utils";
import {
  issueAccessToken,
  issueEventTicket,
  privateKey,
  publicKey,
  readAccessToken,
  readTenantToken,
} from "../../../examples/safety/validate-claims.ts";

const base = {
  iss: "https://auth.example.com",
  aud: "https://api.example.com",
  sub: "user_1a2b",
  scope: "orders:read",
};
const atJwt = { protectedHeader: { typ: "at+jwt" } };

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  return isJWTError(error) ? error.code : undefined;
}

describe("examples/safety/validate-claims", () => {
  it("issues and reads an access token", async () => {
    const payload = await readAccessToken(await issueAccessToken("user_1a2b", "orders:read"));
    expect(payload).toMatchObject({ sub: "user_1a2b", scope: "orders:read" });
    expect(payload.exp - payload.iat).toBe(900);
  });

  it.each([
    [
      "an expired token",
      () => sign({ ...base, iat: 1_700_000_000, exp: 1_700_000_900 }, privateKey, atJwt),
      "ERR_JWT_EXPIRED",
    ],
    [
      "a token older than maxTokenAge",
      () =>
        sign({ ...base, iat: Math.floor(Date.now() / 1000) - 7200 }, privateKey, {
          ...atJwt,
          expiresIn: "1D",
        }),
      "ERR_JWT_EXPIRED",
    ],
    [
      "a token not valid yet",
      () => sign(base, privateKey, { ...atJwt, expiresIn: "1h", notBeforeIn: "10m" }),
      "ERR_JWT_NBF",
    ],
    [
      "another issuer",
      () =>
        sign({ ...base, iss: "https://evil.example.com" }, privateKey, {
          ...atJwt,
          expiresIn: "15m",
        }),
      "ERR_JWT_CLAIM_INVALID",
    ],
    [
      "a token without scope",
      () => sign({ ...base, scope: undefined }, privateKey, { ...atJwt, expiresIn: "15m" }),
      "ERR_JWT_CLAIM_MISSING",
    ],
    [
      "a token without exp",
      () => sign(base, privateKey, { ...atJwt, issuedAt: true }),
      "ERR_JWT_CLAIM_MISSING",
    ],
    [
      "an ID token passed as access token",
      () => sign(base, privateKey, { expiresIn: "15m" }),
      "ERR_JWS_INVALID",
    ],
  ])("refuses %s", async (_, mint, code) => {
    expect(await codeOf(readAccessToken(await mint()))).toBe(code);
  });

  it("accepts an exp a few seconds past within clockTolerance", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign({ ...base, iat: now - 60, exp: now - 10 }, privateKey, atJwt);
    expect((await readAccessToken(token)).sub).toBe("user_1a2b");
  });

  it("compares typ as a media type", async () => {
    const token = await sign(base, privateKey, {
      protectedHeader: { typ: "application/AT+JWT" },
      expiresIn: "15m",
    });
    expect((await readAccessToken(token)).sub).toBe("user_1a2b");
  });

  it("writes nbf and exp from absolute dates", async () => {
    const startsAt = new Date("2026-11-14T18:00:00Z");
    const endsAt = new Date("2026-11-14T23:00:00Z");
    const ticket = await issueEventTicket("user_1a2b", { startsAt, endsAt });
    const { payload } = await verify(ticket, publicKey, { validateClaims: false });
    expect(payload).toMatchObject({ nbf: 1_794_679_200, exp: 1_794_697_200 });
    expect(typeof payload.iat).toBe("number");
    const during = new Date("2026-11-14T20:00:00Z");
    expect((await verify(ticket, publicKey, { currentDate: during })).payload.sub).toBe(
      "user_1a2b",
    );
    expect(
      await codeOf(verify(ticket, publicKey, { currentDate: new Date("2026-11-14T17:00:00Z") })),
    ).toBe("ERR_JWT_NBF");
  });

  it("keeps a claim already in the payload", async () => {
    const token = await sign({ sub: "user_1a2b", exp: 1_900_000_000 }, privateKey, {
      expiresIn: "15m",
    });
    expect((await verify(token, publicKey)).payload.exp).toBe(1_900_000_000);
  });

  it("refuses both expiresIn and expiresAt", async () => {
    expect(await codeOf(sign(base, privateKey, { expiresIn: "1h", expiresAt: new Date() }))).toBe(
      "ERR_JWT_CLAIM_INVALID",
    );
  });

  it("reads a crit header only when it is recognized", async () => {
    const token = await sign(base, privateKey, {
      protectedHeader: { tenant: "acme", crit: ["tenant"] },
    });
    expect((await readTenantToken(token)).tenant).toBe("acme");
    expect(await codeOf(verify(token, publicKey))).toBe("ERR_JWS_INVALID");
  });

  it("skips claims with validateClaims: false, and refuses it on text payloads", async () => {
    const expired = await sign({ exp: 1_700_000_000 }, privateKey);
    expect((await verify(expired, publicKey, { validateClaims: false })).payload.exp).toBe(
      1_700_000_000,
    );
    const text = await sign("hello", privateKey);
    expect((await verify(text, publicKey, { payload: "string" })).payload).toBe("hello");
    expect(await codeOf(verify(text, publicKey, { payload: "string", validateClaims: true }))).toBe(
      "ERR_INVALID_OPTION",
    );
  });

  it("parses durations", () => {
    expect(
      [30, "30", "90s", "15m", "2h", "7D", "2W", "1M", "1Y", "3hours"].map((d) =>
        computeDurationInSeconds(d as never),
      ),
    ).toEqual([30, 30, 90, 900, 7200, 604_800, 1_209_600, 2_592_000, 31_536_000, 10_800]);
    for (const bad of ["7d", "1 h", "1.5h", 0, -5, 2.5]) {
      expect(() => computeDurationInSeconds(bad as never)).toThrow(
        expect.objectContaining({ code: "ERR_INVALID_OPTION" }),
      );
    }
  });

  it("validates claims that arrived some other way", () => {
    const now = new Date("2026-10-26T12:00:00Z");
    const claims = {
      iss: "https://auth.example.com",
      sub: "user_1a2b",
      iat: 1_793_016_000 - 60,
      exp: 1_793_016_000 + 840,
    };
    expect(() =>
      validateJwtClaims(claims, { issuer: "https://auth.example.com", currentDate: now }),
    ).not.toThrow();
    expect(() =>
      validateJwtClaims(claims, { audience: "https://api.example.com", currentDate: now }),
    ).toThrow(expect.objectContaining({ code: "ERR_JWT_CLAIM_MISSING" }));
    expect(() => validateJwtClaims(claims, { issuer: "" })).toThrow(
      expect.objectContaining({ code: "ERR_INVALID_OPTION" }),
    );
  });
});
