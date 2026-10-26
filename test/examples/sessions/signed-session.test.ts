import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { verify } from "unjwt/jws";

async function load(key: string | undefined) {
  vi.resetModules();
  vi.stubEnv("SESSION_SIGNING_KEY", key);
  return import("../../../examples/sessions/signed-session.ts");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/sessions/signed-session", () => {
  it("refuses to load without SESSION_SIGNING_KEY", async () => {
    await expect(load(undefined)).rejects.toThrow("SESSION_SIGNING_KEY is not set");
  });

  it("signs with the private half; anyone with the public half can verify and read it", async () => {
    const { privateKey, publicKey } = await generateJWK("ES256");
    const { signedSession } = await load(JSON.stringify(privateKey));
    const headers = new Headers();
    const session = await signedSession.use({
      req: new Request("https://app.example.com/"),
      res: { headers },
    });
    await session.update({ userId: "user_1a2b", locale: "it-IT" });

    const [line = ""] = headers.getSetCookie();
    expect(line.startsWith("__Host-unjwt-jws=")).toBe(true);
    expect(line).toContain("HttpOnly");

    const { payload, protectedHeader } = await verify(String(session.token), publicKey, {
      algorithms: ["ES256"],
    });
    expect(protectedHeader.typ).toBe("session+jwt");
    expect(payload).toMatchObject({ userId: "user_1a2b", locale: "it-IT", jti: session.id });

    const [, body = ""] = String(session.token).split(".");
    const decoded = JSON.parse(atob(body.replaceAll("-", "+").replaceAll("_", "/")));
    expect(decoded.userId).toBe("user_1a2b");
  });
});
