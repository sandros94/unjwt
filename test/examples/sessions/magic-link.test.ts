import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";

async function load() {
  vi.resetModules();
  vi.stubEnv("SESSION_KEY", JSON.stringify(await generateJWK("A256GCM")));
  const link = await import("../../../examples/sessions/magic-link.ts");
  const { appSession } = await import("../../../examples/sessions/app-session.ts");
  return { ...link, appSession };
}

let app: Awaited<ReturnType<typeof load>>;
beforeEach(async () => {
  app = await load();
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

describe("examples/sessions/magic-link", () => {
  it("emails a link that starts the app session", async () => {
    const url = await app.magicLinkFor("ada@example.com");
    expect(url.origin + url.pathname).toBe("https://app.example.com/auth/callback");
    const response = await app.redeemMagicLink(new Request(url));
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/");
    const cookie = response.headers.getSetCookie()[0]?.split(";", 1)[0] ?? "";
    expect(cookie).toMatch(/^__Host-unjwt-jwe=/);
    const session = await app.appSession.use(
      new Request("https://app.example.com/", { headers: { cookie } }),
    );
    expect(session.data).toEqual({ userId: "user_ada", role: "member" });
  });

  it("refuses a missing, tampered or expired token", async () => {
    const missing = await app.redeemMagicLink(new Request("https://app.example.com/auth/callback"));
    expect(missing.status).toBe(400);

    const url = await app.magicLinkFor("ada@example.com");
    const tampered = new URL(url);
    tampered.searchParams.set("token", `${url.searchParams.get("token")}x`);
    expect((await app.redeemMagicLink(new Request(tampered))).status).toBe(401);

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 16 * 60 * 1000);
    const late = await app.redeemMagicLink(new Request(url));
    expect(late.status).toBe(401);
    expect(late.headers.getSetCookie()).toEqual([]);
  });

  it("a link token never opens as the app session", async () => {
    const token = String((await app.magicLinkFor("ada@example.com")).searchParams.get("token"));
    const session = await app.appSession.use({ token });
    expect(session.id).toBeUndefined();
  });
});
