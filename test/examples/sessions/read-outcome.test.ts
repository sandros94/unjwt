import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { defineJWESession } from "unjwt/session";

async function load() {
  vi.resetModules();
  const key = await generateJWK("A256KW", { kid: "2026-10" });
  vi.stubEnv("SESSION_KEY_ID", "2026-10");
  vi.stubEnv("SECRETS", JSON.stringify({ "session-keys/2026-10": JSON.stringify(key) }));
  const { dashboard } = await import("../../../examples/sessions/read-outcome.ts");
  const { appSession, secretStore } = await import("../../../examples/sessions/key-lookup.ts");
  return { dashboard, appSession, secretStore, key };
}

function request(token?: string): Request {
  return new Request("https://app.example.com/dashboard", {
    headers: token ? { cookie: `__Host-unjwt-jwe=${token}` } : {},
  });
}

let app: Awaited<ReturnType<typeof load>>;
beforeEach(async () => {
  app = await load();
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("examples/sessions/read-outcome", () => {
  it("answers with the data of a token that opens", async () => {
    const response = await app.dashboard(
      request(await app.appSession.issue({ userId: "user_1a2b" })),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ userId: "user_1a2b" });
  });

  it("treats a request without a token as a guest, and writes no cookie", async () => {
    const response = await app.dashboard(request());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ guest: true });
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it("answers 401 for an expired token and expires its cookie", async () => {
    vi.useFakeTimers({ now: Date.now() - 8 * 24 * 60 * 60 * 1000 });
    const token = await app.appSession.issue({ userId: "user_1a2b" });
    vi.useRealTimers();
    const response = await app.dashboard(request(token));
    expect(response.status).toBe(401);
    expect(await response.text()).toBe("Your session expired, sign in again");
    expect(response.headers.getSetCookie()[0]).toContain("Max-Age=0");
  });

  it("answers 401 for a token that fails its checks and expires its cookie", async () => {
    const foreign = await defineJWESession({
      key: await generateJWK("A256KW", { kid: "2026-10" }),
      maxAge: "7D",
    }).issue({ userId: "user_1a2b" });
    const response = await app.dashboard(request(foreign));
    expect(response.status).toBe(401);
    expect(await response.text()).toBe("Sign in again");
    expect(response.headers.getSetCookie()[0]).toContain("Max-Age=0");
  });

  it("answers 503 when the secret manager fails, and keeps the cookie", async () => {
    const token = await app.appSession.issue({ userId: "user_1a2b" });
    vi.spyOn(app.secretStore, "get").mockImplementation(() => {
      throw new Error("secret manager unavailable");
    });
    const response = await app.dashboard(request(token));
    expect(response.status).toBe(503);
    expect(response.headers.get("retry-after")).toBe("5");
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it("leaves on session.error the object onError received, with the lookup's error as cause", async () => {
    const token = await app.appSession.issue({ userId: "user_1a2b" });
    vi.spyOn(app.secretStore, "get").mockImplementation(() => {
      throw new Error("secret manager unavailable");
    });
    const event = { req: request(token), res: { headers: new Headers() } };
    const session = await app.appSession.use(event);
    expect(session.error).toMatchObject({
      code: "ERR_SESSION_READ_FAILED",
      cause: { message: "secret manager unavailable" },
    });
    expect((await app.appSession.use(event)).error).toBe(session.error);
  });
});
